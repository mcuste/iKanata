#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/hidsystem/IOHIDLib.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <pwd.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include <grp.h>

static NSString *const AppIdentifier = @"io.github.mcuste.ikanata";
static NSString *const CLIIdentifier = @"io.github.mcuste.ikanata.cli";
static NSString *const ReaderIdentifier = @"io.github.mcuste.ikanata.config-reader";
static NSString *const EngineIdentifier = @"io.github.mcuste.ikanata.engine";
static NSString *const RuntimeDirectory = @"/Library/Application Support/iKanata/Runtime";
static NSString *const ExecutableDirectory = @"/Library/PrivilegedHelperTools/iKanata";
static NSString *const InstalledApp = @"/Applications/iKanata.app";
static const char *const MachService = "io.github.mcuste.ikanata.service";
static const size_t MaximumReply = 65536;

typedef size_t (*RequestHandler)(uint32_t, uint32_t, uint32_t, uint8_t *, size_t);
typedef void (*AuthenticationLog)(uint32_t);
static int protected_path(const char *path, int kind, BOOL allow_application_parent,
                          uint8_t *error, size_t error_capacity);
static NSBundle *containing_app(uint8_t *error, size_t error_capacity);

static int fail(uint8_t *error, size_t capacity, int code, NSString *message) {
    if (capacity != 0) {
        snprintf((char *)error, capacity, "%s", message.UTF8String ?: "native operation failed");
    }
    return code;
}

static int system_error(uint8_t *error, size_t capacity, int code, NSString *operation) {
    return fail(error, capacity, code,
                [NSString stringWithFormat:@"%@: %s", operation, strerror(code)]);
}

static int security_error(uint8_t *error, size_t capacity, OSStatus status, NSString *operation) {
    NSString *detail = CFBridgingRelease(SecCopyErrorMessageString(status, NULL));
    return fail(error, capacity, EACCES,
                [NSString stringWithFormat:@"%@: %@ (%d)", operation, detail ?: @"signature rejected", (int)status]);
}

static int copy_output(const void *bytes, size_t length, uint8_t *output, size_t capacity,
                       size_t *written, uint8_t *error, size_t error_capacity) {
    if (length > capacity) {
        return fail(error, error_capacity, EMSGSIZE, @"native output exceeds its size limit");
    }
    if (length != 0) {
        memcpy(output, bytes, length);
    }
    *written = length;
    return 0;
}

static BOOL valid_identifier(NSString *identifier) {
    if (identifier.length == 0 || identifier.length > 255) {
        return NO;
    }
    const char *bytes = identifier.UTF8String;
    if (bytes == NULL) {
        return NO;
    }
    for (const unsigned char *cursor = (const unsigned char *)bytes; *cursor; ++cursor) {
        if (!((*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
              (*cursor >= '0' && *cursor <= '9') || *cursor == '.' || *cursor == '-')) {
            return NO;
        }
    }
    return YES;
}

static NSString *identifier_requirement(NSArray<NSString *> *identifiers) {
    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:identifiers.count];
    for (NSString *identifier in identifiers) {
        [names addObject:[NSString stringWithFormat:@"identifier \"%@\"", identifier]];
    }
    return [names componentsJoinedByString:@" or "];
}

static int own_identity(NSArray<NSString *> *allowed, uint8_t *error, size_t error_capacity) {
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    SecRequirementRef requirement = NULL;
    if (status == errSecSuccess) {
        status = SecRequirementCreateWithString((__bridge CFStringRef)identifier_requirement(allowed),
                                                kSecCSDefaultFlags, &requirement);
    }
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    }
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    if (code != NULL) {
        CFRelease(code);
    }
    if (status != errSecSuccess) {
        return security_error(error, error_capacity, status, @"validate own iKanata signature");
    }
    return 0;
}

static NSString *installed_requirement(NSString *path, NSString *identifier,
                                        uint8_t *error, size_t error_capacity) {
    if (protected_path(path.fileSystemRepresentation, 2, geteuid() != 0, error, error_capacity) != 0) {
        return nil;
    }
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],
                                                 kSecCSDefaultFlags, &code);
    BOOL app_reference = [identifier isEqualToString:AppIdentifier] &&
        [path isEqualToString:[RuntimeDirectory stringByAppendingPathComponent:@"Clients/ikanata-app"]];
    SecRequirementRef requirement = NULL;
    if (status == errSecSuccess && !app_reference) {
        status = SecRequirementCreateWithString(
            (__bridge CFStringRef)identifier_requirement(@[identifier]), kSecCSDefaultFlags, &requirement);
    }
    // The private reference lacks bundle metadata; only the validated message can satisfy its code hash.
    if (status == errSecSuccess && !app_reference) {
        status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
                                            requirement);
    }
    CFDictionaryRef information = NULL;
    if (status == errSecSuccess) {
        status = SecCodeCopySigningInformation(code, kSecCSDefaultFlags, &information);
    }
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    if (code != NULL) {
        CFRelease(code);
    }
    NSDictionary *info = CFBridgingRelease(information);
    if (status != errSecSuccess) {
        security_error(error, error_capacity, status, @"validate trusted installed signature");
        return nil;
    }
    NSData *hash = info[(__bridge NSString *)kSecCodeInfoUnique];
    NSString *name = info[(__bridge NSString *)kSecCodeInfoIdentifier];
    if (![name isKindOfClass:NSString.class] || ![name isEqualToString:identifier] ||
        ![hash isKindOfClass:NSData.class] || hash.length != 20) {
        fail(error, error_capacity, EACCES, @"trusted installed code has no matching identifier and cdhash");
        return nil;
    }
    const uint8_t *bytes = hash.bytes;
    char hex[41];
    for (size_t index = 0; index < hash.length; ++index) {
        snprintf(hex + index * 2, 3, "%02x", bytes[index]);
    }
    return [NSString stringWithFormat:@"(%@ and cdhash H\"%s\")",
            identifier_requirement(@[identifier]), hex];
}

static NSString *own_executable(uint8_t *error, size_t error_capacity) {
    uint32_t capacity = 0;
    _NSGetExecutablePath(NULL, &capacity);
    char *path = malloc(capacity);
    if (path == NULL) {
        fail(error, error_capacity, ENOMEM, @"cannot inspect executable path");
        return nil;
    }
    char *resolved = NULL;
    if (_NSGetExecutablePath(path, &capacity) == 0) {
        resolved = realpath(path, NULL);
    }
    free(path);
    if (resolved == NULL) {
        system_error(error, error_capacity, errno ?: EINVAL, @"resolve current executable");
        return nil;
    }
    NSString *executable = [NSFileManager.defaultManager stringWithFileSystemRepresentation:resolved
                                                                                  length:strlen(resolved)];
    free(resolved);
    return executable;
}

static id message_requirement(NSString *text, uint8_t *error, size_t error_capacity) {
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString((__bridge CFStringRef)text,
                                                    kSecCSDefaultFlags, &requirement);
    if (status != errSecSuccess) {
        security_error(error, error_capacity, status, @"create peer signing requirement");
        return nil;
    }
    return CFBridgingRelease(requirement);
}

static OSStatus authenticate_message(xpc_object_t message, id requirement) {
    SecCodeRef code = NULL;
    // This API uses the message's audit token, never a recyclable process ID.
    OSStatus status = SecCodeCreateWithXPCMessage(message, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSStrictValidate,
                                      (__bridge SecRequirementRef)requirement);
        CFRelease(code);
    }
    return status;
}

int ikanata_request(uint32_t operation, uint8_t *output, size_t capacity, size_t *written,
                    uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (operation > 12) {
            return fail(error, error_capacity, EINVAL, @"unknown service operation");
        }
        if (geteuid() == 0 || getuid() == 0) {
            return fail(error, error_capacity, EACCES, @"root clients cannot control the user service");
        }
        int result = own_identity(@[AppIdentifier, CLIIdentifier], error, error_capacity);
        if (result != 0) {
            return result;
        }
        NSBundle *bundle = containing_app(error, error_capacity);
        if (bundle == nil) {
            return EACCES;
        }
        NSString *service = [InstalledApp stringByAppendingPathComponent:@"Contents/MacOS/ikanata-app"];
        NSString *text = installed_requirement(service, AppIdentifier, error, error_capacity);
        if (text == nil) {
            return EACCES;
        }
        xpc_connection_t connection = xpc_connection_create_mach_service(
            MachService, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        if (connection == NULL) {
            return fail(error, error_capacity, ENOMEM, @"could not create service connection");
        }
        int requirement_error = xpc_connection_set_peer_code_signing_requirement(connection, text.UTF8String);
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) { (void)event; });
        xpc_connection_activate(connection);
        if (requirement_error != 0) {
            xpc_connection_cancel(connection);
            return system_error(error, error_capacity, requirement_error, @"require signed service peer");
        }
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_uint64(message, "operation", operation);
        dispatch_semaphore_t completed = dispatch_semaphore_create(0);
        __block xpc_object_t response = nil;
        xpc_connection_send_message_with_reply(connection, message,
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(xpc_object_t reply) {
                response = reply;
                dispatch_semaphore_signal(completed);
            });
        int64_t timeout = (operation == 8 || operation == 9) ? 600 : 60;
        long wait_result = dispatch_semaphore_wait(
            completed, dispatch_time(DISPATCH_TIME_NOW, timeout * NSEC_PER_SEC));
        uid_t server_uid = xpc_connection_get_euid(connection);
        xpc_connection_cancel(connection);
        if (wait_result != 0) {
            return fail(error, error_capacity, ETIMEDOUT, @"service request timed out");
        }
        if (response == nil || xpc_get_type(response) != XPC_TYPE_DICTIONARY) {
            return fail(error, error_capacity, ECONNREFUSED,
                        @"service is unavailable or its installed-build signature was rejected");
        }
        if (server_uid != 0) {
            return fail(error, error_capacity, EACCES, @"the authenticated service must run as root");
        }
        // XPC enforces the exact installed main-app signature for the root peer.
        if (xpc_dictionary_get_count(response) != 1) {
            return fail(error, error_capacity, EPROTO, @"invalid service reply shape");
        }
        xpc_object_t body = xpc_dictionary_get_value(response, "body");
        if (body != NULL && xpc_get_type(body) == XPC_TYPE_DATA) {
            size_t length = xpc_data_get_length(body);
            if (length > MaximumReply) {
                return fail(error, error_capacity, EMSGSIZE, @"service reply exceeds 64 KiB");
            }
            return copy_output(xpc_data_get_bytes_ptr(body), length, output, capacity, written,
                               error, error_capacity);
        }
        xpc_object_t failure = xpc_dictionary_get_value(response, "error");
        if (failure != NULL && xpc_get_type(failure) == XPC_TYPE_STRING &&
            xpc_string_get_length(failure) <= 1024) {
            return fail(error, error_capacity, EIO,
                        [NSString stringWithUTF8String:xpc_string_get_string_ptr(failure)]);
        }
        return fail(error, error_capacity, EPROTO, @"invalid service reply payload");
    }
}

static void send_failure(xpc_object_t message, const char *text) {
    xpc_connection_t peer = xpc_dictionary_get_remote_connection(message);
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (peer != NULL && reply != NULL) {
        xpc_dictionary_set_string(reply, "error", text);
        xpc_connection_send_message(peer, reply);
    }
}

int ikanata_serve(RequestHandler handler, AuthenticationLog authentication_log,
                   uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (geteuid() != 0 || getuid() != 0) {
            return fail(error, error_capacity, EACCES, @"the privileged service must run as root");
        }
        if (![NSThread isMainThread]) {
            return fail(error, error_capacity, EINVAL, @"the XPC service must start on the main thread");
        }
        NSString *executable = own_executable(error, error_capacity);
        if (executable == nil) {
            return EACCES;
        }
        NSString *bundled_service = [InstalledApp stringByAppendingPathComponent:
                                     @"Contents/MacOS/ikanata-app"];
        if (![executable isEqualToString:bundled_service]) {
            return fail(error, error_capacity, EACCES, @"the service must run from the installed app's main executable");
        }
        NSString *service_text = installed_requirement(
            [RuntimeDirectory stringByAppendingPathComponent:@"Clients/ikanata-app"], AppIdentifier,
            error, error_capacity);
        if (service_text == nil) {
            return EACCES;
        }
        id service_requirement = message_requirement(service_text, error, error_capacity);
        if (service_requirement == nil) {
            return EACCES;
        }
        SecCodeRef own_code = NULL;
        OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &own_code);
        if (status == errSecSuccess) {
            status = SecCodeCheckValidity(own_code, kSecCSStrictValidate,
                                          (__bridge SecRequirementRef)service_requirement);
            CFRelease(own_code);
        }
        if (status != errSecSuccess) {
            return security_error(error, error_capacity, status, @"match running service to installed build");
        }
        NSString *cli_text = installed_requirement(
            [RuntimeDirectory stringByAppendingPathComponent:@"Clients/ikanata"], CLIIdentifier,
            error, error_capacity);
        if (cli_text == nil) {
            return EACCES;
        }
        NSString *text = [NSString stringWithFormat:@"%@ or %@", cli_text, service_text];
        id requirement = message_requirement(text, error, error_capacity);
        if (requirement == nil) {
            return EACCES;
        }
        dispatch_queue_t queue = dispatch_queue_create("io.github.mcuste.ikanata.service.requests", DISPATCH_QUEUE_SERIAL);
        __attribute__((objc_precise_lifetime)) xpc_connection_t listener = xpc_connection_create_mach_service(
            MachService, queue, XPC_CONNECTION_MACH_SERVICE_LISTENER);
        if (listener == NULL) {
            return fail(error, error_capacity, ENOMEM, @"could not create service listener");
        }
        xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
            @autoreleasepool {
                if (xpc_get_type(event) != XPC_TYPE_CONNECTION) {
                    return;
                }
                xpc_connection_t peer = (xpc_connection_t)event;
                xpc_connection_set_target_queue(peer, queue);
                int peer_requirement_error = xpc_connection_set_peer_code_signing_requirement(peer, text.UTF8String);
                xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
                    @autoreleasepool {
                        if (xpc_get_type(message) == XPC_TYPE_ERROR) {
                            xpc_connection_set_event_handler(peer, ^(xpc_object_t ignored) { (void)ignored; });
                            xpc_connection_cancel(peer);
                            return;
                        }
                        if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
                            xpc_connection_cancel(peer);
                            return;
                        }
                        // XPC obtains these credentials from the kernel audit token, not message fields.
                        uid_t uid = xpc_connection_get_euid(peer);
                        gid_t gid = xpc_connection_get_egid(peer);
                        if (uid == 0 || authenticate_message(message, requirement) != errSecSuccess) {
                            authentication_log(0);
                            xpc_connection_cancel(peer);
                            return;
                        }
                        authentication_log(1);
                        if (xpc_dictionary_get_count(message) != 1) {
                            send_failure(message, "only one numeric operation is accepted");
                            return;
                        }
                        xpc_object_t operation = xpc_dictionary_get_value(message, "operation");
                        if (operation == NULL || xpc_get_type(operation) != XPC_TYPE_UINT64 ||
                            xpc_uint64_get_value(operation) > 12) {
                            send_failure(message, "unknown service operation");
                            return;
                        }
                        uint8_t *buffer = malloc(MaximumReply);
                        if (buffer == NULL) {
                            send_failure(message, "service cannot allocate reply buffer");
                            return;
                        }
                        size_t length = handler((uint32_t)xpc_uint64_get_value(operation), uid, gid,
                                                buffer, MaximumReply);
                        if (length > MaximumReply) {
                            free(buffer);
                            send_failure(message, "service handler failed or its reply exceeds 64 KiB");
                            return;
                        }
                        xpc_object_t reply = xpc_dictionary_create_reply(message);
                        if (reply != NULL) {
                            xpc_dictionary_set_data(reply, "body", buffer, length);
                            xpc_connection_send_message(peer, reply);
                        }
                        free(buffer);
                    }
                });
                xpc_connection_activate(peer);
                if (peer_requirement_error != 0 || xpc_connection_get_euid(peer) == 0) {
                    authentication_log(0);
                    xpc_connection_cancel(peer);
                }
            }
        });
        xpc_connection_activate(listener);
        dispatch_main();
    }
}

static NSBundle *installed_app_context(uint8_t *error, size_t error_capacity) {
    NSBundle *bundle = NSBundle.mainBundle;
    if (![bundle.bundleIdentifier isEqualToString:AppIdentifier] ||
        ![bundle.bundleURL.path isEqualToString:InstalledApp] ||
        ![bundle.bundleURL.URLByResolvingSymlinksInPath.path isEqualToString:InstalledApp] ||
        ![bundle.executableURL.lastPathComponent isEqualToString:@"ikanata-app"]) {
        fail(error, error_capacity, EINVAL,
             @"this operation must run in the actual /Applications/iKanata.app main executable; open iKanata.app instead of invoking the CLI");
        return nil;
    }
    NSString *executable = own_executable(error, error_capacity);
    if (executable == nil) {
        return nil;
    }
    if (![executable isEqualToString:bundle.executableURL.path]) {
        fail(error, error_capacity, EINVAL, @"the current executable is not the installed main app");
        return nil;
    }
    if (own_identity(@[AppIdentifier], error, error_capacity) != 0) {
        return nil;
    }
    return bundle;
}

int ikanata_request_input_permissions(uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (geteuid() == 0 || getuid() == 0) {
            return fail(error, error_capacity, EACCES, @"input permission requests require the non-root main app");
        }
        NSBundle *bundle = installed_app_context(error, error_capacity);
        if (bundle == nil) {
            return EACCES;
        }
        int result = protected_path(bundle.executableURL.fileSystemRepresentation, 2, YES,
                                    error, error_capacity);
        if (result != 0) {
            return result;
        }
        NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
        (void)AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
        (void)IOHIDRequestAccess(kIOHIDRequestTypeListenEvent);
        return 0;
    }
}

int ikanata_service_action(uint32_t action, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (action > 5) {
            return fail(error, error_capacity, EINVAL, @"unknown native app operation");
        }
        NSBundle *bundle = installed_app_context(error, error_capacity);
        if (bundle == nil) {
            return EACCES;
        }
        NSError *failure = nil;
        BOOL success = NO;
        if (action == 4) {
            if (geteuid() == 0) {
                return fail(error, error_capacity, EACCES, @"only the user's app can move itself to Trash");
            }
            success = [NSFileManager.defaultManager trashItemAtURL:bundle.bundleURL
                                                  resultingItemURL:NULL error:&failure];
        } else {
            SMAppService *service = action < 2 || action == 5
                ? [SMAppService daemonServiceWithPlistName:@"io.github.mcuste.ikanata.service.plist"]
                : SMAppService.mainAppService;
            BOOL registered = service.status != SMAppServiceStatusNotRegistered &&
                              service.status != SMAppServiceStatusNotFound;
            if ((action == 1 || action == 3) && !registered) {
                return 0;
            }
            if (action == 0 || action == 2) {
                success = [service registerAndReturnError:&failure];
            } else {
                dispatch_semaphore_t completion = dispatch_semaphore_create(0);
                __block NSError *completionError = nil;
                __block BOOL completionSuccess = NO;
                dispatch_block_t registerUpdated = ^{
                    NSError *registrationError = nil;
                    completionSuccess = [service registerAndReturnError:&registrationError];
                    completionError = registrationError;
                    dispatch_semaphore_signal(completion);
                };
                if (action == 5 && !registered) {
                    dispatch_async(dispatch_get_main_queue(), registerUpdated);
                } else {
                    [service unregisterWithCompletionHandler:^(NSError *unregisterError) {
                        if (unregisterError == nil && action == 5) {
                            dispatch_async(dispatch_get_main_queue(), registerUpdated);
                        } else {
                            completionError = unregisterError;
                            completionSuccess = unregisterError == nil;
                            dispatch_semaphore_signal(completion);
                        }
                    }];
                }
                NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 30.0;
                while (dispatch_semaphore_wait(completion,
                       dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC)) != 0) {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, true);
                    if (NSProcessInfo.processInfo.systemUptime >= deadline) {
                        return fail(error, error_capacity, ETIMEDOUT,
                                    @"macOS did not finish changing the service registration");
                    }
                }
                success = completionSuccess;
                failure = completionError;
            }
            if ((action == 0 || action == 5) && service.status == SMAppServiceStatusRequiresApproval) {
                [SMAppService openSystemSettingsLoginItems];
                return fail(error, error_capacity, EACCES,
                            @"enable iKanata in Login Items & Extensions, then run setup again");
            }
        }
        if (!success) {
            return fail(error, error_capacity, EACCES,
                        failure.localizedDescription ?: @"macOS rejected the app operation");
        }
        return 0;
    }
}

int ikanata_service_status(uint8_t *output, size_t capacity, size_t *written,
                           uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (installed_app_context(error, error_capacity) == nil) {
            return EACCES;
        }
        SMAppServiceStatus status = [SMAppService daemonServiceWithPlistName:
                                     @"io.github.mcuste.ikanata.service.plist"].status;
        const char *text;
        switch (status) {
            case SMAppServiceStatusEnabled: text = "enabled"; break;
            case SMAppServiceStatusRequiresApproval: text = "requires-approval"; break;
            case SMAppServiceStatusNotRegistered: text = "not-registered"; break;
            case SMAppServiceStatusNotFound: text = "not-found"; break;
            default: return fail(error, error_capacity, EIO, @"unknown Service Management status");
        }
        return copy_output(text, strlen(text), output, capacity, written, error, error_capacity);
    }
}

static int current_session(uint32_t *uid, BOOL *on_console, BOOL *locked,
                            uint8_t *error, size_t error_capacity) {
    io_registry_entry_t root = IORegistryGetRootEntry(kIOMainPortDefault);
    if (root == IO_OBJECT_NULL) {
        return fail(error, error_capacity, ENOENT, @"the global console registry is unavailable");
    }
    CFMutableDictionaryRef properties = NULL;
    kern_return_t status = IORegistryEntryCreateCFProperties(root, &properties, kCFAllocatorDefault, 0);
    IOObjectRelease(root);
    NSDictionary *registry = CFBridgingRelease(properties);
    if (status != KERN_SUCCESS || ![registry isKindOfClass:NSDictionary.class]) {
        return fail(error, error_capacity, EIO, @"cannot read the global console registry");
    }
    NSArray *sessions = registry[@"IOConsoleUsers"];
    id lock = registry[@"IOConsoleLocked"];
    if (![sessions isKindOfClass:NSArray.class] || lock == nil ||
        CFGetTypeID((__bridge CFTypeRef)lock) != CFBooleanGetTypeID()) {
        return fail(error, error_capacity, ENOENT, @"the global console session or lock state is unavailable");
    }
    uid_t console_uid = 0;
    gid_t console_gid = 0;
    CFStringRef name = SCDynamicStoreCopyConsoleUser(NULL, &console_uid, &console_gid);
    if (name == NULL) {
        return fail(error, error_capacity, ENOENT, @"no graphical console user is available");
    }
    BOOL login_window = CFEqual(name, CFSTR("loginwindow"));
    CFRelease(name);
    if (console_uid == 0 || login_window) {
        return fail(error, error_capacity, ENOENT, @"the graphical console has no logged-in user");
    }
    BOOL found = NO;
    BOOL screen_locked = [lock boolValue];
    for (id value in sessions) {
        if (![value isKindOfClass:NSDictionary.class]) {
            return fail(error, error_capacity, EIO, @"the global console session list is malformed");
        }
        NSDictionary *session = value;
        NSNumber *user = session[@"kCGSSessionUserIDKey"];
        id console = session[@"kCGSSessionOnConsoleKey"];
        id logged_in = session[@"kCGSessionLoginDoneKey"];
        if (![user isKindOfClass:NSNumber.class] ||
            CFGetTypeID((__bridge CFTypeRef)user) != CFNumberGetTypeID() ||
            CFNumberIsFloatType((__bridge CFNumberRef)user) || user.longLongValue < 0 ||
            user.unsignedLongLongValue > UINT32_MAX || console == nil || logged_in == nil ||
            CFGetTypeID((__bridge CFTypeRef)console) != CFBooleanGetTypeID() ||
            CFGetTypeID((__bridge CFTypeRef)logged_in) != CFBooleanGetTypeID()) {
            return fail(error, error_capacity, EIO, @"the global console session identity is malformed");
        }
        if (![console boolValue]) {
            continue;
        }
        if (found || user.unsignedIntValue != console_uid || ![logged_in boolValue]) {
            return fail(error, error_capacity, ENOENT, @"the graphical console session is changing");
        }
        id session_lock = session[@"CGSSessionScreenIsLocked"];
        if (session_lock != nil) {
            if (CFGetTypeID((__bridge CFTypeRef)session_lock) != CFBooleanGetTypeID()) {
                return fail(error, error_capacity, EIO, @"the console session lock state is malformed");
            }
            screen_locked |= [session_lock boolValue];
        }
        found = YES;
    }
    if (!found) {
        return fail(error, error_capacity, ENOENT, @"the console user has no active registry session");
    }
    *uid = console_uid;
    *on_console = YES;
    *locked = screen_locked;
    return 0;
}

int ikanata_console_uid(uint32_t *uid, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        BOOL on_console = NO;
        BOOL locked = YES;
        int result = current_session(uid, &on_console, &locked, error, error_capacity);
        if (result == 0 && !on_console) {
            return fail(error, error_capacity, ENOENT, @"no user owns the graphical console");
        }
        return result;
    }
}

int ikanata_session_active(uint32_t uid, int *active, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        *active = 0;
        if (uid == 0) {
            return fail(error, error_capacity, EINVAL, @"root cannot own a remapping session");
        }
        uint32_t console_uid = 0;
        BOOL on_console = NO;
        BOOL locked = YES;
        int result = current_session(&console_uid, &on_console, &locked, error, error_capacity);
        if (result == 0) {
            *active = console_uid == uid && on_console && !locked;
        }
        return result;
    }
}

static int lookup_user(uint32_t uid, struct passwd *user, char **storage,
                        uint8_t *error, size_t error_capacity) {
    size_t capacity = 16384;
    const size_t maximum = 1048576;
    for (;;) {
        char *buffer = malloc(capacity);
        if (buffer == NULL) {
            return fail(error, error_capacity, ENOMEM, @"cannot allocate user lookup buffer");
        }
        struct passwd *found = NULL;
        int result = getpwuid_r(uid, user, buffer, capacity, &found);
        if (result == 0 && found != NULL) {
            *storage = buffer;
            return 0;
        }
        free(buffer);
        if (result == ERANGE && capacity < maximum) {
            capacity *= 2;
            continue;
        }
        return system_error(error, error_capacity, result != 0 ? result : ENOENT, @"resolve user identity");
    }
}

int ikanata_home_for_uid(uint32_t uid, uint8_t *output, size_t capacity, size_t *written,
                         uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        struct passwd user;
        char *storage = NULL;
        int result = lookup_user(uid, &user, &storage, error, error_capacity);
        if (result != 0) {
            return result;
        }
        if (user.pw_dir == NULL || user.pw_dir[0] != '/') {
            free(storage);
            return fail(error, error_capacity, EINVAL, @"the user's home directory is not absolute");
        }
        result = copy_output(user.pw_dir, strlen(user.pw_dir), output, capacity, written,
                             error, error_capacity);
        free(storage);
        return result;
    }
}

int ikanata_notify(const char *title, const char *message, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (geteuid() == 0 || strlen(title) > 256 || strlen(message) > 4096) {
            return fail(error, error_capacity, EINVAL, @"notifications require a user session and bounded text");
        }
        NSString *heading = [NSString stringWithUTF8String:title];
        NSString *body = [NSString stringWithUTF8String:message];
        NSUserNotificationCenter *center = NSUserNotificationCenter.defaultUserNotificationCenter;
        if (heading == nil || body == nil || center == nil) {
            return fail(error, error_capacity, ENOTSUP, @"native user notifications are unavailable");
        }
        @try {
            NSUserNotification *notification = [NSUserNotification new];
            notification.title = heading;
            notification.informativeText = body;
            [center deliverNotification:notification];
        } @catch (NSException *exception) {
            return fail(error, error_capacity, EIO, exception.reason ?: @"notification submission failed");
        }
        return 0;
    }
}

static NSBundle *containing_app(uint8_t *error, size_t error_capacity) {
    NSString *executable = own_executable(error, error_capacity);
    if (executable == nil) {
        return nil;
    }
    NSString *macos = executable.stringByDeletingLastPathComponent;
    NSString *contents = macos.stringByDeletingLastPathComponent;
    NSString *root = contents.stringByDeletingLastPathComponent;
    NSBundle *bundle = [NSBundle bundleWithPath:root];
    if (![macos.lastPathComponent isEqualToString:@"MacOS"] ||
        ![contents.lastPathComponent isEqualToString:@"Contents"] ||
        ![bundle.bundleIdentifier isEqualToString:AppIdentifier]) {
        fail(error, error_capacity, ENOENT, @"this executable is not inside an iKanata app bundle");
        return nil;
    }
    return bundle;
}

int ikanata_bundle_resource(const char *name, uint8_t *output, size_t capacity, size_t *written,
                            uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        size_t length = strlen(name);
        if (length == 0 || length > 255 || strchr(name, '/') != NULL ||
            strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            return fail(error, error_capacity, EINVAL, @"a resource must be a single filename");
        }
        NSString *filename = [NSString stringWithUTF8String:name];
        if (filename == nil) {
            return fail(error, error_capacity, EINVAL, @"resource name is not UTF-8");
        }
        NSBundle *bundle = containing_app(error, error_capacity);
        if (bundle == nil) {
            return ENOENT;
        }
        NSURL *resource = [bundle.resourceURL URLByAppendingPathComponent:filename isDirectory:NO];
        if (resource == nil) {
            return fail(error, error_capacity, ENOENT, @"the app has no resource directory");
        }
        struct stat metadata;
        if (lstat(resource.fileSystemRepresentation, &metadata) != 0) {
            return system_error(error, error_capacity, errno, @"inspect bundled resource");
        }
        if (!S_ISREG(metadata.st_mode)) {
            return fail(error, error_capacity, EINVAL, @"the bundled resource must be a regular file, not a symlink");
        }
        const char *path = resource.fileSystemRepresentation;
        return copy_output(path, strlen(path), output, capacity, written, error, error_capacity);
    }
}

uint32_t ikanata_effective_uid(void) {
    return geteuid();
}

int ikanata_drop_privileges(uint32_t uid, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (uid == 0 || getuid() != 0 || geteuid() != 0) {
            return fail(error, error_capacity, EACCES, @"only a root reader can drop to a non-root user");
        }
        struct passwd user;
        char *storage = NULL;
        int result = lookup_user(uid, &user, &storage, error, error_capacity);
        if (result != 0) {
            return result;
        }
        gid_t gid = user.pw_gid;
        if (user.pw_uid != uid || user.pw_name == NULL || user.pw_name[0] == '\0') {
            free(storage);
            return fail(error, error_capacity, EINVAL, @"user lookup returned an invalid identity");
        }
        if (initgroups(user.pw_name, gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
            int saved = errno;
            free(storage);
            return system_error(error, error_capacity, saved, @"permanently drop reader privileges");
        }
        free(storage);
        if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
            return fail(error, error_capacity, EACCES, @"reader credential verification failed");
        }
        return 0;
    }
}

__attribute__((visibility("hidden")))
int ikanata_protected_acl(const char *path, uint8_t *error, size_t error_capacity) {
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        int saved = errno;
        // macOS reports ENOENT for an existing file with no ACL.
        if (saved == ENOENT) {
            struct stat metadata;
            if (lstat(path, &metadata) == 0) {
                return 0;
            }
            saved = errno;
        }
        return system_error(error, error_capacity, saved, @"inspect protected path ACL");
    }
    const acl_perm_t writes[] = {
        ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
        ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER
    };
    acl_entry_t entry;
    int position = ACL_FIRST_ENTRY;
    while (acl_get_entry(acl, position, &entry) == 0) {
        position = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        acl_permset_t permissions;
        if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &permissions) != 0) {
            int saved = errno;
            acl_free(acl);
            return system_error(error, error_capacity, saved, @"inspect protected path ACL entry");
        }
        if (tag != ACL_EXTENDED_ALLOW) {
            continue;
        }
        for (size_t index = 0; index < sizeof(writes) / sizeof(writes[0]); ++index) {
            int present = acl_get_perm_np(permissions, writes[index]);
            if (present != 0) {
                acl_free(acl);
                return fail(error, error_capacity, EACCES, @"protected paths must not have ACL write grants");
            }
        }
    }
    acl_free(acl);
    return 0;
}

static int protected_path(const char *path, int kind, BOOL allow_application_parent,
                          uint8_t *error, size_t error_capacity) {
    if (path[0] != '/' || strlen(path) >= PATH_MAX) {
        return fail(error, error_capacity, EINVAL, @"the protected path must be absolute");
    }
    char *resolved = realpath(path, NULL);
    if (resolved == NULL) {
        return system_error(error, error_capacity, errno, @"resolve protected path");
    }
    BOOL canonical = strcmp(path, resolved) == 0;
    free(resolved);
    if (!canonical) {
        return fail(error, error_capacity, EACCES, @"the protected path must be canonical and free of symlinks");
    }
    char *component = strdup(path);
    if (component == NULL) {
        return fail(error, error_capacity, ENOMEM, @"cannot inspect protected path");
    }
    size_t length = strlen(component);
    allow_application_parent = allow_application_parent &&
        (strcmp(path, "/Applications") == 0 ||
         strncmp(path, "/Applications/iKanata.app/", strlen("/Applications/iKanata.app/")) == 0 ||
         strncmp(path, "/Applications/.Karabiner-VirtualHIDDevice-Manager.app",
                 strlen("/Applications/.Karabiner-VirtualHIDDevice-Manager.app")) == 0);
    BOOL runtime = strcmp(path, RuntimeDirectory.fileSystemRepresentation) == 0 ||
        strncmp(path, "/Library/Application Support/iKanata/Runtime/",
                strlen("/Library/Application Support/iKanata/Runtime/")) == 0;
    BOOL public_executable = strncmp(path, "/Library/PrivilegedHelperTools/iKanata/",
                                    strlen("/Library/PrivilegedHelperTools/iKanata/")) == 0;
    for (size_t index = 1; index <= length; ++index) {
        if (component[index] != '/' && component[index] != '\0') {
            continue;
        }
        char saved = component[index];
        component[index] = '\0';
        struct stat metadata;
        if (lstat(component, &metadata) != 0) {
            int saved_errno = errno;
            free(component);
            return system_error(error, error_capacity, saved_errno, @"inspect protected path");
        }
        BOOL final = index == length;
        mode_t forbidden_writes = S_IWGRP | S_IWOTH;
        // macOS permits administrators to replace apps in /Applications.
        if (allow_application_parent && strcmp(component, "/Applications") == 0) {
            forbidden_writes = S_IWOTH;
        }
        if (metadata.st_uid != 0 || (metadata.st_mode & forbidden_writes) != 0 ||
            (final ? (kind == 0 ? !S_ISDIR(metadata.st_mode) : !S_ISREG(metadata.st_mode)) ||
                     (kind == 2 && (metadata.st_mode & S_IXUSR) == 0)
                   : !S_ISDIR(metadata.st_mode))) {
            free(component);
            return fail(error, error_capacity, EACCES,
                        @"protected paths must be root-owned, non-writable by other users, and free of symlinks");
        }
        if (runtime &&
            (strcmp(component, "/Library/Application Support/iKanata") == 0 ||
             strcmp(component, RuntimeDirectory.fileSystemRepresentation) == 0 ||
             strcmp(component, "/Library/Application Support/iKanata/Runtime/Clients") == 0) &&
            (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != S_IRWXU) {
            free(component);
            return fail(error, error_capacity, EACCES, @"the installed runtime directories must have mode 0700");
        }
        if (public_executable &&
            (final || strcmp(component, ExecutableDirectory.fileSystemRepresentation) == 0) &&
            (metadata.st_gid != 0 || (metadata.st_mode & 07777) != 0755)) {
            free(component);
            return fail(error, error_capacity, EACCES, @"the installed engine directory and executables must be root:wheel mode 0755");
        }
        int acl_result = ikanata_protected_acl(component, error, error_capacity);
        if (acl_result != 0) {
            free(component);
            return acl_result;
        }
        component[index] = saved;
    }
    free(component);
    struct stat root;
    if (lstat("/", &root) != 0 || root.st_uid != 0 || (root.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return fail(error, error_capacity, EACCES, @"the filesystem root is not protected");
    }
    return ikanata_protected_acl("/", error, error_capacity);
}

int ikanata_verify_executable(const char *path, const char *identifier, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:identifier];
        if (name == nil || !valid_identifier(name)) {
            return fail(error, error_capacity, EINVAL, @"invalid executable signing identifier");
        }
        NSString *executable = [NSFileManager.defaultManager stringWithFileSystemRepresentation:path
                                                                                      length:strlen(path)];
        if (geteuid() == 0) {
            NSString *filename = [name isEqualToString:EngineIdentifier] ? @"kanata" :
                [name isEqualToString:ReaderIdentifier] ? @"ikanata-config-reader" : nil;
            if (filename == nil ||
                ![executable isEqualToString:[ExecutableDirectory stringByAppendingPathComponent:filename]]) {
                return fail(error, error_capacity, EACCES, @"root may execute only the fixed installed engine and reader");
            }
        } else {
            NSBundle *bundle = containing_app(error, error_capacity);
            if (bundle == nil) {
                return EACCES;
            }
            NSString *resources = [bundle.resourceURL.path stringByAppendingString:@"/"];
            if (resources == nil || ![executable hasPrefix:resources]) {
                return fail(error, error_capacity, EACCES, @"user validation requires a resource in this executable's own app");
            }
        }
        int result = protected_path(path, 2, geteuid() != 0, error, error_capacity);
        if (result != 0) {
            return result;
        }
        NSURL *url = [NSURL fileURLWithPath:executable];
        if (url == NULL) {
            return fail(error, error_capacity, EINVAL, @"invalid executable filesystem path");
        }
        SecStaticCodeRef code = NULL;
        OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code);
        SecRequirementRef requirement = NULL;
        if (status == errSecSuccess) {
            status = SecRequirementCreateWithString((__bridge CFStringRef)identifier_requirement(@[name]),
                                                    kSecCSDefaultFlags, &requirement);
        }
        if (status == errSecSuccess) {
            status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
                                                requirement);
        }
        if (requirement != NULL) {
            CFRelease(requirement);
        }
        if (code != NULL) {
            CFRelease(code);
        }
        if (status != errSecSuccess) {
            return security_error(error, error_capacity, status, @"verify protected executable signature");
        }
        return 0;
    }
}

static const char *const DriverDaemon =
    "/Library/Application Support/org.pqrs/Karabiner-DriverKit-VirtualHIDDevice/Applications/Karabiner-VirtualHIDDevice-Daemon.app/Contents/MacOS/Karabiner-VirtualHIDDevice-Daemon";
static NSString *const DriverDaemonRequirement =
    @"anchor apple generic and certificate leaf[subject.OU] = \"G43BCU2T37\" and identifier \"org.pqrs.Karabiner-VirtualHIDDevice-Daemon\"";

static int vendor_code(const char *path, NSString *text, uint8_t *error, size_t error_capacity) {
    int result = protected_path(path, 2, YES, error, error_capacity);
    if (result != 0) {
        return result;
    }
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    NSURL *url = [NSURL fileURLWithFileSystemRepresentation:path isDirectory:NO relativeToURL:nil];
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement);
    }
    if (status == errSecSuccess) {
        status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
                                           requirement);
    }
    if (requirement != NULL) CFRelease(requirement);
    if (code != NULL) CFRelease(code);
    return status == errSecSuccess ? 0 :
        security_error(error, error_capacity, status, @"verify vendor executable");
}

int ikanata_verify_driver_manager(uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        return vendor_code(
            "/Applications/.Karabiner-VirtualHIDDevice-Manager.app/Contents/MacOS/Karabiner-VirtualHIDDevice-Manager",
            @"anchor apple generic and certificate leaf[subject.OU] = \"G43BCU2T37\" and identifier \"org.pqrs.Karabiner-VirtualHIDDevice-Manager\"",
            error, error_capacity);
    }
}

static int driver_daemon_identity(pid_t pid, struct proc_bsdinfo *identity,
                                  uint8_t *error, size_t error_capacity) {
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, identity, sizeof(*identity)) != (int)sizeof(*identity)) {
        return system_error(error, error_capacity, errno ?: EIO, @"inspect vendor daemon identity");
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof(path)) <= 0 || strcmp(path, DriverDaemon) != 0 ||
        identity->pbi_uid != 0 || identity->pbi_ruid != 0 ||
        (identity->pbi_ppid != 1 && identity->pbi_ppid != (uint32_t)getpid())) {
        return fail(error, error_capacity, EBUSY,
                    @"the vendor daemon must be root-owned and not supervised by another app");
    }
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributePid: @(pid)};
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes,
                                                    kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecRequirementCreateWithString((__bridge CFStringRef)DriverDaemonRequirement,
                                                kSecCSDefaultFlags, &requirement);
    }
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    }
    if (requirement != NULL) CFRelease(requirement);
    if (code != NULL) CFRelease(code);
    return status == errSecSuccess ? 0 :
        security_error(error, error_capacity, status, @"verify running vendor daemon");
}

static int driver_daemon_clients(pid_t pid, uint8_t *error, size_t error_capacity) {
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0 || bytes > 16 * 1024 * 1024) {
        return fail(error, error_capacity, EBUSY, @"could not inspect vendor daemon clients");
    }
    size_t capacity = (size_t)bytes + 32 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds = malloc(capacity);
    if (fds == NULL) return fail(error, error_capacity, ENOMEM, @"cannot inspect vendor daemon clients");
    bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)capacity);
    int result = 0;
    if (bytes <= 0 || (size_t)bytes >= capacity) {
        result = fail(error, error_capacity, EBUSY, @"vendor daemon descriptors changed during inspection");
    } else {
        for (size_t index = 0; index < (size_t)bytes / sizeof(*fds); ++index) {
            if (fds[index].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo socket;
            if (proc_pidfdinfo(pid, fds[index].proc_fd, PROC_PIDFDSOCKETINFO,
                               &socket, sizeof(socket)) != (int)sizeof(socket)) {
                result = fail(error, error_capacity, EBUSY, @"could not inspect a vendor daemon socket");
                break;
            }
            if (socket.psi.soi_kind == SOCKINFO_UN && socket.psi.soi_type == SOCK_STREAM &&
                (socket.psi.soi_options & SO_ACCEPTCONN) == 0) {
                result = fail(error, error_capacity, EBUSY,
                              @"another client is connected to the shared VirtualHID daemon");
                break;
            }
        }
    }
    free(fds);
    return result;
}

static int stop_vendor_daemon(pid_t pid, uint8_t *error, size_t error_capacity) {
    struct proc_bsdinfo original, current;
    int result = driver_daemon_identity(pid, &original, error, error_capacity);
    if (result != 0) return result;
    result = driver_daemon_clients(pid, error, error_capacity);
    if (result != 0) return result;
    result = driver_daemon_identity(pid, &current, error, error_capacity);
    if (result != 0) return result;
    if (current.pbi_start_tvsec != original.pbi_start_tvsec ||
        current.pbi_start_tvusec != original.pbi_start_tvusec) {
        return fail(error, error_capacity, EBUSY, @"vendor daemon identity changed");
    }
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        return system_error(error, error_capacity, errno, @"stop verified vendor daemon");
    }
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &current, sizeof(current)) != (int)sizeof(current) ||
            current.pbi_start_tvsec != original.pbi_start_tvsec ||
            current.pbi_start_tvusec != original.pbi_start_tvusec || current.pbi_status == SZOMB) {
            return 0;
        }
        usleep(25000);
    }
    return fail(error, error_capacity, EBUSY, @"the vendor daemon did not stop; retry cleanup after it exits");
}

int ikanata_driver_cleanup(uint32_t action, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (geteuid() != 0 || getuid() != 0 || action > 1) {
            return fail(error, error_capacity, EACCES, @"driver cleanup requires the root service");
        }
        if (action == 0) {
            for (NSString *path in @[
                @"/Applications/.Karabiner-VirtualHIDDevice-Manager.app",
                @"/Library/Application Support/org.pqrs/Karabiner-DriverKit-VirtualHIDDevice",
                @"/Library/Application Support/org.pqrs/tmp/rootonly",
                @"/private/var/log/karabiner"
            ]) {
                NSString *existing = path;
                struct stat metadata;
                while (lstat(existing.fileSystemRepresentation, &metadata) != 0) {
                    if (errno != ENOENT) return system_error(error, error_capacity, errno, @"inspect vendor path");
                    existing = existing.stringByDeletingLastPathComponent;
                }
                int result = protected_path(existing.fileSystemRepresentation, 0, YES, error, error_capacity);
                if (result != 0) return result;
            }
            return 0;
        }
        int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        if (bytes <= 0) return fail(error, error_capacity, EIO, @"cannot enumerate vendor daemons");
        size_t capacity = (size_t)bytes + 256 * sizeof(pid_t);
        pid_t *pids = malloc(capacity);
        if (pids == NULL) return fail(error, error_capacity, ENOMEM, @"cannot enumerate vendor daemons");
        bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)capacity);
        int result = 0;
        if (bytes <= 0 || (size_t)bytes >= capacity) {
            result = fail(error, error_capacity, EBUSY, @"process list changed during driver cleanup");
        } else {
            for (size_t index = 0; index < (size_t)bytes / sizeof(*pids); ++index) {
                char path[PROC_PIDPATHINFO_MAXSIZE];
                if (pids[index] <= 0 || proc_pidpath(pids[index], path, sizeof(path)) <= 0) continue;
                if (strcmp(path, DriverDaemon) != 0) continue;
                result = stop_vendor_daemon(pids[index], error, error_capacity);
                if (result != 0) break;
            }
        }
        if (result == 0) {
            usleep(100000);
            bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)capacity);
            if (bytes <= 0 || (size_t)bytes >= capacity) {
                result = fail(error, error_capacity, EBUSY, @"cannot confirm the vendor daemon stopped");
            } else {
                for (size_t index = 0; index < (size_t)bytes / sizeof(*pids); ++index) {
                    char path[PROC_PIDPATHINFO_MAXSIZE];
                    struct proc_bsdinfo identity;
                    if (pids[index] <= 0 || proc_pidpath(pids[index], path, sizeof(path)) <= 0 ||
                        strcmp(path, DriverDaemon) != 0) continue;
                    if (proc_pidinfo(pids[index], PROC_PIDTBSDINFO, 0, &identity, sizeof(identity)) !=
                        (int)sizeof(identity) || identity.pbi_status != SZOMB) {
                        result = fail(error, error_capacity, EBUSY,
                                      @"another service restarted the vendor daemon; stop that service before retrying");
                        break;
                    }
                }
            }
        }
        free(pids);
        return result;
    }
}

static const char *const DriverPackageSource =
    "/Applications/iKanata.app/Contents/Resources/Karabiner-DriverKit-VirtualHIDDevice-8.0.0.pkg";
static const char *const DriverPackageSnapshot =
    "/Library/Application Support/iKanata/Runtime/DriverPackage.pkg";

int ikanata_driver_package(uint32_t action, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (geteuid() != 0 || action > 1) {
            return fail(error, error_capacity, EACCES, @"driver package preparation requires the root service");
        }
        int result = protected_path(RuntimeDirectory.fileSystemRepresentation, 0, NO, error, error_capacity);
        if (result != 0) {
            return result;
        }
        struct stat existing;
        if (lstat(DriverPackageSnapshot, &existing) == 0) {
            result = protected_path(DriverPackageSnapshot, 1, NO, error, error_capacity);
            if (result != 0) {
                return result;
            }
            if (existing.st_nlink != 1 ||
                ((existing.st_mode & 07777) != 0400 && (existing.st_mode & 07777) != 0600)) {
                return fail(error, error_capacity, EACCES, @"unsafe driver package snapshot");
            }
            if (chflags(DriverPackageSnapshot, 0) != 0 || unlink(DriverPackageSnapshot) != 0) {
                return system_error(error, error_capacity, errno, @"remove driver package snapshot");
            }
        } else if (errno != ENOENT) {
            return system_error(error, error_capacity, errno, @"inspect driver package snapshot");
        }
        if (action == 1) {
            return 0;
        }
        result = protected_path(DriverPackageSource, 1, YES, error, error_capacity);
        if (result != 0) {
            return result;
        }
        int source = open(DriverPackageSource, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (source < 0) {
            return system_error(error, error_capacity, errno, @"open bundled driver package");
        }
        struct stat metadata;
        if (fstat(source, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            metadata.st_nlink != 1) {
            close(source);
            return fail(error, error_capacity, EACCES, @"unsafe bundled driver package");
        }
        int snapshot = open(DriverPackageSnapshot,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (snapshot < 0) {
            int saved = errno;
            close(source);
            return system_error(error, error_capacity, saved, @"create driver package snapshot");
        }
        CC_SHA256_CTX hash;
        CC_SHA256_Init(&hash);
        unsigned char buffer[65536];
        ssize_t count;
        for (;;) {
            count = read(source, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                break;
            }
            CC_SHA256_Update(&hash, buffer, (CC_LONG)count);
            ssize_t written = 0;
            while (written < count) {
                ssize_t part = write(snapshot, buffer + written, (size_t)(count - written));
                if (part < 0 && errno == EINTR) {
                    continue;
                }
                if (part <= 0) {
                    result = system_error(error, error_capacity, part == 0 ? EIO : errno,
                                          @"write driver package snapshot");
                    break;
                }
                written += part;
            }
            if (result != 0) {
                break;
            }
        }
        if (count < 0 && result == 0) {
            result = system_error(error, error_capacity, errno, @"read bundled driver package");
        }
        close(source);
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256_Final(digest, &hash);
        const unsigned char expected[CC_SHA256_DIGEST_LENGTH] = {
            0x0d, 0x41, 0x2e, 0xa4, 0x96, 0x13, 0xb7, 0x0a,
            0x98, 0x1d, 0x81, 0x64, 0x61, 0xdc, 0x30, 0x19,
            0xb8, 0x4a, 0x96, 0x59, 0xfd, 0xe0, 0xa1, 0x56,
            0x93, 0x96, 0x97, 0x28, 0x3a, 0x61, 0xa7, 0xac
        };
        if (result == 0 && memcmp(digest, expected, sizeof(expected)) != 0) {
            result = fail(error, error_capacity, EACCES, @"bundled driver package checksum does not match");
        }
        if (result == 0 &&
            (fchmod(snapshot, 0400) != 0 || fsync(snapshot) != 0 ||
             fchflags(snapshot, UF_IMMUTABLE) != 0)) {
            result = system_error(error, error_capacity, errno, @"protect driver package snapshot");
        }
        if (result != 0) {
            fchflags(snapshot, 0);
        }
        close(snapshot);
        if (result != 0) {
            unlink(DriverPackageSnapshot);
        }
        return result;
    }
}

int ikanata_lock_file(int fd, uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        struct stat metadata;
        if (fstat(fd, &metadata) != 0) {
            return system_error(error, error_capacity, errno, @"inspect app instance lock");
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
            metadata.st_nlink != 1 || (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            return fail(error, error_capacity, EACCES, @"the app lock must be a private, user-owned regular file");
        }
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            return system_error(error, error_capacity, errno, @"acquire app instance lock");
        }
        return 0;
    }
}

typedef int (*ApplicationOpenHandler)(void);

@interface IKanataApplicationDelegate : NSObject <NSApplicationDelegate, NSUserNotificationCenterDelegate>
@property(nonatomic, assign) ApplicationOpenHandler onOpen;
@property(nonatomic, assign) BOOL showOnLaunch;
@end

@implementation IKanataApplicationDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    if (self.showOnLaunch && self.onOpen() != 0) {
        NSLog(@"iKanata could not display its launch status");
    }
}
- (BOOL)applicationShouldHandleReopen:(NSApplication *)application hasVisibleWindows:(BOOL)visible {
    (void)application;
    (void)visible;
    if (self.onOpen() != 0) {
        NSLog(@"iKanata could not display its status");
    }
    return NO;
}
- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center
    shouldPresentNotification:(NSUserNotification *)notification {
    (void)center;
    (void)notification;
    return YES;
}
@end

int ikanata_run_app(ApplicationOpenHandler on_open, int show_on_launch,
                     uint8_t *error, size_t error_capacity) {
    @autoreleasepool {
        if (![NSThread isMainThread] || geteuid() == 0 || on_open == NULL) {
            return fail(error, error_capacity, EINVAL, @"the background app requires the user's main thread");
        }
        if (installed_app_context(error, error_capacity) == nil) {
            return EINVAL;
        }
        NSApplication *application = NSApplication.sharedApplication;
        [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
        __attribute__((objc_precise_lifetime)) IKanataApplicationDelegate *delegate =
            [IKanataApplicationDelegate new];
        delegate.onOpen = on_open;
        delegate.showOnLaunch = show_on_launch != 0;
        application.delegate = delegate;
        NSUserNotificationCenter.defaultUserNotificationCenter.delegate = delegate;
        [application run];
        return 0;
    }
}

int ikanata_request_app_exit(uint8_t *error, size_t error_capacity) {
    if (geteuid() == 0) {
        return fail(error, error_capacity, EACCES, @"only the user app can request termination");
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApplication.sharedApplication terminate:nil];
    });
    return 0;
}
