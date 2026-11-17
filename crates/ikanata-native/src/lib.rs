//! Safe native macOS APIs for iKanata's app, CLI, and privileged service.

mod api;

pub use api::{
    Caller, Operation, bundle_resource, console_uid, drop_privileges, effective_uid, home_for_uid,
    lock_file, notify, refresh_service_registration, register_service, request, request_app_exit,
    request_input_permissions, run_app, serve, service_status, session_active, set_login_enabled,
    stop_standalone_driver_daemons, trash_app, unregister_service, verify_driver_manager,
    verify_driver_removal_paths, verify_executable, with_driver_package,
};
