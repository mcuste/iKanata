//! Read and observe user-owned Kanata files without changing existing configuration.
//!
//! Call these functions as the enrolled, unprivileged user. This crate does not
//! change identity or restrict includes to a home directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Caps Lock to Escape configuration, with no includes or command execution.
pub const STARTER: &str = include_str!("../starter.kbd");

/// Return the default configuration path for the enrolled user's home directory.
pub fn default_path(home: &Path) -> PathBuf {
    home.join(".config/kanata/config.kbd")
}

/// Create the starter only if the path is absent, returning whether it was created.
///
/// Call only as the enrolled, unprivileged user, never from the root service.
/// Existing files and symlinks remain unchanged. Existing files must be readable,
/// regular, and nonempty. Use [`validate`] to check Kanata syntax separately.
pub fn setup(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            read_regular(path)?;
            return Ok(false);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(STARTER.as_bytes())?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_regular(path)?;
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Check a configuration with the caller's fixed bundled engine, as the user.
///
/// The child receives only a safe system `PATH`. Its output never appears in
/// returned errors because diagnostics can contain private configuration text.
pub fn validate(engine: &Path, config: &Path) -> io::Result<()> {
    let status = Command::new(engine)
        .args(["--check", "--no-wait", "-c"])
        .arg(config)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| io::Error::new(error.kind(), "could not run configuration validation"))?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid("configuration validation failed"))
    }
}

/// Return canonical paths for the main file and its transitive include files.
///
/// Relative includes resolve against the selected main file's directory, not its
/// symlink target's directory. Repeated targets appear once; cycles are errors.
/// Parsing recognizes top-level include forms, not text in comments or strings.
/// Call as the enrolled user; includes may point outside that user's home.
pub fn dependencies(path: &Path) -> io::Result<Vec<PathBuf>> {
    let graph = load_graph(path)?;
    Ok(graph
        .into_values()
        .map(|file| file.target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

/// Poll files and include links by contents and file identity, not timestamps alone.
///
/// Errors preserve the last complete dependency graph. The caller must keep its
/// running keymap when a file disappears or an edit cannot be parsed.
pub struct Watcher {
    config: PathBuf,
    files: BTreeMap<PathBuf, LoadedFile>,
}

impl fmt::Debug for Watcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Watcher")
            .field("config", &self.config)
            .field("dependency_count", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl Watcher {
    /// Capture the current complete configuration graph in the user's context.
    pub fn new(config: PathBuf) -> io::Result<Self> {
        let config = std::path::absolute(config)?;
        let files = load_graph(&config)?;
        Ok(Self { config, files })
    }

    /// Return whether any contents, target, identity, or dependency changed.
    ///
    /// A successful call replaces the snapshot. An error leaves it unchanged.
    /// Validate changed files before asking the running engine to reload them.
    pub fn changed(&mut self) -> io::Result<bool> {
        let files = load_graph(&self.config)?;
        if self.files == files {
            return Ok(false);
        }
        self.files = files;
        Ok(true)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LoadedFile {
    target: PathBuf,
    contents: String,
    identity: FileIdentity,
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                modified: metadata.modified().ok(),
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(invalid("configuration dependency is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o444 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration dependency is not readable",
            ));
        }
    }
    Ok(())
}

fn read_regular(path: &Path) -> io::Result<LoadedFile> {
    let target = fs::canonicalize(path)?;
    regular(&fs::metadata(&target)?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    // Do not block if a regular file becomes a FIFO between metadata and open.
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0004);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0800);
    }
    let mut file: File = options.open(&target)?;
    let metadata = file.metadata()?;
    regular(&metadata)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    if contents.trim().is_empty() {
        return Err(invalid("configuration dependency is empty"));
    }
    Ok(LoadedFile {
        target,
        contents,
        identity: FileIdentity::from_metadata(&metadata),
    })
}

enum Visit {
    Enter(PathBuf),
    Leave(PathBuf),
}

fn load_graph(path: &Path) -> io::Result<BTreeMap<PathBuf, LoadedFile>> {
    let path = std::path::absolute(path)?;
    let base = path
        .parent()
        .ok_or_else(|| invalid("configuration path has no parent directory"))?;
    let mut pending = vec![Visit::Enter(path.clone())];
    let mut files = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut visited = BTreeSet::new();
    while let Some(visit) = pending.pop() {
        let path = match visit {
            Visit::Enter(path) => path,
            Visit::Leave(target) => {
                active.remove(&target);
                continue;
            }
        };
        let file = read_regular(&path)?;
        if active.contains(&file.target) {
            return Err(invalid("configuration include cycle"));
        }
        if visited.insert(file.target.clone()) {
            let includes = include_paths(&file.contents)?;
            active.insert(file.target.clone());
            pending.push(Visit::Leave(file.target.clone()));
            for include in includes.into_iter().rev() {
                pending.push(Visit::Enter(base.join(include)));
            }
        }
        files.insert(path, file);
    }
    Ok(files)
}

#[derive(Debug)]
enum Token<'a> {
    Open,
    Close,
    Atom(&'a str),
}

struct Lexer<'a> {
    remaining: &'a str,
}

impl<'a> Lexer<'a> {
    fn next(&mut self) -> io::Result<Option<Token<'a>>> {
        loop {
            self.remaining = self
                .remaining
                .trim_start_matches(|c: char| c.is_ascii_whitespace());
            if let Some(rest) = self.remaining.strip_prefix(";;") {
                self.remaining = rest.find('\n').map_or("", |end| rest.split_at(end).1);
            } else if let Some(rest) = self.remaining.strip_prefix("#|") {
                self.remaining = rest;
                self.block_comment()?;
            } else {
                break;
            }
        }
        if self.remaining.is_empty() {
            return Ok(None);
        }
        if let Some(rest) = self.remaining.strip_prefix('(') {
            self.remaining = rest;
            return Ok(Some(Token::Open));
        }
        if let Some(rest) = self.remaining.strip_prefix(')') {
            self.remaining = rest;
            return Ok(Some(Token::Close));
        }
        let atom = if self.remaining.starts_with("r#\"") {
            self.string("r#\"", "\"#", false)?
        } else if self.remaining.starts_with('"') {
            self.string("\"", "\"", true)?
        } else {
            let end = self
                .remaining
                .find(|c: char| c.is_ascii_whitespace() || matches!(c, '(' | ')' | '"'))
                .unwrap_or(self.remaining.len());
            let (atom, rest) = self.remaining.split_at(end);
            self.remaining = rest;
            atom
        };
        Ok(Some(Token::Atom(atom)))
    }

    fn string(&mut self, start: &str, end: &str, single_line: bool) -> io::Result<&'a str> {
        let rest = self
            .remaining
            .strip_prefix(start)
            .ok_or_else(|| invalid("invalid configuration string"))?;
        let length = rest
            .find(end)
            .ok_or_else(|| invalid("unterminated configuration string"))?;
        if single_line && rest.split_at(length).0.contains('\n') {
            return Err(invalid("unterminated configuration string"));
        }
        let (atom, rest) = self.remaining.split_at(start.len() + length + end.len());
        self.remaining = rest;
        Ok(atom)
    }

    fn block_comment(&mut self) -> io::Result<()> {
        let mut depth = 1_usize;
        while depth != 0 {
            let Some(position) = self.remaining.find(['#', '|']) else {
                return Err(invalid("unterminated configuration block comment"));
            };
            self.remaining = self.remaining.split_at(position).1;
            if let Some(rest) = self.remaining.strip_prefix("#|") {
                depth += 1;
                self.remaining = rest;
            } else if let Some(rest) = self.remaining.strip_prefix("|#") {
                depth -= 1;
                self.remaining = rest;
            } else {
                self.remaining = self.remaining.split_at(1).1;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Form<'a> {
    count: usize,
    head: Option<&'a str>,
    argument: Option<&'a str>,
}

fn include_paths(contents: &str) -> io::Result<Vec<PathBuf>> {
    let mut lexer = Lexer {
        remaining: contents.strip_prefix('\u{feff}').unwrap_or(contents),
    };
    let mut stack: Vec<Form<'_>> = Vec::new();
    let mut includes = Vec::new();
    while let Some(token) = lexer.next()? {
        match token {
            Token::Open => {
                if let Some(parent) = stack.last_mut() {
                    parent.count += 1;
                }
                stack.push(Form::default());
            }
            Token::Close => {
                let form = stack
                    .pop()
                    .ok_or_else(|| invalid("unmatched configuration closing parenthesis"))?;
                if stack.is_empty() && form.head == Some("include") {
                    if form.count != 2 {
                        return Err(invalid("include requires exactly one file path"));
                    }
                    let argument = form
                        .argument
                        .ok_or_else(|| invalid("include path must be an atom"))?;
                    let argument = if let Some(raw) = argument.strip_prefix("r#\"") {
                        raw.strip_suffix("\"#").unwrap_or(raw)
                    } else if let Some(quoted) = argument.strip_prefix('"') {
                        quoted.strip_suffix('"').unwrap_or(quoted)
                    } else {
                        argument
                    };
                    if argument.is_empty() {
                        return Err(invalid("include path is empty"));
                    }
                    includes.push(PathBuf::from(argument));
                }
            }
            Token::Atom(atom) => {
                let form = stack
                    .last_mut()
                    .ok_or_else(|| invalid("configuration atom is outside a form"))?;
                form.count += 1;
                if form.count == 1 {
                    form.head = Some(atom);
                } else if form.count == 2 {
                    form.argument = Some(atom);
                }
            }
        }
    }
    if !stack.is_empty() {
        return Err(invalid("unclosed configuration form"));
    }
    Ok(includes)
}
