use crate::{RedactedId, sha256_hex};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileFacts {
    pub kind: FileKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub hard_links: u64,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileSecurityError {
    NotAbsolute,
    ParentTraversal,
    Symlink(PathBuf),
    WrongKind(PathBuf),
    HardLinked(PathBuf),
    WrongOwner {
        path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
    },
    WrongMode {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    InsecureParent(PathBuf),
    Missing(PathBuf),
    ChangedSincePlan(PathBuf),
    Io,
}

impl fmt::Display for FileSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure filesystem precondition failed")
    }
}

impl std::error::Error for FileSecurityError {}

pub fn validate_absolute_path(path: &Path) -> Result<(), FileSecurityError> {
    if !path.is_absolute() {
        return Err(FileSecurityError::NotAbsolute);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(FileSecurityError::ParentTraversal);
    }
    Ok(())
}

pub fn validate_secure_parent(
    path: &Path,
    facts: &FileFacts,
    expected_uid: u32,
) -> Result<(), FileSecurityError> {
    validate_absolute_path(path)?;
    if facts.kind == FileKind::Symlink {
        return Err(FileSecurityError::Symlink(path.to_path_buf()));
    }
    if facts.kind != FileKind::Directory {
        return Err(FileSecurityError::WrongKind(path.to_path_buf()));
    }
    if facts.uid != expected_uid || facts.mode & 0o022 != 0 {
        return Err(FileSecurityError::InsecureParent(path.to_path_buf()));
    }
    Ok(())
}

pub fn validate_secure_file(
    path: &Path,
    facts: &FileFacts,
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), FileSecurityError> {
    validate_absolute_path(path)?;
    if facts.kind == FileKind::Symlink {
        return Err(FileSecurityError::Symlink(path.to_path_buf()));
    }
    if facts.kind != FileKind::Regular {
        return Err(FileSecurityError::WrongKind(path.to_path_buf()));
    }
    if facts.hard_links != 1 {
        return Err(FileSecurityError::HardLinked(path.to_path_buf()));
    }
    if facts.uid != expected_uid || facts.gid != expected_gid {
        return Err(FileSecurityError::WrongOwner {
            path: path.to_path_buf(),
            expected_uid,
            expected_gid,
        });
    }
    if facts.mode & 0o7777 != expected_mode {
        return Err(FileSecurityError::WrongMode {
            path: path.to_path_buf(),
            expected: expected_mode,
            actual: facts.mode & 0o7777,
        });
    }
    Ok(())
}

pub trait FileInspector: Send + Sync {
    fn inspect_no_follow(&self, path: &Path) -> Result<Option<FileFacts>, FileSecurityError>;
    fn read(&self, path: &Path) -> Result<Vec<u8>, FileSecurityError>;
}

/// Read-only host filesystem adapter. Mutating operations intentionally live behind
/// a separate capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFileInspector;

#[cfg(unix)]
impl FileInspector for StdFileInspector {
    fn inspect_no_follow(&self, path: &Path) -> Result<Option<FileFacts>, FileSecurityError> {
        use std::os::unix::fs::MetadataExt;

        validate_absolute_path(path)?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(FileSecurityError::Io),
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_file() {
            FileKind::Regular
        } else if file_type.is_dir() {
            FileKind::Directory
        } else {
            FileKind::Other
        };
        Ok(Some(FileFacts {
            kind,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            hard_links: metadata.nlink(),
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
        }))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, FileSecurityError> {
        validate_absolute_path(path)?;
        fs::read(path).map_err(|_| FileSecurityError::Io)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AtomicWriteRequest {
    pub target: PathBuf,
    pub backup: PathBuf,
    pub expected_original_sha256: Option<String>,
    pub content: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub fsync_file_and_directory: bool,
}

impl fmt::Debug for AtomicWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicWriteRequest")
            .field(
                "target",
                &RedactedId::from_sensitive(self.target.as_os_str().as_encoded_bytes()),
            )
            .field(
                "backup",
                &RedactedId::from_sensitive(self.backup.as_os_str().as_encoded_bytes()),
            )
            .field("expected_original_sha256", &self.expected_original_sha256)
            .field("content", &"<redacted>")
            .field("mode", &format_args!("{:04o}", self.mode))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("fsync_file_and_directory", &self.fsync_file_and_directory)
            .finish()
    }
}

impl Drop for AtomicWriteRequest {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

pub trait AtomicWriter: Send + Sync {
    /// Implementations must create a same-directory temporary file with O_EXCL and
    /// O_NOFOLLOW semantics, set owner/mode, fsync file and directory, then rename.
    fn atomic_replace(&self, request: &AtomicWriteRequest) -> Result<(), FileSecurityError>;
}

/// Linux/NixOS atomic writer using descriptor-relative operations.
///
/// It fails closed when `openat2(RESOLVE_NO_SYMLINKS)` is unavailable. Target,
/// backup and temporary file are opened relative to one verified directory
/// descriptor with `O_NOFOLLOW`. Ownership is set on the open descriptors (never
/// by path), file and directory are fsynced, and rename is descriptor-relative.
/// It intentionally does not overwrite an existing backup.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct LinuxAtomicWriter {
    sequence: AtomicU64,
}

#[cfg(target_os = "linux")]
impl AtomicWriter for LinuxAtomicWriter {
    fn atomic_replace(&self, request: &AtomicWriteRequest) -> Result<(), FileSecurityError> {
        use rustix::fs::{
            ABS, AtFlags, Gid, Mode, OFlags, ResolveFlags, Uid, fchmod, fchown, fstat, fsync,
            openat, openat2, renameat, unlinkat,
        };

        validate_atomic_request_paths(request)?;
        let parent = request
            .target
            .parent()
            .ok_or(FileSecurityError::ParentTraversal)?;
        let target_name = request
            .target
            .file_name()
            .ok_or(FileSecurityError::ParentTraversal)?;
        let backup_name = request
            .backup
            .file_name()
            .ok_or(FileSecurityError::ParentTraversal)?;

        let directory = openat2(
            ABS,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| FileSecurityError::Io)?;
        let directory_stat = fstat(&directory).map_err(|_| FileSecurityError::Io)?;
        if directory_stat.st_uid != request.uid || directory_stat.st_mode & 0o022 != 0 {
            return Err(FileSecurityError::InsecureParent(parent.to_path_buf()));
        }

        let original = match &request.expected_original_sha256 {
            Some(expected) => {
                let original_fd = openat(
                    &directory,
                    target_name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| FileSecurityError::ChangedSincePlan(request.target.clone()))?;
                let mut original = fs::File::from(original_fd);
                verify_open_regular_file(
                    &original,
                    &request.target,
                    request.mode,
                    request.uid,
                    request.gid,
                )?;
                let original_stat = original.metadata().map_err(|_| FileSecurityError::Io)?;
                let mut content = Vec::new();
                original
                    .read_to_end(&mut content)
                    .map_err(|_| FileSecurityError::Io)?;
                if sha256_hex(&content) != *expected {
                    return Err(FileSecurityError::ChangedSincePlan(request.target.clone()));
                }
                original
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| FileSecurityError::Io)?;

                let backup_fd = openat(
                    &directory,
                    backup_name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(request.mode),
                )
                .map_err(|_| FileSecurityError::Io)?;
                fchmod(&backup_fd, Mode::from_bits_truncate(request.mode))
                    .map_err(|_| FileSecurityError::Io)?;
                fchown(
                    &backup_fd,
                    Some(Uid::from_raw(request.uid)),
                    Some(Gid::from_raw(request.gid)),
                )
                .map_err(|_| FileSecurityError::Io)?;
                let mut backup = fs::File::from(backup_fd);
                io::copy(&mut original, &mut backup).map_err(|_| FileSecurityError::Io)?;
                backup.sync_all().map_err(|_| FileSecurityError::Io)?;
                Some(original_stat)
            }
            None => {
                match openat(
                    &directory,
                    target_name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(_) => {
                        return Err(FileSecurityError::ChangedSincePlan(request.target.clone()));
                    }
                    Err(rustix::io::Errno::NOENT) => {}
                    Err(_) => return Err(FileSecurityError::Io),
                }
                None
            }
        };

        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let target_name_display = target_name.to_string_lossy();
        let temporary_name = format!(
            ".{target_name_display}.nixkeyforge.tmp.{}.{}",
            std::process::id(),
            sequence
        );
        let result = (|| {
            let temporary_fd = openat(
                &directory,
                temporary_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(request.mode),
            )
            .map_err(|_| FileSecurityError::Io)?;
            fchmod(&temporary_fd, Mode::from_bits_truncate(request.mode))
                .map_err(|_| FileSecurityError::Io)?;
            fchown(
                &temporary_fd,
                Some(Uid::from_raw(request.uid)),
                Some(Gid::from_raw(request.gid)),
            )
            .map_err(|_| FileSecurityError::Io)?;
            let mut temporary = fs::File::from(temporary_fd);
            temporary
                .write_all(&request.content)
                .map_err(|_| FileSecurityError::Io)?;
            temporary.sync_all().map_err(|_| FileSecurityError::Io)?;
            verify_open_regular_file(
                &temporary,
                &request.target,
                request.mode,
                request.uid,
                request.gid,
            )?;

            match original {
                Some(ref original_stat) => {
                    let current_fd = openat(
                        &directory,
                        target_name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| FileSecurityError::ChangedSincePlan(request.target.clone()))?;
                    let mut current = fs::File::from(current_fd);
                    let current_stat = current.metadata().map_err(|_| FileSecurityError::Io)?;
                    if current_stat.dev() != original_stat.dev()
                        || current_stat.ino() != original_stat.ino()
                    {
                        return Err(FileSecurityError::ChangedSincePlan(request.target.clone()));
                    }
                    let mut current_content = Vec::new();
                    current
                        .read_to_end(&mut current_content)
                        .map_err(|_| FileSecurityError::Io)?;
                    if request
                        .expected_original_sha256
                        .as_ref()
                        .is_none_or(|expected| sha256_hex(&current_content) != *expected)
                    {
                        return Err(FileSecurityError::ChangedSincePlan(request.target.clone()));
                    }
                }
                None => {
                    match openat(
                        &directory,
                        target_name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(_) => {
                            return Err(FileSecurityError::ChangedSincePlan(
                                request.target.clone(),
                            ));
                        }
                        Err(rustix::io::Errno::NOENT) => {}
                        Err(_) => return Err(FileSecurityError::Io),
                    }
                }
            }
            renameat(&directory, temporary_name.as_str(), &directory, target_name)
                .map_err(|_| FileSecurityError::Io)?;
            if request.fsync_file_and_directory {
                fsync(&directory).map_err(|_| FileSecurityError::Io)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn verify_open_regular_file(
    file: &fs::File,
    display_path: &Path,
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), FileSecurityError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|_| FileSecurityError::Io)?;
    let facts = FileFacts {
        kind: if metadata.is_file() {
            FileKind::Regular
        } else {
            FileKind::Other
        },
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        hard_links: metadata.nlink(),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
    };
    validate_secure_file(
        display_path,
        &facts,
        expected_mode,
        expected_uid,
        expected_gid,
    )
}

fn validate_atomic_request_paths(request: &AtomicWriteRequest) -> Result<(), FileSecurityError> {
    validate_absolute_path(&request.target)?;
    validate_absolute_path(&request.backup)?;
    if request.target == request.backup
        || request.target.parent().is_none()
        || request.target.parent() != request.backup.parent()
    {
        return Err(FileSecurityError::ParentTraversal);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockFile {
    pub facts: FileFacts,
    pub content: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MockFileSystem {
    files: Mutex<BTreeMap<PathBuf, MockFile>>,
    writes: Mutex<Vec<AtomicWriteRequest>>,
}

impl MockFileSystem {
    pub fn insert(&self, path: impl Into<PathBuf>, file: MockFile) {
        lock_unpoison(&self.files).insert(path.into(), file);
    }

    pub fn writes(&self) -> Vec<AtomicWriteRequest> {
        lock_unpoison(&self.writes).clone()
    }
}

impl FileInspector for MockFileSystem {
    fn inspect_no_follow(&self, path: &Path) -> Result<Option<FileFacts>, FileSecurityError> {
        Ok(lock_unpoison(&self.files)
            .get(path)
            .map(|file| file.facts.clone()))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, FileSecurityError> {
        lock_unpoison(&self.files)
            .get(path)
            .map(|file| file.content.clone())
            .ok_or_else(|| FileSecurityError::Missing(path.to_path_buf()))
    }
}

impl AtomicWriter for MockFileSystem {
    fn atomic_replace(&self, request: &AtomicWriteRequest) -> Result<(), FileSecurityError> {
        if let Some(expected) = &request.expected_original_sha256 {
            let current = self.read(&request.target)?;
            if sha256_hex(&current) != *expected {
                return Err(FileSecurityError::ChangedSincePlan(request.target.clone()));
            }
        }
        lock_unpoison(&self.writes).push(request.clone());
        Ok(())
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    fn facts(kind: FileKind, mode: u32, links: u64) -> FileFacts {
        FileFacts {
            kind,
            mode,
            uid: 0,
            gid: 0,
            hard_links: links,
            device: 1,
            inode: 2,
            size: 0,
        }
    }

    #[test]
    fn rejects_symlink_and_hardlink_facts() {
        let path = Path::new("/etc/u2f_mappings");
        assert!(matches!(
            validate_secure_file(path, &facts(FileKind::Symlink, 0o600, 1), 0o600, 0, 0),
            Err(FileSecurityError::Symlink(_))
        ));
        assert!(matches!(
            validate_secure_file(path, &facts(FileKind::Regular, 0o600, 2), 0o600, 0, 0),
            Err(FileSecurityError::HardLinked(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn tempdir_inspector_does_not_follow_symlink_or_hide_hardlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let original = temp.path().join("mapping");
        let linked = temp.path().join("linked");
        let symbolic = temp.path().join("symbolic");
        File::create(&original)?;
        fs::hard_link(&original, &linked)?;
        symlink(&original, &symbolic)?;
        let inspector = StdFileInspector;
        let original_facts = inspector
            .inspect_no_follow(&original)?
            .ok_or("original must exist")?;
        let symbolic_facts = inspector
            .inspect_no_follow(&symbolic)?
            .ok_or("symlink must exist")?;
        assert_eq!(original_facts.hard_links, 2);
        assert_eq!(symbolic_facts.kind, FileKind::Symlink);
        Ok(())
    }

    #[test]
    fn atomic_writer_detects_toctou_content_change() {
        let fs = MockFileSystem::default();
        let path = PathBuf::from("/safe/file");
        fs.insert(
            path.clone(),
            MockFile {
                facts: facts(FileKind::Regular, 0o600, 1),
                content: b"changed".to_vec(),
            },
        );
        let request = AtomicWriteRequest {
            target: path.clone(),
            backup: PathBuf::from("/safe/file.bak"),
            expected_original_sha256: Some(sha256_hex(b"original")),
            content: b"replacement".to_vec(),
            mode: 0o600,
            uid: 0,
            gid: 0,
            fsync_file_and_directory: true,
        };
        assert_eq!(
            fs.atomic_replace(&request),
            Err(FileSecurityError::ChangedSincePlan(path))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_atomic_writer_backs_up_fsyncs_and_replaces() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let target = temp.path().join("mapping");
        let backup = temp.path().join("mapping.bak");
        fs::write(&target, b"before")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::metadata(temp.path())?;
        let writer = LinuxAtomicWriter::default();
        writer.atomic_replace(&AtomicWriteRequest {
            target: target.clone(),
            backup: backup.clone(),
            expected_original_sha256: Some(sha256_hex(b"before")),
            content: b"after".to_vec(),
            mode: 0o600,
            uid: metadata.uid(),
            gid: metadata.gid(),
            fsync_file_and_directory: true,
        })?;
        assert_eq!(fs::read(&target)?, b"after");
        assert_eq!(fs::read(&backup)?, b"before");
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o7777, 0o600);
        Ok(())
    }
}
