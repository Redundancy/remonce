use crate::config::FileConfig;
use glob::glob;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Clone)]
pub struct FileMetadata {
    pub name: Option<String>,
    pub path: String,
    pub description: Option<String>,
}

/// Resolve a path through `canonicalize` (which follows symlinks in parent
/// components and gives us a stable absolute path), but reject the final
/// component being a symlink itself. This prevents an attacker who can write
/// inside a globbed directory from staging a symlink to a sensitive file
/// outside the configured allowlist.
fn safe_canonicalize(p: &Path) -> Option<PathBuf> {
    let lstat = std::fs::symlink_metadata(p).ok()?;
    if lstat.file_type().is_symlink() {
        tracing::warn!("File resolver: refusing symlink {}", p.display());
        return None;
    }
    if !lstat.file_type().is_file() {
        return None;
    }
    std::fs::canonicalize(p).ok()
}

pub fn list_available_files(configs: &[FileConfig]) -> Vec<FileMetadata> {
    let mut files = Vec::new();
    for config in configs {
        if let Ok(paths) = glob(&config.path) {
            for entry in paths.flatten() {
                if let Some(canon) = safe_canonicalize(&entry) {
                    files.push(FileMetadata {
                        name: config.name.clone(),
                        path: canon.to_string_lossy().to_string(),
                        description: config.description.clone(),
                    });
                }
            }
        }
    }
    files
}

pub enum FileIdentifier {
    Name(String),
    Path(String),
}

/// Resolve a file identifier to a concrete on-disk path, with two safety
/// rails beyond the configured glob match:
///
/// 1. The final path must not be a symlink (`safe_canonicalize` rejects it).
/// 2. For path-identifiers, the canonicalized request must equal a
///    canonicalized glob expansion — `==` on raw `PathBuf`s isn't enough
///    because callers can pass relative paths or `..` segments.
pub fn resolve_file_path(configs: &[FileConfig], identifier: &FileIdentifier) -> Option<PathBuf> {
    match identifier {
        FileIdentifier::Name(name) => {
            for config in configs.iter().filter(|c| c.name.as_deref() == Some(name)) {
                if let Ok(mut paths) = glob(&config.path) {
                    if let Some(Ok(p)) = paths.next() {
                        if let Some(canon) = safe_canonicalize(&p) {
                            return Some(canon);
                        }
                    }
                }
            }
            None
        }
        FileIdentifier::Path(requested_path) => {
            let requested_canon = safe_canonicalize(Path::new(requested_path))?;
            for config in configs {
                if let Ok(paths) = glob(&config.path) {
                    for entry in paths.flatten() {
                        if let Some(allowed_canon) = safe_canonicalize(&entry) {
                            if allowed_canon == requested_canon {
                                return Some(allowed_canon);
                            }
                        }
                    }
                }
            }
            None
        }
    }
}
