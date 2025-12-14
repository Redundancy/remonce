use crate::config::FileConfig;
use glob::glob;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize, Clone)]
pub struct FileMetadata {
    pub name: Option<String>,
    pub path: String,
    pub description: Option<String>,
}

pub fn list_available_files(configs: &[FileConfig]) -> Vec<FileMetadata> {
    let mut files = Vec::new();

    for config in configs {
        // If it's a simple path (no glob patterns), just add it (if it exists?)
        // Or we can just use glob() on everything since it handles non-glob paths too.
        if let Ok(paths) = glob(&config.path) {
            for entry in paths {
                if let Ok(path) = entry {
                    files.push(FileMetadata {
                        name: config.name.clone(),
                        path: path.to_string_lossy().to_string(), // Absolute or relative as resolved
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

pub fn resolve_file_path(configs: &[FileConfig], identifier: &FileIdentifier) -> Option<PathBuf> {
    match identifier {
        FileIdentifier::Name(name) => {
            // Find config with this name
            for config in configs {
                if config.name.as_deref() == Some(name) {
                    // If name matches, we must find the concrete file. 
                    // If the config path is a glob, implies we might need to be specific?
                    // For now, if name maps to a glob, we might just pick the first match or fail if ambiguous?
                    // User requirement: "Files can be named, in which case they are accessible using their name."
                    // If "logs/*.log" is named "logs", asking for "logs" -> maybe ambiguous?
                    // Let's assume if named, it SHOULD be a single file, OR we just return the first match.
                    if let Ok(mut paths) = glob(&config.path) {
                        if let Some(Ok(path)) = paths.next() {
                           return Some(path);
                        }
                    }
                }
            }
            None
        }
        FileIdentifier::Path(requested_path) => {
            // Check if requested_path matches ANY config's glob expansion
            let req_path = PathBuf::from(requested_path);
            
            // Normalize absolute path if possible, but simplest check is:
            // Does this path exist in the set of allowed paths?
            
            for config in configs {
                 if let Ok(paths) = glob(&config.path) {
                    for entry in paths {
                        if let Ok(allowed_path) = entry {
                            if allowed_path == req_path {
                                return Some(allowed_path);
                            }
                        }
                    }
                 }
            }
            None
        }
    }
}
