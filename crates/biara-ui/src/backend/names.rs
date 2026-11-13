//! Names the user gives functions and data.
//!
//! Stored in the engine's own annotation format (`biara_proto::annotations::Annotations`), so
//! `biara lift --annotations <file>` reads what the UI saved. The file lives in the user's
//! data directory, keyed by the binary's path, so read-only locations such as `/usr/lib` work
//! and nothing is written next to the binary.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use biara_proto::annotations::{Annotations, FunctionAnnotation};

/// What a name is attached to; the annotation file keeps functions and data apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    Function,
    Data,
}

/// The user's names, plus where they are saved.
#[derive(Debug, Default)]
pub struct Names {
    functions: BTreeMap<u64, String>,
    data: BTreeMap<u64, String>,
    file: Option<PathBuf>,
    /// Bumped on every change; views cache against it.
    version: u64,
}

/// Why a name was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameError(pub String);

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A valid C identifier: the renderer needs names it can print as code.
pub fn validate(name: &str) -> Result<(), NameError> {
    let mut chars = name.chars();
    let first = chars
        .next()
        .ok_or_else(|| NameError("a name cannot be empty".into()))?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(NameError(
            "a name starts with a letter or underscore".into(),
        ));
    }
    if let Some(bad) = chars.find(|c| !(c.is_ascii_alphanumeric() || *c == '_')) {
        return Err(NameError(format!(
            "{bad:?} is not allowed in a name; use letters, digits and underscores"
        )));
    }
    Ok(())
}

impl Names {
    /// The names saved for `binary`, if any. A missing or unreadable file is an empty set;
    /// the error, if there was one, is returned so the UI can say so.
    pub fn load(binary: &Path) -> (Names, Option<String>) {
        let file = Self::file_for(binary);
        let mut names = Names {
            file: file.clone(),
            ..Names::default()
        };
        let Some(path) = file else {
            return (names, None);
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Annotations>(&text) {
                Ok(a) => {
                    names.functions = a
                        .functions
                        .into_iter()
                        .filter_map(|(addr, f)| Some((addr, f.name?)))
                        .collect();
                    names.data = a.globals;
                    (names, None)
                }
                Err(e) => (names, Some(format!("{}: {e}", path.display()))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (names, None),
            Err(e) => (names, Some(format!("{}: {e}", path.display()))),
        }
    }

    /// A names set that is never written to disk.
    pub fn in_memory() -> Names {
        Names::default()
    }

    /// Where `binary`'s names live: `<data dir>/biara/names/<hash of the path>.json`.
    pub fn file_for(binary: &Path) -> Option<PathBuf> {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))?;
        let canonical = binary.canonicalize().unwrap_or_else(|_| binary.to_owned());
        let hash = blake3::hash(canonical.to_string_lossy().as_bytes()).to_hex();
        let stem = canonical
            .file_name()
            .map_or_else(|| "binary".into(), |n| n.to_string_lossy().into_owned());
        Some(
            data.join("biara/names")
                .join(format!("{stem}-{}.json", &hash[..16])),
        )
    }

    pub fn path(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn get(&self, addr: u64) -> Option<&str> {
        self.functions
            .get(&addr)
            .or_else(|| self.data.get(&addr))
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.functions.len() + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Name `addr`, or remove its name when `name` is empty. Saves immediately; the error from
    /// saving, if any, is returned (the name still applies for this session).
    pub fn set(
        &mut self,
        addr: u64,
        kind: NameKind,
        name: &str,
    ) -> Result<Option<String>, NameError> {
        let map = match kind {
            NameKind::Function => &mut self.functions,
            NameKind::Data => &mut self.data,
        };
        if name.is_empty() {
            map.remove(&addr);
        } else {
            validate(name)?;
            map.insert(addr, name.to_owned());
        }
        self.version += 1;
        Ok(self.save().err())
    }

    fn annotations(&self) -> Annotations {
        Annotations {
            functions: self
                .functions
                .iter()
                .map(|(&a, n)| {
                    (
                        a,
                        FunctionAnnotation {
                            name: Some(n.clone()),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
            globals: self.data.clone(),
            ..Annotations::default()
        }
    }

    /// Write the names atomically (temp file, then rename).
    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        let write = || -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("json.tmp");
            let json =
                serde_json::to_vec_pretty(&self.annotations()).map_err(std::io::Error::other)?;
            std::fs::write(&tmp, json)?;
            std::fs::rename(&tmp, path)
        };
        write().map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_dir(dir: &Path) -> Names {
        Names {
            file: Some(dir.join("n.json")),
            ..Names::default()
        }
    }

    #[test]
    fn names_must_be_c_identifiers() {
        assert!(validate("parse_header2").is_ok());
        assert!(validate("_x").is_ok());
        assert!(validate("").is_err());
        assert!(validate("2fast").is_err());
        assert!(validate("has space").unwrap_err().0.contains("' '"));
        assert!(validate("a-b").is_err());
    }

    #[test]
    fn set_get_clear_round_trip_through_the_annotation_file() {
        let dir = std::env::temp_dir().join(format!("biara-names-{}", std::process::id()));
        let mut n = in_dir(&dir);
        let v0 = n.version();
        assert_eq!(n.set(0x401000, NameKind::Function, "main_loop"), Ok(None));
        assert_eq!(n.set(0x404010, NameKind::Data, "config"), Ok(None));
        assert!(n.version() > v0);
        assert_eq!(n.get(0x401000), Some("main_loop"));

        // The file is the CLI's annotation format, with functions and globals apart.
        let text = std::fs::read_to_string(n.path().unwrap()).unwrap();
        let parsed: Annotations = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed.functions[&0x401000].name.as_deref(),
            Some("main_loop")
        );
        assert_eq!(parsed.globals[&0x404010], "config");

        // A fresh load sees the same names; clearing removes them from the file.
        let mut again = in_dir(&dir);
        again.functions = parsed
            .functions
            .into_iter()
            .filter_map(|(a, f)| Some((a, f.name?)))
            .collect();
        assert_eq!(again.get(0x401000), Some("main_loop"));
        n.set(0x401000, NameKind::Function, "").unwrap();
        assert_eq!(n.get(0x401000), None);
        let parsed: Annotations =
            serde_json::from_str(&std::fs::read_to_string(n.path().unwrap()).unwrap()).unwrap();
        assert!(parsed.functions.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_names_change_nothing() {
        let mut n = Names::in_memory();
        let v = n.version();
        assert!(n.set(0x10, NameKind::Function, "not valid").is_err());
        assert_eq!((n.version(), n.get(0x10)), (v, None));
    }
}
