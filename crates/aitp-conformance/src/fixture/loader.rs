//! Walks a fixtures directory and parses each JSON file.

use crate::fixture::Fixture;
use std::path::Path;

/// Loads fixtures from a directory.
pub struct FixtureLoader;

impl FixtureLoader {
    /// Load all `*.json` fixtures under `dir` (non-recursive), returning
    /// them sorted by `id`. Errors out on the first malformed fixture.
    pub fn load_dir(dir: &Path) -> Result<Vec<Fixture>, std::io::Error> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let fixture: Fixture = serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {}", path.display(), e),
                )
            })?;
            out.push(fixture);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}
