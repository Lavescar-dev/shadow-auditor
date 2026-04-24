//! Filesystem cache for OSV.dev responses (24h TTL).

use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::CveError;

pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub cached_at: DateTime<Utc>,
    pub value: T,
}

pub fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("shaudit/cve"))
}

pub fn read<T: for<'de> Deserialize<'de>>(name: &str, ttl_secs: u64) -> Option<T> {
    let dir = cache_dir()?;
    let path = dir.join(name);
    let data = std::fs::read_to_string(&path).ok()?;
    let entry: CacheEntry<T> = serde_json::from_str(&data).ok()?;
    let age = (Utc::now() - entry.cached_at).num_seconds().max(0) as u64;
    if age > ttl_secs {
        return None;
    }
    Some(entry.value)
}

pub fn write<T: Serialize>(name: &str, value: &T) -> Result<(), CveError> {
    let Some(dir) = cache_dir() else {
        return Ok(()); // silently skip if no cache dir
    };
    std::fs::create_dir_all(&dir).map_err(CveError::Io)?;
    let entry = CacheEntry {
        cached_at: SystemTime::now().into(),
        value,
    };
    let json = serde_json::to_string(&entry).map_err(|e| CveError::Parse(e.to_string()))?;
    std::fs::write(dir.join(name), json).map_err(CveError::Io)?;
    Ok(())
}
