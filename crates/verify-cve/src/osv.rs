//! OSV.dev REST client (batch query) for Node/Python/Go ecosystems.
//!
//! Docs: <https://google.github.io/osv.dev/api/>
//! Endpoint: POST <https://api.osv.dev/v1/querybatch>

use std::path::Path;

use serde::{Deserialize, Serialize};
use shaudit_core::{Finding, Location, Severity};

use crate::lockfiles::Package;
use crate::{cache, CveError};

const ENDPOINT: &str = "https://api.osv.dev/v1/querybatch";
/// OSV.dev accepts up to 1000 queries per batch request.
const CHUNK_SIZE: usize = 500;

#[derive(Serialize)]
struct Query<'a> {
    package: PackageQuery<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct PackageQuery<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct Batch<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BatchResponse {
    #[serde(default)]
    pub results: Vec<VulnListOrEmpty>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum VulnListOrEmpty {
    WithVulns { vulns: Vec<VulnMinimal> },
    Empty {},
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VulnMinimal {
    pub id: String,
    #[serde(default)]
    pub modified: Option<String>,
}

/// Fetch vulnerability summaries for a list of packages, using cache.
pub async fn query_batch(
    packages: &[Package],
    ecosystem: &str,
    lockfile_path: &Path,
    ttl_secs: u64,
) -> Result<Vec<Finding>, CveError> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    // Cache key = ecosystem + hash of packages list.
    let cache_name = format!("{ecosystem}.json");
    let mut cached: std::collections::HashMap<String, Vec<VulnMinimal>> =
        cache::read(&cache_name, ttl_secs).unwrap_or_default();

    // Identify packages missing from cache.
    let mut to_query: Vec<&Package> = Vec::new();
    for p in packages {
        let key = format!("{}@{}", p.name, p.version);
        if !cached.contains_key(&key) {
            to_query.push(p);
        }
    }

    if !to_query.is_empty() {
        let fresh = fetch(&to_query, ecosystem).await?;
        for (i, pkg) in to_query.iter().enumerate() {
            let key = format!("{}@{}", pkg.name, pkg.version);
            let ids = fresh.get(i).cloned().unwrap_or_default();
            cached.insert(key, ids);
        }
        cache::write(&cache_name, &cached).ok();
    }

    let mut findings = Vec::new();
    for pkg in packages {
        let key = format!("{}@{}", pkg.name, pkg.version);
        let Some(vulns) = cached.get(&key) else {
            continue;
        };
        for vuln in vulns {
            findings.push(Finding {
                verifier_id: crate::ID.to_string(),
                rule_id: format!("cve.{}.{}", ecosystem.to_lowercase(), vuln.id),
                severity: Severity::High,
                message: format!("{} {}: see {}", pkg.name, pkg.version, vuln.id),
                location: Location {
                    path: lockfile_path.to_path_buf(),
                    start_line: 1,
                    start_col: 1,
                    end_line: 1,
                    end_col: 1,
                    snippet: Some(format!("{} {}", pkg.name, pkg.version)),
                },
                fix: None,
                provenance_score: None,
                metadata: serde_json::json!({
                    "advisory_id": vuln.id,
                    "package": pkg.name,
                    "version": pkg.version,
                    "ecosystem": ecosystem,
                    "source": "osv.dev",
                }),
            });
        }
    }
    Ok(findings)
}

async fn fetch(packages: &[&Package], ecosystem: &str) -> Result<Vec<Vec<VulnMinimal>>, CveError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| CveError::Network(e.to_string()))?;

    let mut results: Vec<Vec<VulnMinimal>> = Vec::with_capacity(packages.len());

    for chunk in packages.chunks(CHUNK_SIZE) {
        let queries: Vec<Query> = chunk
            .iter()
            .map(|p| Query {
                package: PackageQuery {
                    name: &p.name,
                    ecosystem,
                },
                version: &p.version,
            })
            .collect();
        let body = Batch { queries };

        let resp = client
            .post(ENDPOINT)
            .json(&body)
            .send()
            .await
            .map_err(|e| CveError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CveError::Network(format!(
                "osv.dev returned {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            )));
        }

        let parsed: BatchResponse = resp
            .json()
            .await
            .map_err(|e| CveError::Parse(format!("osv.dev: {e}")))?;

        for r in parsed.results {
            match r {
                VulnListOrEmpty::WithVulns { vulns } => results.push(vulns),
                VulnListOrEmpty::Empty {} => results.push(Vec::new()),
            }
        }
    }

    Ok(results)
}
