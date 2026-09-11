//! Validity checks: run declarative predicates against the real world at recall time.

use crate::canon::blake3_hex;
use crate::types::{Check, CheckOutcome, CheckResult, Status};
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve a check path against the vault root. Absolute paths are used as-is.
pub fn resolve_path(root: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

pub fn file_blake3(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(blake3_hex(&bytes))
}

/// Run one check. Never panics; unexpected conditions become `Error` outcomes.
pub fn run_check(root: &Path, check: &Check, now: &chrono::DateTime<chrono::Utc>) -> CheckOutcome {
    match check {
        Check::FileExists { path } => {
            let p = resolve_path(root, path);
            if p.exists() {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail { reason: format!("file missing: {}", p.display()) }
            }
        }
        Check::FileHash { path, blake3 } => {
            let Some(expected) = blake3 else {
                return CheckOutcome::Error { reason: "no baseline hash recorded".into() };
            };
            let p = resolve_path(root, path);
            match file_blake3(&p) {
                Ok(actual) if &actual == expected => CheckOutcome::Pass,
                Ok(actual) => CheckOutcome::Fail {
                    reason: format!(
                        "file changed: {} (was {}.., now {}..)",
                        p.display(),
                        &expected[..expected.len().min(12)],
                        &actual[..actual.len().min(12)]
                    ),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    CheckOutcome::Fail { reason: format!("file missing: {}", p.display()) }
                }
                Err(e) => CheckOutcome::Error { reason: format!("cannot read {}: {e}", p.display()) },
            }
        }
        Check::SymbolInFile { path, symbol } => {
            let p = resolve_path(root, path);
            match fs::read_to_string(&p) {
                Ok(content) if content.contains(symbol.as_str()) => CheckOutcome::Pass,
                Ok(_) => CheckOutcome::Fail { reason: format!("symbol '{symbol}' not found in {}", p.display()) },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    CheckOutcome::Fail { reason: format!("file missing: {}", p.display()) }
                }
                Err(e) => CheckOutcome::Error { reason: format!("cannot read {}: {e}", p.display()) },
            }
        }
        Check::Ttl { expires } => match chrono::DateTime::parse_from_rfc3339(expires) {
            Ok(exp) => {
                if exp.with_timezone(&chrono::Utc) > *now {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail { reason: format!("expired at {expires}") }
                }
            }
            Err(e) => CheckOutcome::Error { reason: format!("bad ttl '{expires}': {e}") },
        },
    }
}

/// Run all checks of a memory and fold them into a status.
pub fn run_checks(root: &Path, checks: &[Check], now: &chrono::DateTime<chrono::Utc>) -> (Status, Vec<CheckResult>) {
    if checks.is_empty() {
        return (Status::Unverified, Vec::new());
    }
    let results: Vec<CheckResult> = checks
        .iter()
        .map(|c| CheckResult { check: c.clone(), outcome: run_check(root, c, now) })
        .collect();
    let status = fold_status(&results);
    (status, results)
}

pub fn fold_status(results: &[CheckResult]) -> Status {
    if results.is_empty() {
        return Status::Unverified;
    }
    let mut any_error = false;
    for r in results {
        match r.outcome {
            CheckOutcome::Fail { .. } => return Status::Stale,
            CheckOutcome::Error { .. } => any_error = true,
            CheckOutcome::Pass => {}
        }
    }
    if any_error { Status::Unverified } else { Status::Fresh }
}

/// Fill in baseline hashes for `FileHash` checks that omit them. Fails if the file is unreadable,
/// because a memory that cannot be verified at creation time should not claim to be verifiable.
pub fn bake_checks(root: &Path, checks: &mut [Check]) -> crate::error::Result<()> {
    for c in checks.iter_mut() {
        if let Check::FileHash { path, blake3 } = c
            && blake3.is_none()
        {
            let p = resolve_path(root, path);
            let h = file_blake3(&p).map_err(|e| {
                crate::error::Error::Invalid(format!("cannot hash {} for file_hash check: {e}", p.display()))
            })?;
            *blake3 = Some(h);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_hash_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, "one").unwrap();
        let mut checks = vec![Check::FileHash { path: "a.txt".into(), blake3: None }];
        bake_checks(dir.path(), &mut checks).unwrap();
        let now = chrono::Utc::now();
        assert_eq!(run_checks(dir.path(), &checks, &now).0, Status::Fresh);
        fs::write(&f, "two").unwrap();
        assert_eq!(run_checks(dir.path(), &checks, &now).0, Status::Stale);
        fs::remove_file(&f).unwrap();
        assert_eq!(run_checks(dir.path(), &checks, &now).0, Status::Stale);
    }

    #[test]
    fn ttl_and_symbol() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("s.rs"), "fn compile_ledger() {}").unwrap();
        let now = chrono::Utc::now();
        let ok = Check::SymbolInFile { path: "s.rs".into(), symbol: "compile_ledger".into() };
        let bad = Check::SymbolInFile { path: "s.rs".into(), symbol: "gone".into() };
        assert_eq!(run_check(dir.path(), &ok, &now), CheckOutcome::Pass);
        assert!(matches!(run_check(dir.path(), &bad, &now), CheckOutcome::Fail { .. }));
        let past = Check::Ttl { expires: "2000-01-01T00:00:00Z".into() };
        let future = Check::Ttl { expires: "2999-01-01T00:00:00Z".into() };
        assert!(matches!(run_check(dir.path(), &past, &now), CheckOutcome::Fail { .. }));
        assert_eq!(run_check(dir.path(), &future, &now), CheckOutcome::Pass);
        assert_eq!(run_checks(dir.path(), &[], &now).0, Status::Unverified);
    }
}
