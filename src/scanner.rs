use std::{
    fs, io,
    path::{Path, PathBuf},
};

use walkdir::{DirEntry, WalkDir};

use crate::{
    report::{Finding, redact_line, risk_as_string},
    rules::FindingRule,
};

fn should_skip(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();

    entry.file_type().is_dir()
        && matches!(
            name.as_ref(),
            ".git" | "target" | "node_modules" | ".next" | "dist" | "build" | "vendor"
        )
}

fn looks_like_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
}

fn scan_file(
    path: &Path,
    root: &Path,
    rules: &[FindingRule],
) -> io::Result<Vec<Finding>> {
    let bytes = fs::read(path)?;

    if !looks_like_text(&bytes) {
        return Ok(Vec::new());
    }

    let contents = match String::from_utf8(bytes) {
        Ok(contents) => contents,
        Err(_) => return Ok(Vec::new()),
    };

    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let mut findings = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        for rule in rules {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
                    file: relative_path.clone(),
                    line: index + 1,
                    rule: rule.name.to_string(),
                    risk: risk_as_string(&rule.risk).to_string(),
                    preview: redact_line(line, &rule.pattern),
                    recommendation: rule.recommendation.to_string(),
                });
            }
        }
    }

    Ok(findings)
}

pub fn scan_repository(
    root: &Path,
    rules: &[FindingRule],
) -> io::Result<(usize, Vec<Finding>)> {
    let mut files_scanned = 0;
    let mut findings = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !should_skip(entry))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("Warning: {error}");
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path: PathBuf = entry.path().to_path_buf();

        match scan_file(&path, root, rules) {
            Ok(mut file_findings) => {
                files_scanned += 1;
                findings.append(&mut file_findings);
            }
            Err(error) => {
                eprintln!("Warning: could not scan {}: {error}", path.display());
            }
        }
    }

    Ok((files_scanned, findings))
}
