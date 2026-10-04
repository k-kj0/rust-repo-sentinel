use std::{env, path::PathBuf, process};

use serde_json::to_string_pretty;

use crate::report::ScanReport;
use crate::rules::default_rules;
use crate::scanner::scan_repository;

mod report;
mod rules;
mod scanner;

fn print_usage() {
    println!(
        "rust-repo-sentinel\n\n\
         Usage:\n\
         cargo run -- <PATH> [--json]\n\n\
         Examples:\n\
         cargo run -- .\n\
         cargo run -- ../my-project\n\
         cargo run -- . --json"
    );
}

fn main() {
    let mut args = env::args().skip(1);

    let mut root = PathBuf::from(".");
    let mut json_output = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => {
                json_output = true;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            value if value.starts_with('-') => {
                eprintln!("Unknown option: {value}");
                process::exit(2);
            }
            value => {
                root = PathBuf::from(value);
            }
        }
    }

    if !root.exists() {
        eprintln!("Error: path does not exist: {}", root.display());
        process::exit(2);
    }

    if !root.is_dir() {
        eprintln!("Error: expected a directory: {}", root.display());
        process::exit(2);
    }

    let rules = default_rules();

    let (files_scanned, findings) = match scan_repository(&root, &rules) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Scan failed: {error}");
            process::exit(1);
        }
    };

    let report = ScanReport {
        files_scanned,
        findings,
    };

    if json_output {
        println!("{}", to_string_pretty(&report).expect("report should serialize"));
        return;
    }

    println!("rust-repo-sentinel");
    println!("------------------");
    println!("Files scanned: {}", report.files_scanned);
    println!("Findings:      {}", report.findings.len());
    println!();

    if report.findings.is_empty() {
        println!("No findings.");
        return;
    }

    for finding in &report.findings {
        println!("[{}] {}:{}", finding.risk, finding.file, finding.line);
        println!("Rule: {}", finding.rule);
        println!("Preview: {}", finding.preview);
        println!("Action: {}", finding.recommendation);
        println!();
    }
}
