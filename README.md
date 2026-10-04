# rust-repo-sentinel

A local-first Rust repository analyzer for detecting risky configuration patterns.

## Overview

`rust-repo-sentinel` is a small command-line tool written in Rust that scans a local repository and reports potentially risky patterns such as:

- Secret-like assignments
- Private key material
- Debug configuration enabled in source files

The project is designed as a learning-focused systems and security tooling project.

It does not upload repository contents or findings to an external service.

## Why I built this

Repositories contain source code, configuration files, build artifacts, and other data that can introduce security or operational risks.

I wanted to explore how a small repository analysis tool could be built in Rust while learning:

- File-system traversal
- Pattern matching
- Ownership and borrowing
- Error handling with `Result`
- Structs and enums
- Modules
- JSON serialization
- Automated testing
- CI with GitHub Actions

## Architecture

```text
Command Line
     |
     v
Repository Scanner
     |
     +---- File traversal
     |
     +---- Text detection
     |
     +---- Detection rules
     |
     v
Findings
     |
     +---- Terminal output
     |
     +---- JSON output
