//! Source-build contracts for the independently compiled Upgrade candidate fixture.
#![cfg(unix)]

use std::{fs, path::PathBuf, process::Command};

// The installed lifecycle suite separately exercises the canonical entrypoint.
#[allow(dead_code)]
#[path = "support/upgrade_candidate.rs"]
mod candidate;
use candidate::{checked, prepare_in};

#[path = "support/native_binary.rs"]
mod native_binary;
// Canonical entrypoint is exercised by the installed archive lifecycle suite.
#[allow(dead_code)]
#[path = "support/archive_binary.rs"]
mod archive;

#[path = "support/upgrade_candidate_tests.rs"]
mod tests;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
