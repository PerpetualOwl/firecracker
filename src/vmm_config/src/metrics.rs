// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::open_file_nonblock; // open_file_nonblock is in lib.rs of this crate
// use vmm::logger::{FcLineWriter, METRICS}; // Will use local stubs

// --- Start of local stubs for vmm::logger types ---
use std::fs::File;
// use std::io::Write; // This import is unused in the stub
use std::sync::Mutex;

/// Placeholder for `vmm::logger::FcLineWriter`
pub struct FcLineWriter {
    // Using a simple File for the stub, the actual implementation might be more complex
    _file: Mutex<File>,
}

impl FcLineWriter {
    /// Creates a new `FcLineWriter`.
    pub fn new(file: File) -> Self {
        Self { _file: Mutex::new(file) }
    }

    // Add a dummy write method if needed by METRICS.init or other usages
    #[allow(dead_code)]
    fn write_line(&self, _line: &str) -> std::io::Result<()> {
        // In a real scenario, this would write to the self.file
        Ok(())
    }
}

/// Placeholder for `vmm::logger::Metrics`
pub struct Metrics;

impl Metrics {
    /// Placeholder for `init` method.
    pub fn init(&self, _writer: FcLineWriter) -> Result<(), String> {
        // In a real scenario, this would initialize the metrics system.
        // For the stub, we'll just return Ok.
        Ok(())
    }
}

/// Placeholder for the global `METRICS` instance.
#[allow(non_upper_case_globals)]
pub static METRICS: Metrics = Metrics;

// --- End of local stubs ---

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
}

/// Errors associated with actions on the `MetricsConfig`.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MetricsConfigError {
    /// Cannot initialize the metrics system due to bad user input: {0}
    InitializationFailure(String),
}

/// Configures the metrics as described in `metrics_cfg`.
pub fn init_metrics(metrics_cfg: MetricsConfig) -> Result<(), MetricsConfigError> {
    let writer = FcLineWriter::new(
        open_file_nonblock(&metrics_cfg.metrics_path)
            .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))?,
    );
    METRICS
        .init(writer)
        .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_init_metrics() {
        // Error case: initializing metrics with invalid pipe returns error.
        let desc = MetricsConfig {
            metrics_path: PathBuf::from("not_found_file_metrics"),
        };
        init_metrics(desc).unwrap_err();

        // Initializing metrics with valid pipe is ok.
        let metrics_file = TempFile::new().unwrap();
        let desc = MetricsConfig {
            metrics_path: metrics_file.as_path().to_path_buf(),
        };

        init_metrics(desc.clone()).unwrap();
        init_metrics(desc).unwrap_err();
    }
}