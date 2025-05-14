// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the configuration for a virtio-pmem device.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
// use vmm::devices::virtio::pmem::device::VirtioPmem; // Will use local stub

// --- Start of local stub for vmm::devices::virtio::pmem::device::VirtioPmem ---
/// Placeholder for `vmm::devices::virtio::pmem::device::VirtioPmem`
#[derive(Debug)]
pub struct VirtioPmem {
    // Add fields if they are accessed by PmemBuilder or other parts of this crate.
    // For now, keeping it minimal.
    #[allow(dead_code)]
    id: String,
}

impl VirtioPmem {
    // Add a constructor or methods if PmemBuilder needs to create or interact with VirtioPmem instances.
    // For now, PmemBuilder only stores Arc<Mutex<VirtioPmem>> and doesn't seem to call methods on it
    // beyond what a generic MutexGuard would allow (which is nothing without fields/methods here).
    // The `add_device` method in PmemBuilder takes a pre-built device.
}
// --- End of local stub ---

/// Errors specific to pmem device configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemConfigError {
    /// The pmem drive ID `{0}` is already in use.
    DriveIdAlreadyExists(String),
    /// Invalid drive ID.
    InvalidDriveId,
    /// Path not set.
    PathNotSet,
    /// Size not set or zero.
    SizeNotSet,
}


/// Configuration for a virtio-pmem device, as received from the API.
/// Based on design_document.md section 3.2.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PmemDeviceConfig {
    /// Unique identifier for the pmem device.
    pub drive_id: String,
    /// Path to the backing file on the host.
    pub path_on_host: String,
    /// Size of the persistent memory region in MiB.
    pub size_mib: u64,
    /// Whether the device should be read-only.
    #[serde(default)]
    pub is_read_only: bool,
    /// Hint to enable DAX by negotiating the VIRTIO_PMEM_F_SHMEM_REGION feature.
    #[serde(default = "default_use_dax")]
    pub use_dax: bool,
}

fn default_use_dax() -> bool {
    true
}

impl PmemDeviceConfig {
    /// Validates the parameters of the pmem device configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.drive_id.is_empty() {
            return Err("The drive_id for a pmem device cannot be empty.".to_string());
        }
        if self.path_on_host.is_empty() {
            return Err("The path_on_host for a pmem device cannot be empty.".to_string());
        }
        if self.size_mib == 0 {
            return Err("The size_mib for a pmem device must be greater than 0.".to_string());
        }
        Ok(())
    }
}

/// Builder for configuring and attaching virtio-pmem devices.
#[derive(Debug, Default)]
pub struct PmemBuilder {
    pub(crate) devices: Vec<Arc<Mutex<VirtioPmem>>>,
    pub(crate) configs: Vec<PmemDeviceConfig>,
}

impl PmemBuilder {
    /// Creates a new `PmemBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new pmem device configuration.
    pub fn insert(&mut self, config: PmemDeviceConfig) -> Result<(), PmemConfigError> {
        if self.configs.iter().any(|c| c.drive_id == config.drive_id) {
            return Err(PmemConfigError::DriveIdAlreadyExists(config.drive_id));
        }
        config.validate().map_err(|_s| PmemConfigError::InvalidDriveId)?; // Simplified error mapping
        self.configs.push(config);
        Ok(())
    }
    
    /// Returns a vector of the pmem device configurations.
    pub fn configs(&self) -> Vec<PmemDeviceConfig> {
        self.configs.clone()
    }

    /// Adds a pre-built `VirtioPmem` device (used for snapshot restoration).
    pub fn add_device(&mut self, device: Arc<Mutex<VirtioPmem>>) {
        // During snapshot restore, we might not have the original config easily.
        // We could reconstruct it from the device if needed, or adjust how VmConfig is built.
        // For now, just add the device. The `configs` vec might be out of sync in this case.
        self.devices.push(device);
    }

    /// Returns an iterator over the built `VirtioPmem` devices.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Mutex<VirtioPmem>>> {
        self.devices.iter()
    }
}