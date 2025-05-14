// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the configuration for virtio-crypto devices.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

// This import assumes VirtioCrypto is in vmm crate. This will cause a circular dependency.
// For now, I'll use a placeholder. This needs to be resolved by moving VirtioCrypto
// or using a trait if VirtioCrypto cannot be moved.
// use vmm::devices::virtio::crypto::VirtioCrypto;
#[derive(Debug)] // Added Debug derive
struct VirtioCrypto; // Placeholder

/// API Configuration for the virtio-crypto device.
/// Based on design_document.md:127-130
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioCryptoConfig {
    /// Unique identifier for the crypto device.
    pub crypto_id: String,
    /// Number of data virtqueues (minimal implementation likely supports only 1).
    #[serde(default = "default_num_data_queues")]
    pub num_data_queues: u32,
}

fn default_num_data_queues() -> u32 {
    1 // As per design_document.md:133
}

/// Builder for configuring virtio-crypto devices.
#[derive(Debug, Default, Clone)]
pub struct CryptoBuilder {
    pub configs: Vec<VirtioCryptoConfig>,
    pub devices: Vec<Arc<std::sync::Mutex<VirtioCrypto>>>,
}

impl CryptoBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, cfg: VirtioCryptoConfig) -> Result<(), CryptoConfigError> {
        if self.configs.iter().any(|c| c.crypto_id == cfg.crypto_id) {
            return Err(CryptoConfigError::InvalidCryptoConfiguration(format!(
                "Crypto device with ID {} already exists.",
                cfg.crypto_id
            )));
        }
        self.configs.push(cfg);
        Ok(())
    }

    pub fn add_device(&mut self, device: Arc<std::sync::Mutex<VirtioCrypto>>) {
        self.devices.push(device);
    }
    
    pub fn configs(&self) -> Vec<VirtioCryptoConfig> {
        self.configs.clone()
    }
}

// It's common to also have a specific error type for device configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CryptoConfigError {
    /// Invalid configuration for virtio-crypto device: {0}
    InvalidCryptoConfiguration(String),
}