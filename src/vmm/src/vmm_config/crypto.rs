// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the configuration for virtio-crypto devices.

// Re-export the VirtioCryptoConfig from the device module for now.
// If the API layer needs a different structure, this can be adapted.
pub use crate::devices::virtio::crypto::device::VirtioCryptoConfig;

// It's common to also have a specific error type for device configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CryptoConfigError {
    /// Invalid configuration for virtio-crypto device: {0}
    InvalidCryptoConfiguration(String),
}