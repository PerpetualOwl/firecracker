// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

// use vmm::mmds::data_store; // Will use local stubs
// use vmm::mmds::data_store::MmdsVersion; // Will use local stubs

// --- Start of local stubs for vmm::mmds::data_store types ---

/// Placeholder for `vmm::mmds::data_store::MmdsVersion`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum MmdsVersion {
    /// V1 is the legacy version of MMDS.
    #[default]
    V1,
    /// V2 is the latest version of MMDS.
    V2,
}

impl std::fmt::Display for MmdsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MmdsVersion::V1 => write!(f, "V1"),
            MmdsVersion::V2 => write!(f, "V2"),
        }
    }
}

/// Placeholder for `vmm::mmds::data_store` module and its `MmdsDatastoreError`
pub mod data_store {
    // use super::MmdsVersion; // This import is unused now as MmdsVersion is used directly in MmdsConfigError
    use serde::{Deserialize, Serialize};

    /// Placeholder for `vmm::mmds::data_store::MmdsDatastoreError`
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, thiserror::Error, displaydoc::Display)]
    pub enum MmdsDatastoreError {
        /// Placeholder: {0}
        Placeholder(String),
        // Add other variants if they are directly used by MmdsConfigError::MmdsVersion
        // For example, if MmdsVersion constructor in vmm could return an error.
        // For now, assuming MmdsVersion construction is infallible or errors are not directly propagated here.
    }
}
// --- End of local stubs ---

/// Keeps the MMDS configuration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MmdsConfig {
    /// MMDS version.
    #[serde(default)]
    pub version: MmdsVersion,
    /// Network interfaces that allow forwarding packets to MMDS.
    pub network_interfaces: Vec<String>,
    /// MMDS IPv4 configured address.
    pub ipv4_address: Option<Ipv4Addr>,
}

impl MmdsConfig {
    /// Returns the MMDS version configured.
    pub fn version(&self) -> MmdsVersion {
        self.version
    }

    /// Returns the network interfaces that accept MMDS requests.
    pub fn network_interfaces(&self) -> Vec<String> {
        self.network_interfaces.clone()
    }

    /// Returns the MMDS IPv4 address if one was configured.
    /// Otherwise returns None.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_address
    }
}

/// MMDS configuration related errors.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmdsConfigError {
    /// The list of network interface IDs that allow forwarding MMDS requests is empty.
    EmptyNetworkIfaceList,
    /// The MMDS IPv4 address is not link local.
    InvalidIpv4Addr,
    /// The list of network interface IDs provided contains at least one ID that does not correspond to any existing network interface.
    InvalidNetworkInterfaceId,
    /// The MMDS could not be configured to version {0}: {1}
    MmdsVersion(MmdsVersion, data_store::MmdsDatastoreError),
}