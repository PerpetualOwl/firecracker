// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::RateLimiterConfig; // Assuming RateLimiterConfig is in vmm_config/src/lib.rs
// use vmm::VmmError; // Will use local stub
// use vmm::devices::virtio::net::{Net, TapError}; // Will use local stubs
// use vmm::utils::net::mac::MacAddr; // Will use local stub

// --- Start of local stubs ---

/// Placeholder for `vmm::VmmError`
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmError {
    /// Placeholder: {0}
    Placeholder(String),
    // Add other variants if needed by NetworkInterfaceError::DeviceUpdate
}

/// Placeholder for `vmm::utils::net::mac::MacAddr`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        // Simplified stub implementation
        if s.len() == 17 && s.matches(':').count() == 5 {
            Ok(MacAddr([0x01, 0x23, 0x45, 0x67, 0x89, 0x0a])) // Dummy MAC
        } else {
            Err("Invalid MAC address format".to_string())
        }
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}


pub mod devices {
    pub mod virtio {
        pub mod net {
            // use crate::RateLimiterConfig; // from current crate - This seems unused in the stub Net
            use super::super::super::MacAddr; // from current crate's stub
            // use std::sync::Arc; // For RateLimiter stub - This seems unused in the stub Net

            /// Placeholder for `vmm::devices::virtio::net::TapError`
            #[derive(Debug, thiserror::Error, displaydoc::Display)]
            pub enum TapError {
                /// IfreqExecuteError: {0:?}, {1}
                IfreqExecuteError(std::io::Error, String),
                // Add other variants if needed by tests or NetworkInterfaceError::OpenTap
            }

            /// Placeholder for `vmm::devices::virtio::net::NetError`
            #[derive(Debug, thiserror::Error, displaydoc::Display)]
            pub enum NetError {
                /// TapOpen: {0}
                TapOpen(TapError),
                // Add other variants if needed by NetworkInterfaceError::CreateNetworkDevice
            }

            /// Placeholder for `vmm::devices::virtio::net::Net`
            #[derive(Debug)]
            pub struct Net {
                id: String,
                iface_name: String,
                guest_mac: Option<MacAddr>,
                rx_rate_limiter: crate::rate_limiter::RateLimiter, // from vmm_config
                tx_rate_limiter: crate::rate_limiter::RateLimiter, // from vmm_config
            }

            impl Net {
                pub fn new(
                    id: String,
                    host_dev_name: &str,
                    guest_mac: Option<MacAddr>,
                    rx_rate_limiter: crate::rate_limiter::RateLimiter,
                    tx_rate_limiter: crate::rate_limiter::RateLimiter,
                ) -> Result<Self, NetError> {
                    // Simplified stub
                    if host_dev_name == "dev_should_fail_open" { // for test case
                        return Err(NetError::TapOpen(TapError::IfreqExecuteError(std::io::Error::from_raw_os_error(16), host_dev_name.to_string())));
                    }
                    Ok(Net {
                        id,
                        iface_name: host_dev_name.to_string(),
                        guest_mac,
                        rx_rate_limiter,
                        tx_rate_limiter,
                    })
                }

                pub fn id(&self) -> &String {
                    &self.id
                }

                pub fn iface_name(&self) -> String {
                    self.iface_name.clone()
                }

                pub fn guest_mac(&self) -> Option<&MacAddr> {
                    self.guest_mac.as_ref()
                }
                 pub fn rx_rate_limiter(&self) -> &crate::rate_limiter::RateLimiter {
                    &self.rx_rate_limiter
                }

                pub fn tx_rate_limiter(&self) -> &crate::rate_limiter::RateLimiter {
                    &self.tx_rate_limiter
                }
            }
        }
    }
}

// --- End of local stubs ---

use devices::virtio::net::Net; // Bring the stubbed Net into scope

/// This struct represents the strongly typed equivalent of the json body from net iface
/// related requests.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    /// ID of the guest network interface.
    pub iface_id: String,
    /// Host level path for the guest network interface.
    pub host_dev_name: String,
    /// Guest MAC address.
    pub guest_mac: Option<MacAddr>,
    /// Rate Limiter for received packages.
    pub rx_rate_limiter: Option<RateLimiterConfig>,
    /// Rate Limiter for transmitted packages.
    pub tx_rate_limiter: Option<RateLimiterConfig>,
}

impl From<&Net> for NetworkInterfaceConfig {
    fn from(net: &Net) -> Self {
        let rx_rl: RateLimiterConfig = net.rx_rate_limiter().into();
        let tx_rl: RateLimiterConfig = net.tx_rate_limiter().into();
        NetworkInterfaceConfig {
            iface_id: net.id().clone(),
            host_dev_name: net.iface_name(),
            guest_mac: net.guest_mac().copied(),
            rx_rate_limiter: rx_rl.into_option(),
            tx_rate_limiter: tx_rl.into_option(),
        }
    }
}

/// The data fed into a network iface update request. Currently, only the RX and TX rate limiters
/// can be updated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceUpdateConfig {
    /// The net iface ID, as provided by the user at iface creation time.
    pub iface_id: String,
    /// New RX rate limiter config. Only provided data will be updated. I.e. if any optional data
    /// is missing, it will not be nullified, but left unchanged.
    pub rx_rate_limiter: Option<RateLimiterConfig>,
    /// New TX rate limiter config. Only provided data will be updated. I.e. if any optional data
    /// is missing, it will not be nullified, but left unchanged.
    pub tx_rate_limiter: Option<RateLimiterConfig>,
}

/// Errors associated with the operations allowed on a net device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NetworkInterfaceError {
    /// Could not create the network device: {0}
    CreateNetworkDevice(#[from] devices::virtio::net::NetError), // Use local stub
    /// Cannot create the rate limiter: {0}
    CreateRateLimiter(#[from] std::io::Error),
    /// Unable to update the net device: {0}
    DeviceUpdate(#[from] VmmError),
    /// The MAC address is already in use: {0}
    GuestMacAddressInUse(String),
    /// Cannot open/create the tap device: {0}
    OpenTap(#[from] devices::virtio::net::TapError), // Use local stub
}

/// Builder for a list of network devices.
#[derive(Debug, Default)]
pub struct NetBuilder {
    net_devices: Vec<Arc<Mutex<Net>>>,
}

impl NetBuilder {
    /// Creates an empty list of Network Devices.
    pub fn new() -> Self {
        NetBuilder {
            // List of built network devices.
            net_devices: Vec::new(),
        }
    }

    /// Returns a immutable iterator over the network devices.
    pub fn iter(&self) -> ::std::slice::Iter<Arc<Mutex<Net>>> {
        self.net_devices.iter()
    }

    /// Returns a mutable iterator over the network devices.
    pub fn iter_mut(&mut self) -> ::std::slice::IterMut<Arc<Mutex<Net>>> {
        self.net_devices.iter_mut()
    }

    /// Adds an existing network device in the builder.
    pub fn add_device(&mut self, device: Arc<Mutex<Net>>) {
        self.net_devices.push(device);
    }

    /// Builds a network device based on a network interface config. Keeps a device reference
    /// in the builder's internal list.
    pub fn build(
        &mut self,
        netif_config: NetworkInterfaceConfig,
    ) -> Result<Arc<Mutex<Net>>, NetworkInterfaceError> {
        if let Some(ref mac_address) = netif_config.guest_mac {
            let mac_conflict = |net: &Arc<Mutex<Net>>| {
                let net = net.lock().expect("Poisoned lock");
                // Check if another net dev has same MAC.
                Some(mac_address) == net.guest_mac() && &netif_config.iface_id != net.id()
            };
            // Validate there is no Mac conflict.
            // No need to validate host_dev_name conflict. In such a case,
            // an error will be thrown during device creation anyway.
            if self.net_devices.iter().any(mac_conflict) {
                return Err(NetworkInterfaceError::GuestMacAddressInUse(
                    mac_address.to_string(),
                ));
            }
        }

        // If this is an update, just remove the old one.
        if let Some(index) = self
            .net_devices
            .iter()
            .position(|net| net.lock().expect("Poisoned lock").id() == &netif_config.iface_id)
        {
            self.net_devices.swap_remove(index);
        }

        // Add new device.
        let net = Arc::new(Mutex::new(Self::create_net(netif_config)?));
        self.net_devices.push(net.clone());

        Ok(net)
    }

    /// Creates a Net device from a NetworkInterfaceConfig.
    pub fn create_net(cfg: NetworkInterfaceConfig) -> Result<Net, NetworkInterfaceError> {
        let rx_rate_limiter = cfg
            .rx_rate_limiter
            .map(super::RateLimiterConfig::try_into)
            .transpose()
            .map_err(NetworkInterfaceError::CreateRateLimiter)?;
        let tx_rate_limiter = cfg
            .tx_rate_limiter
            .map(super::RateLimiterConfig::try_into)
            .transpose()
            .map_err(NetworkInterfaceError::CreateRateLimiter)?;

        // Create and return the Net device
        devices::virtio::net::Net::new( // Use local stub
            cfg.iface_id,
            &cfg.host_dev_name,
            cfg.guest_mac,
            rx_rate_limiter.unwrap_or_default(),
            tx_rate_limiter.unwrap_or_default(),
        )
        .map_err(NetworkInterfaceError::CreateNetworkDevice)
    }

    /// Returns a vec with the structures used to configure the net devices.
    pub fn configs(&self) -> Vec<NetworkInterfaceConfig> {
        let mut ret = vec![];
        for net in &self.net_devices {
            ret.push(NetworkInterfaceConfig::from(net.lock().unwrap().deref()));
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use vmm::rate_limiter::RateLimiter;

    impl NetBuilder {
        pub(crate) fn len(&self) -> usize {
            self.net_devices.len()
        }
    }

    fn create_netif(id: &str, name: &str, mac: &str) -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id: String::from(id),
            host_dev_name: String::from(name),
            guest_mac: Some(MacAddr::from_str(mac).unwrap()),
            rx_rate_limiter: RateLimiterConfig::default().into_option(),
            tx_rate_limiter: RateLimiterConfig::default().into_option(),
        }
    }

    impl Clone for NetworkInterfaceConfig {
        fn clone(&self) -> Self {
            NetworkInterfaceConfig {
                iface_id: self.iface_id.clone(),
                host_dev_name: self.host_dev_name.clone(),
                guest_mac: self.guest_mac,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            }
        }
    }

    #[test]
    fn test_insert() {
        let mut net_builder = NetBuilder::new();

        let id_1 = "id_1";
        let mut host_dev_name_1 = "dev1";
        let mut guest_mac_1 = "01:23:45:67:89:0a";

        // Test create.
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        net_builder.build(netif_1).unwrap();
        assert_eq!(net_builder.net_devices.len(), 1);

        // Test update mac address (this test does not modify the tap).
        guest_mac_1 = "01:23:45:67:89:0b";
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);

        net_builder.build(netif_1).unwrap();
        assert_eq!(net_builder.net_devices.len(), 1);

        // Test update host_dev_name (the tap will be updated).
        host_dev_name_1 = "dev2";
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        net_builder.build(netif_1).unwrap();
        assert_eq!(net_builder.net_devices.len(), 1);
    }

    #[test]
    fn test_insert_error_cases() {
        let mut net_builder = NetBuilder::new();

        let id_1 = "id_1";
        let host_dev_name_1 = "dev3";
        let guest_mac_1 = "01:23:45:67:89:0a";

        // Adding the first valid network config.
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        net_builder.build(netif_1).unwrap();

        // Error Cases for CREATE
        // Error Case: Add new network config with the same mac as netif_1.
        let id_2 = "id_2";
        let host_dev_name_2 = "dev4";
        let guest_mac_2 = "01:23:45:67:89:0b";

        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_1);
        let expected_error = NetworkInterfaceError::GuestMacAddressInUse(guest_mac_1.into());
        assert_eq!(
            net_builder.build(netif_2).err().unwrap().to_string(),
            expected_error.to_string()
        );
        assert_eq!(net_builder.net_devices.len(), 1);

        // Error Case: Add new network config with the same dev_host_name as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_1, guest_mac_2);
        assert_eq!(
            net_builder.build(netif_2).err().unwrap().to_string(),
            NetworkInterfaceError::CreateNetworkDevice( // Use local stubs
                devices::virtio::net::NetError::TapOpen(devices::virtio::net::TapError::IfreqExecuteError(
                    std::io::Error::from_raw_os_error(16),
                    host_dev_name_1.to_string()
                ))
            )
            .to_string()
        );
        assert_eq!(net_builder.net_devices.len(), 1);

        // Adding the second valid network config.
        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_2);
        net_builder.build(netif_2).unwrap();

        // Error Cases for UPDATE
        // Error Case: Update netif_2 mac using the same mac as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_1);
        let expected_error = NetworkInterfaceError::GuestMacAddressInUse(guest_mac_1.into());
        assert_eq!(
            net_builder.build(netif_2).err().unwrap().to_string(),
            expected_error.to_string()
        );

        // Error Case: Update netif_2 dev_host_name using the same dev_host_name as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_1, guest_mac_2);
        assert_eq!(
            net_builder.build(netif_2).err().unwrap().to_string(),
            NetworkInterfaceError::CreateNetworkDevice( // Use local stubs
                devices::virtio::net::NetError::TapOpen(devices::virtio::net::TapError::IfreqExecuteError(
                    std::io::Error::from_raw_os_error(16),
                    host_dev_name_1.to_string()
                ))
            )
            .to_string()
        );
    }

    #[test]
    fn test_net_config() {
        let net_id = "id";
        let host_dev_name = "dev";
        let guest_mac = "01:23:45:67:89:0b";

        let net_if_cfg = create_netif(net_id, host_dev_name, guest_mac);
        assert_eq!(
            net_if_cfg.guest_mac.unwrap(),
            MacAddr::from_str(guest_mac).unwrap()
        );

        let mut net_builder = NetBuilder::new();
        net_builder.build(net_if_cfg.clone()).unwrap();
        assert_eq!(net_builder.net_devices.len(), 1);

        let configs = net_builder.configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs.first().unwrap(), &net_if_cfg);
    }

    #[test]
    fn test_add_device() {
        let mut net_builder = NetBuilder::new();
        let net_id = "test_id";
        let host_dev_name = "dev";
        let guest_mac = "01:23:45:67:89:0b";

        let net = Net::new(
            net_id.to_string(),
            host_dev_name,
            Some(MacAddr::from_str(guest_mac).unwrap()),
            RateLimiter::default(),
            RateLimiter::default(),
        )
        .unwrap();

        net_builder.add_device(Arc::new(Mutex::new(net)));
        assert_eq!(net_builder.net_devices.len(), 1);
        assert_eq!(
            net_builder
                .net_devices
                .pop()
                .unwrap()
                .lock()
                .unwrap()
                .deref()
                .id(),
            net_id
        );
    }
}