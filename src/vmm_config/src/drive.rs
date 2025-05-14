// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io;

use serde::{Deserialize, Serialize};

use crate::RateLimiterConfig;

// Moved from vmm::devices::virtio::block::virtio::device
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    #[default]
    Sync,
}

// Moved from vmm::devices::virtio::block::mod
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum CacheType {
    /// Flushing mechanic not will be advertised to the guest driver
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

// Placeholder for vmm::devices::virtio::block::BlockError
// TODO: Define this properly, possibly by moving or re-defining its variants.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockError {
    /// Placeholder variant for BlockError: {0}
    Placeholder(String),
    // Add other variants as needed, e.g.:
    // VirtioBackend(VirtioBlockError),
    // VhostUserBackend(VhostUserBlockError),
}

// Placeholder for vmm::VmmError
// TODO: Define a more specific error type for vmm_config or a shared error module.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmErrorPlaceholder {
    /// Placeholder variant for VmmError: {0}
    Placeholder(String),
}


// The Block struct (live device) is not needed here.
// pub use vmm::devices::virtio::block::virtio::device::FileEngineType; // Defined locally
// use vmm::devices::virtio::block::{BlockError, CacheType}; // Defined locally or placeholder

/// Errors associated with the operations allowed on a drive.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DriveError {
    /// Unable to create the virtio block device: {0}
    CreateBlockDevice(BlockError), // Uses local placeholder BlockError
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Unable to patch the block device: {0} Please verify the request arguments.
    DeviceUpdate(VmmErrorPlaceholder), // Uses local placeholder VmmErrorPlaceholder
    /// A root block device already exists!
    RootBlockDeviceAlreadyAdded,
}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,

    // VirtioBlock specific fields
    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: Option<bool>,
    /// Path of the drive.
    pub path_on_host: Option<String>,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    // #[serde(default)]
    // #[serde(rename = "io_engine")]
    // pub file_engine_type: FileEngineType,
    #[serde(rename = "io_engine")]
    pub file_engine_type: Option<FileEngineType>,

    // VhostUserBlock specific fields
    /// Path to the vhost-user socket.
    pub socket: Option<String>,
}

/// Only provided fields will be updated. I.e. if any optional fields
/// are missing, they will not be updated.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceUpdateConfig {
    /// The drive ID, as provided by the user at creation time.
    pub drive_id: String,

    // VirtioBlock sepcific fields
    /// New block file path on the host. Only provided data will be updated.
    pub path_on_host: Option<String>,
    /// New rate limiter config.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Wrapper for the collection that holds all the Block Devices
#[derive(Debug, Default)]
pub struct BlockBuilder {
    /// The list of block devices.
    /// There can be at most one root block device and it would be the first in the list.
    // Root Device should be the first in the list whether or not PARTUUID is
    // specified in order to avoid bugs in case of switching from partuuid boot
    // scenarios to /dev/vda boot type.
    // pub devices: VecDeque<Arc<Mutex<Block>>>, // Block is a live device from vmm
    // TODO: BlockBuilder needs to be re-evaluated. It should likely store
    // BlockDeviceConfig instances or a similar config-only representation,
    // not live Block devices from the vmm crate.
    // For now, making it store configs to allow compilation.
    pub devices: VecDeque<BlockDeviceConfig>,
}

impl BlockBuilder {
    /// Constructor for BlockDevices. It initializes an empty LinkedList.
    pub fn new() -> Self {
        Self {
            devices: Default::default(),
        }
    }

    /// Specifies whether there is a root block device already present in the list.
    fn has_root_device(&self) -> bool {
        // If there is a root device, it would be at the top of the list.
        if let Some(block_config) = self.devices.front() {
            // block.lock().expect("Poisoned lock").root_device()
            block_config.is_root_device // Accessing config directly
        } else {
            false
        }
    }

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.devices
            .iter()
            // .position(|b| b.lock().expect("Poisoned lock").id().eq(drive_id))
            .position(|cfg| cfg.drive_id.eq(drive_id)) // Accessing config directly
    }

    /// Inserts an existing block device config.
    // pub fn add_virtio_device(&mut self, block_device: Arc<Mutex<Block>>) { // Original signature
    pub fn add_block_config(&mut self, config: BlockDeviceConfig) { // New signature with config
        // if block_device.lock().expect("Poisoned lock").root_device() {
        if config.is_root_device { // Accessing config directly
            self.devices.push_front(config);
        } else {
            self.devices.push_back(config);
        }
    }

    /// Inserts a `BlockDeviceConfig` in the block devices list.
    /// If a block with the same id already exists, it will overwrite it.
    /// Inserting a secondary root block device will fail.
    pub fn insert(&mut self, config: BlockDeviceConfig) -> Result<(), DriveError> {
        let position = self.get_index_of_drive_id(&config.drive_id);
        let has_root_device = self.has_root_device();
        let configured_as_root = config.is_root_device;

        // Don't allow adding a second root block device.
        // If the new device cfg is root and not an update to the existing root, fail fast.
        if configured_as_root && has_root_device && position != Some(0) {
            return Err(DriveError::RootBlockDeviceAlreadyAdded);
        }

        // let block_dev = Arc::new(Mutex::new(
        //     Block::new(config).map_err(DriveError::CreateBlockDevice)?, // Cannot create live Block here
        // ));
        // For now, just store the config. The actual device creation happens in vmm.
        let block_dev_config = config;


        // If the id of the drive already exists in the list, the operation is update/overwrite.
        match position {
            // New block device.
            None => {
                if configured_as_root {
                    self.devices.push_front(block_dev_config);
                } else {
                    self.devices.push_back(block_dev_config);
                }
            }
            // Update existing block device.
            Some(index) => {
                // Update the slot with the new block.
                self.devices[index] = block_dev_config;
                // Check if the root block device is being updated.
                if index != 0 && configured_as_root {
                    // Make sure the root device is on the first position.
                    self.devices.swap(0, index);
                }
            }
        }
        Ok(())
    }

    /// Returns a vec with the structures used to configure the devices.
    pub fn configs(&self) -> Vec<BlockDeviceConfig> {
        self.devices
            .iter()
            // .map(|b| b.lock().unwrap().config()) // Was for live Block device
            .map(|config| config.clone()) // Explicitly map and clone
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    // use vmm::devices::virtio::block::virtio::VirtioBlockError; // This would be local if BlockError was fully defined

    impl PartialEq for DriveError {
        fn eq(&self, other: &DriveError) -> bool {
            self.to_string() == other.to_string()
        }
    }

    #[test]
    fn test_create_block_devs() {
        let block_devs = BlockBuilder::new();
        assert_eq!(block_devs.devices.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let dummy_id = String::from("1");
        let dummy_block_device = BlockDeviceConfig {
            drive_id: dummy_id.clone(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Writeback,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(dummy_block_device.clone()).unwrap();

        assert!(!block_devs.has_root_device());
        assert_eq!(block_devs.devices.len(), 1);
        assert_eq!(block_devs.get_index_of_drive_id(&dummy_id), Some(0));

        let block = block_devs.devices[0].lock().unwrap();
        assert_eq!(block.id(), dummy_block_device.drive_id);
        assert_eq!(block.partuuid(), &dummy_block_device.partuuid);
        assert_eq!(block.read_only(), dummy_block_device.is_read_only.unwrap());
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();

        let dummy_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some(dummy_path),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(dummy_block_device.clone()).unwrap();

        assert!(block_devs.has_root_device());
        assert_eq!(block_devs.devices.len(), 1);
        let block = block_devs.devices[0].lock().unwrap();
        assert_eq!(block.id(), dummy_block_device.drive_id);
        assert_eq!(block.partuuid(), &dummy_block_device.partuuid);
        assert_eq!(block.read_only(), dummy_block_device.is_read_only.unwrap());
    }

    #[test]
    fn test_add_two_root_block_devs() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device_1 = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_1),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let root_block_device_2 = BlockDeviceConfig {
            drive_id: String::from("2"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_2),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root_block_device_1).unwrap();
        assert_eq!(
            block_devs.insert(root_block_device_2).unwrap_err(),
            DriveError::RootBlockDeviceAlreadyAdded
        );
    }

    #[test]
    // Test BlockDevicesConfigs::add when you first add the root device and then the other devices.
    fn test_add_root_block_device_first() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_1),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            drive_id: String::from("2"),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_2),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            drive_id: String::from("3"),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_3),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(dummy_block_dev_2.clone()).unwrap();
        block_devs.insert(dummy_block_dev_3.clone()).unwrap();
        block_devs.insert(root_block_device.clone()).unwrap();

        assert_eq!(block_devs.devices.len(), 3);

        let mut block_iter = block_devs.devices.iter();
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            root_block_device.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            dummy_block_dev_2.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            dummy_block_dev_3.drive_id
        );
    }

    #[test]
    // Test BlockDevicesConfigs::add when you add other devices first and then the root device.
    fn test_root_block_device_add_last() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_1),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_2 = BlockDeviceConfig {
            drive_id: String::from("2"),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_2),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_3 = TempFile::new().unwrap();
        let dummy_path_3 = dummy_file_3.as_path().to_str().unwrap().to_string();
        let dummy_block_dev_3 = BlockDeviceConfig {
            drive_id: String::from("3"),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_3),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(dummy_block_dev_2.clone()).unwrap();
        block_devs.insert(dummy_block_dev_3.clone()).unwrap();
        block_devs.insert(root_block_device.clone()).unwrap();

        assert_eq!(block_devs.devices.len(), 3);

        let mut block_iter = block_devs.devices.iter();
        // The root device should be first in the list no matter of the order in
        // which the devices were added.
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            root_block_device.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            dummy_block_dev_2.drive_id
        );
        assert_eq!(
            block_iter.next().unwrap().lock().unwrap().id(),
            dummy_block_dev_3.drive_id
        );
    }

    #[test]
    fn test_update() {
        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_path_1 = dummy_file_1.as_path().to_str().unwrap().to_string();
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_1.clone()),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_path_2 = dummy_file_2.as_path().to_str().unwrap().to_string();
        let mut dummy_block_device_2 = BlockDeviceConfig {
            drive_id: String::from("2"),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_2.clone()),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();

        // Add 2 block devices.
        block_devs.insert(root_block_device).unwrap();
        block_devs.insert(dummy_block_device_2.clone()).unwrap();

        // Get index zero.
        assert_eq!(
            block_devs.get_index_of_drive_id(&String::from("1")),
            Some(0)
        );

        // Get None.
        assert!(
            block_devs
                .get_index_of_drive_id(&String::from("foo"))
                .is_none()
        );

        // Test several update cases using dummy_block_device_2.
        // Validate `dummy_block_device_2` is already in the list
        assert!(
            block_devs
                .get_index_of_drive_id(&dummy_block_device_2.drive_id)
                .is_some()
        );
        // Update OK.
        dummy_block_device_2.is_read_only = Some(true);
        block_devs.insert(dummy_block_device_2.clone()).unwrap();

        let index = block_devs
            .get_index_of_drive_id(&dummy_block_device_2.drive_id)
            .unwrap();
        // Validate update was successful.
        assert!(block_devs.devices[index].lock().unwrap().read_only());

        // Update with invalid path.
        let dummy_path_3 = String::from("test_update_3");
        dummy_block_device_2.path_on_host = Some(dummy_path_3);
        assert!(matches!(
            block_devs.insert(dummy_block_device_2.clone()),
            Err(DriveError::CreateBlockDevice(BlockError::VirtioBackend(
                VirtioBlockError::BackingFile(_, _)
            )))
        ));

        // Update with 2 root block devices.
        dummy_block_device_2.path_on_host = Some(dummy_path_2.clone());
        dummy_block_device_2.is_root_device = true;
        assert_eq!(
            block_devs.insert(dummy_block_device_2),
            Err(DriveError::RootBlockDeviceAlreadyAdded)
        );

        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_1),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };
        // Switch roots and add a PARTUUID for the new one.
        let mut root_block_device_old = root_block_device;
        root_block_device_old.is_root_device = false;
        let root_block_device_new = BlockDeviceConfig {
            drive_id: String::from("2"),
            partuuid: Some("0eaa91a0-01".to_string()),
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(dummy_path_2),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        block_devs.insert(root_block_device_old).unwrap();
        let root_block_id = root_block_device_new.drive_id.clone();
        block_devs.insert(root_block_device_new).unwrap();
        assert!(block_devs.has_root_device());
        // Verify it's been moved to the first position.
        assert_eq!(block_devs.devices[0].lock().unwrap().id(), root_block_id);
    }

    #[test]
    fn test_block_config() {
        let dummy_file = TempFile::new().unwrap();

        let dummy_block_device = BlockDeviceConfig {
            drive_id: String::from("1"),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some(dummy_file.as_path().to_str().unwrap().to_string()),
            rate_limiter: None,
            file_engine_type: Some(FileEngineType::Sync),

            socket: None,
        };

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(dummy_block_device.clone()).unwrap();

        let configs = block_devs.configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs.first().unwrap(), &dummy_block_device);
    }

    #[test]
    fn test_add_device() {
        let mut block_devs = BlockBuilder::new();
        let backing_file = TempFile::new().unwrap();

        let block_id = "test_id";
        let config = BlockDeviceConfig {
            drive_id: block_id.to_string(),
            partuuid: None,
            is_root_device: true,
            cache_type: CacheType::default(),

            is_read_only: Some(true),
            path_on_host: Some(backing_file.as_path().to_str().unwrap().to_string()),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let block = Block::new(config).unwrap();

        block_devs.add_virtio_device(Arc::new(Mutex::new(block)));
        assert_eq!(block_devs.devices.len(), 1);
        assert_eq!(
            block_devs.devices.pop_back().unwrap().lock().unwrap().id(),
            block_id
        );
    }
}