// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring virtio-pmem devices.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

// Assuming PmemConfigSpace is defined in super::device
use super::device::{PmemConfigSpace, PmemFileProperties, VirtioPmem};
use super::{PMEM_NUM_QUEUES, PMEM_QUEUE_SIZES, VirtioPmemError}; // Removed TYPE_PMEM from here
use crate::devices::virtio::TYPE_PMEM; // Added correct import for TYPE_PMEM
use crate::devices::virtio::device::{DeviceState, IrqTrigger};
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO; // PMEM uses this feature bit
use super::device::VIRTIO_PMEM_F_SHMEM_REGION;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;


/// Constructor arguments for `VirtioPmem::restore`.
#[derive(Clone)]
pub struct PmemConstructorArgs {
    /// Guest memory map.
    pub mem: GuestMemoryMmap,
}


/// Holds info about the pmem device. Gets saved in snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioPmemState {
    id: String,
    path_on_host: String,
    size_mib: u64,
    is_read_only: bool,
    use_dax: bool,
    virtio_state: VirtioDeviceState,
}

impl Persist<'_> for VirtioPmem {
    type State = VirtioPmemState;
    type ConstructorArgs = PmemConstructorArgs;
    type Error = VirtioPmemError;

    fn save(&self) -> Self::State {
        VirtioPmemState {
            id: self.id.clone(),
            path_on_host: self.pmem_file_properties.file_path.clone(),
            size_mib: self.pmem_file_properties.size / (1024 * 1024),
            is_read_only: self.read_only,
            use_dax: self.use_dax,
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Reconstruct PmemFileProperties.
        // Note: The actual file opening and mmaping (if DAX) happens during activate,
        // but we need the properties for config space and initial setup.
        // The `is_read_only` for PmemFileProperties::new comes from the persisted state.
        let pmem_file_properties = PmemFileProperties::new(
            state.path_on_host.clone(),
            state.is_read_only,
            state.size_mib,
        )?;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioPmemError::EventFd)?];

        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                TYPE_PMEM,
                PMEM_NUM_QUEUES,
                PMEM_QUEUE_SIZES[0], // Assuming all queues have the same max size for simplicity
            )
            .map_err(VirtioPmemError::Persist)?;

        let mut irq_trigger = IrqTrigger::new().map_err(VirtioPmemError::IrqTrigger)?;
        irq_trigger.irq_status = Arc::new(AtomicU32::new(state.virtio_state.interrupt_status));

        let avail_features = state.virtio_state.avail_features;
        let acked_features = state.virtio_state.acked_features;

        let device_state = if state.virtio_state.activated {
            // Activation, including mmap for DAX, will be re-done by the VMM
            // when the device is actually activated post-restore.
            // For now, mark as activated with the provided memory.
            DeviceState::Activated(constructor_args.mem)
        } else {
            DeviceState::Inactive
        };

        let config_space = PmemConfigSpace {
            usable_region_size: pmem_file_properties.size.to_le(),
            unusable_region_size: 0u64.to_le(),
        };

        Ok(VirtioPmem {
            avail_features,
            acked_features,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioPmemError::EventFd)?,
            queues,
            queue_evts,
            device_state,
            irq_trigger,
            id: state.id.clone(),
            read_only: state.is_read_only,
            use_dax: state.use_dax,
            pmem_file_properties,
            mmap_region: None, // mmap will be re-established on activate if DAX
            guest_mem_region_addr: None, // guest mapping re-established on activate
            // metrics: PmemMetricsPerDevice::alloc(state.id.clone()), // TODO
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice; // For common trait methods
    use crate::devices::virtio::test_utils::default_mem;
    use crate::snapshot::Snapshot;

    fn create_test_file(size_bytes: u64) -> TempFile {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(size_bytes).unwrap();
        f
    }

    #[test]
    fn test_pmem_persistence() {
        let size_mib = 16;
        let expected_size_bytes = size_mib * 1024 * 1024;
        let temp_file = create_test_file(expected_size_bytes);

        let config = VirtioPmemConfig {
            drive_id: "pmem_persist_test".to_string(),
            path_on_host: temp_file.as_path().to_str().unwrap().to_string(),
            size_mib,
            is_read_only: false,
            use_dax: true,
        };

        let mut pmem_dev = VirtioPmem::new(config.clone()).unwrap();
        let guest_mem_orig = default_mem();

        // Activate the device to set some internal state like acked_features
        pmem_dev.set_acked_features(pmem_dev.avail_features()); // Ack all available
        pmem_dev.activate(guest_mem_orig.clone()).unwrap();


        // Save the pmem device state.
        let mut snapshot_data = vec![0; 4096];
        Snapshot::serialize(&mut snapshot_data.as_mut_slice(), &pmem_dev.save()).unwrap();

        // Restore the pmem device.
        let guest_mem_restore = default_mem(); // Can be a new instance for testing restore
        let constructor_args = PmemConstructorArgs { mem: guest_mem_restore.clone() };
        let restored_pmem_dev = VirtioPmem::restore(
            constructor_args,
            &Snapshot::deserialize(&mut snapshot_data.as_slice()).unwrap(),
        )
        .unwrap();

        // Test that virtio specific fields are the same.
        assert_eq!(restored_pmem_dev.device_type(), TYPE_PMEM);
        assert_eq!(restored_pmem_dev.avail_features(), pmem_dev.avail_features());
        assert_eq!(restored_pmem_dev.acked_features(), pmem_dev.acked_features());
        assert_eq!(restored_pmem_dev.queues().len(), pmem_dev.queues().len());
        // Queue details might be tricky if not fully initialized, but count should match.
        // Interrupt status might be reset or needs careful handling in real restore.
        // For this test, it's based on VirtioDeviceState which captures it.
        assert_eq!(
            restored_pmem_dev.interrupt_status().load(Ordering::Relaxed),
            pmem_dev.interrupt_status().load(Ordering::Relaxed)
        );
        // is_activated() state is based on the snapshot.
        // The actual mmap and KVM mapping happens on *re-activation* by the VMM.
        assert_eq!(restored_pmem_dev.is_activated(), pmem_dev.is_activated());


        // Test that pmem specific fields are the same.
        assert_eq!(restored_pmem_dev.id, pmem_dev.id);
        assert_eq!(restored_pmem_dev.pmem_file_properties.file_path, pmem_dev.pmem_file_properties.file_path);
        assert_eq!(restored_pmem_dev.pmem_file_properties.size, pmem_dev.pmem_file_properties.size);
        assert_eq!(restored_pmem_dev.read_only, pmem_dev.read_only);
        assert_eq!(restored_pmem_dev.use_dax, pmem_dev.use_dax);

        // Config space should be correctly reconstructed
        assert_eq!(restored_pmem_dev.config_space.usable_region_size, pmem_dev.config_space.usable_region_size);
        assert_eq!(restored_pmem_dev.config_space.unusable_region_size, pmem_dev.config_space.unusable_region_size);

        // mmap_region should be None after restore, it's set up on activate.
        assert!(restored_pmem_dev.mmap_region.is_none());
        assert!(restored_pmem_dev.guest_mem_region_addr.is_none());
    }
}