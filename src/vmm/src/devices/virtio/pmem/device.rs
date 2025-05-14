// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::os::unix::io::AsRawFd; // For mmap

use serde::{Deserialize, Serialize};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryError, MmapRegion, bitmap::AtomicBitmap};
use vmm_sys_util::eventfd::EventFd;
use vm_memory::VolatileMemory; // For writing to descriptors
use crate::devices::virtio::queue::Descriptor; // For direct descriptor access

use super::request::{PmemRequest, VirtioPmemResp, VIRTIO_PMEM_RESP_OK, VIRTIO_PMEM_RESP_EIO, PmemReqType}; // Assuming PmemReqType enum
use super::{PMEM_NUM_QUEUES, PMEM_QUEUE_SIZES, VirtioPmemError};
// TODO: Define PmemDeviceMetrics
// use crate::devices::virtio::pmem::metrics::{PmemDeviceMetrics, PmemMetricsPerDevice};
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
// Virtio PMEM spec constants
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO; // PMEM also uses RO
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::ActivateError;
use crate::logger::{IncMetric, error, warn};
use crate::utils::u64_to_usize;
use vmm_config::pmem::PmemDeviceConfig;


// Virtio Device Type for PMEM
pub const TYPE_PMEM: u32 = 27;

// Feature bits for virtio-pmem
pub const VIRTIO_PMEM_F_SHMEM_REGION: u64 = 0; // Exposes pmem region as shared memory for DAX
// VIRTIO_BLK_F_FLUSH is also relevant for pmem's FLUSH command (feature bit 9)
pub const VIRTIO_PMEM_F_FLUSH: u64 = 9;


/// Helper object for setting up all `Pmem` fields derived from its backing file.
#[derive(Debug)]
pub struct PmemFileProperties {
    pub file_path: String,
    pub backing_file: File,
    pub size: u64, // Size of the backing file in bytes
    // mmap_region will be part of VirtioPmem struct directly to handle KVM mapping
}

impl PmemFileProperties {
    pub fn new(
        disk_image_path: String,
        is_read_only: bool,
        size_mib: u64, // Expected size from config
    ) -> Result<Self, VirtioPmemError> {
        // OpenOptions::create(true).truncate(true) ensures the file is created
        // if not present and always set to the exact expected_size_bytes (after set_len).
        // design_document.md:118 ("May create/truncate the host file")
        // design_document.md:205 ("Firecracker may create it and truncate it to the specified size_mib")
        let mut backing_file = OpenOptions::new()
            .read(true)
            .write(!is_read_only)
            .create(true) // Create if it doesn't exist.
            .truncate(true) // Truncate to 0 length if it exists, otherwise no effect on new file.
            .open(PathBuf::from(&disk_image_path))
            .map_err(|e| VirtioPmemError::BackingFile(e, disk_image_path.to_string()))?;

        let expected_size_bytes = size_mib * 1024 * 1024;

        // Set the file to the expected size.
        // This is necessary because truncate(true) makes it 0-length if it existed,
        // or creates it as an empty file.
        backing_file.set_len(expected_size_bytes)
            .map_err(|e| VirtioPmemError::BackingFile(
                e,
                format!("Failed to set_len to {} for {}", expected_size_bytes, disk_image_path))
            )?;

        // Seek back to the start of the file.
        // While mmap might not strictly require this for some operations,
        // it's good practice to ensure the file pointer is in a known state.
        backing_file.seek(SeekFrom::Start(0))
            .map_err(|e| VirtioPmemError::BackingFile(
                e,
                format!("Failed to seek to start for {}", disk_image_path))
            )?;

        Ok(Self {
            file_path: disk_image_path,
            backing_file,
            size: expected_size_bytes,
        })
    }
}

/// Configuration space for a virtio-pmem device.
/// See Virtio Spec 1.2, Section 5.10.6 Device configuration layout
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct PmemConfigSpace {
    /// The size of the pmem region that is usable by the driver, in bytes. (le64)
    pub usable_region_size: u64,
    /// The size of a pmem region that is not usable by the driver, in bytes. (le64)
    /// This is typically 0 for file-backed pmem.
    pub unusable_region_size: u64,
    // According to spec 1.2, these are the only fields for pmem config.
    // block_size and plugged_size were mentioned in design doc based on older spec?
    // For now, sticking to 1.2 spec.
    // pub block_size: u32, (le32) -> Not in 1.2 spec config space directly.
    // pub plugged_size: u64, (le64) -> Not in 1.2 spec config space directly.
}

// SAFETY: `PmemConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for PmemConfigSpace {}

// This local VirtioPmemConfig is no longer needed, as we'll use PmemDeviceConfig from vmm_config crate.
// /// Use this structure to set up the Pmem Device before booting the kernel.
// /// Based on API spec in design_document.md:103-109
// #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
// #[serde(deny_unknown_fields)]
// pub struct VirtioPmemConfig {
//     /// Unique identifier of the drive.
//     pub drive_id: String,
//     /// Path to the backing file on the host.
//     pub path_on_host: String,
//     /// Size of the persistent memory region in MiB.
//     pub size_mib: u64,
//     /// Whether the device should be read-only.
//     #[serde(default)]
//     pub is_read_only: bool,
//     /// Hint to enable DAX by negotiating the VIRTIO_PMEM_F_SHMEM_REGION feature.
//     #[serde(default = "default_use_dax")]
//     pub use_dax: bool,
// }
//
// fn default_use_dax() -> bool {
// true
// }


/// Virtio device for exposing persistent memory to the guest.
#[derive(Debug)]
pub struct VirtioPmem {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: PmemConfigSpace,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; PMEM_NUM_QUEUES], // PMEM has 1 queue
    pub device_state: DeviceState,
    pub irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub id: String,
    pub read_only: bool,
    pub use_dax: bool, // From config, influences feature negotiation

    // Host file and mmap properties.
    pub pmem_file_properties: PmemFileProperties,
    pub mmap_region: Option<MmapRegion>, // Holds the mmap if DAX is active
    pub guest_mem_region_addr: Option<GuestAddress>, // GPA for DAX mapping

    // TODO: Define and use PmemDeviceMetrics
    // pub metrics: Arc<PmemDeviceMetrics>,
}

impl VirtioPmem {
    pub fn new(config: PmemDeviceConfig) -> Result<VirtioPmem, VirtioPmemError> { // Changed config type
        let pmem_file_properties = PmemFileProperties::new(
            config.path_on_host.clone(),
            config.is_read_only,
            config.size_mib,
        )?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO; // VIRTIO_BLK_F_RO is bit 5
        }
        // VIRTIO_PMEM_F_FLUSH is bit 9 (same as VIRTIO_BLK_F_FLUSH)
        avail_features |= 1u64 << VIRTIO_PMEM_F_FLUSH;

        if config.use_dax {
            avail_features |= 1u64 << VIRTIO_PMEM_F_SHMEM_REGION;
        }

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioPmemError::EventFd)?];
        let queues = PMEM_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let region_size_bytes = config.size_mib * 1024 * 1024;
        let config_space = PmemConfigSpace {
            usable_region_size: region_size_bytes.to_le(),
            unusable_region_size: 0u64.to_le(), // Typically 0 for file-backed
        };

        Ok(VirtioPmem {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioPmemError::EventFd)?,
            queues,
            queue_evts,
            device_state: DeviceState::Inactive,
            irq_trigger: IrqTrigger::new().map_err(VirtioPmemError::IrqTrigger)?,
            id: config.drive_id.clone(),
            read_only: config.is_read_only,
            use_dax: config.use_dax,
            pmem_file_properties,
            mmap_region: None,
            guest_mem_region_addr: None,
            // metrics: PmemMetricsPerDevice::alloc(config.drive_id), // TODO
        })
    }

    pub fn config(&self) -> PmemDeviceConfig { // Changed return type
        PmemDeviceConfig { // Changed to construct PmemDeviceConfig
            drive_id: self.id.clone(),
            path_on_host: self.pmem_file_properties.file_path.clone(),
            size_mib: self.pmem_file_properties.size / (1024 * 1024),
            is_read_only: self.read_only,
            use_dax: self.use_dax,
        }
    }

    pub(crate) fn process_queue_event(&mut self) {
        // self.metrics.queue_event_count.inc(); // TODO
        if let Err(err) = self.queue_evts[0].read() {
            error!("Failed to get pmem queue event: {:?}", err);
            // self.metrics.event_fails.inc(); // TODO
        } else {
            self.process_virtio_queues();
        }
    }

    pub fn process_virtio_queues(&mut self) {
        self.process_queue(0);
    }

    fn add_used_descriptor(
        queue: &mut Queue,
        index: u16,
        len: u32,
        irq_trigger: &IrqTrigger,
        // block_metrics: &PmemDeviceMetrics, // TODO
    ) {
        queue.add_used(index, len).unwrap_or_else(|err| {
            error!("PMEM: Failed to add available descriptor head {}: {}", index, err)
        });

        if queue.prepare_kick() {
            irq_trigger.trigger_irq(IrqType::Vring).unwrap_or_else(|err| {
                error!("PMEM: Failed to trigger vring irq: {:?}", err);
                // block_metrics.event_fails.inc(); // TODO
            });
        }
    }

    pub fn process_queue(&mut self, queue_index: usize) {
        let mem = match self.device_state.mem() {
            Some(m) => m,
            None => {
                warn!("PMEM: Attempting to process queue on inactive device.");
                return;
            }
        };

        let queue = &mut self.queues[queue_index];
        let mut used_any_descriptors = false;

        while let Some(head) = queue.pop_or_enable_notification() {
            // self.metrics.remaining_reqs_count.add(queue.len().into()); // TODO

            // Assuming PmemRequest::parse returns Result<(PmemReqType, u16 /* req_desc_idx */, u16 /* status_desc_idx */), Error>
            // For simplicity, let's assume parse gives us the type and the status descriptor index directly.
            // The actual parsing logic in `request.rs` will be more involved.
            match PmemRequest::parse(mem, queue, head.index) {
                Ok((req_type, req_desc_idx, status_desc_idx)) => {
                    let mut response_status = VIRTIO_PMEM_RESP_OK;

                    match req_type {
                        PmemReqType::Flush => {
                            if self.has_feature(VIRTIO_PMEM_F_FLUSH) {
                                if let Some(ref region) = self.mmap_region {
                                    let res = unsafe {
                                        libc::msync(
                                            region.as_ptr() as *mut libc::c_void,
                                            region.size(),
                                            libc::MS_SYNC,
                                        )
                                    };
                                    if res == 0 {
                                        // warn!("PMEM: FLUSH successful (msync)."); // Too noisy for normal operation
                                        response_status = VIRTIO_PMEM_RESP_OK;
                                    } else {
                                        let err = std::io::Error::last_os_error();
                                        error!("PMEM: FLUSH failed (msync error: {:?}).", err);
                                        response_status = VIRTIO_PMEM_RESP_EIO;
                                    }
                                } else if self.use_dax {
                                    warn!("PMEM: FLUSH for DAX without VMM mmap_region. Guest responsible or KVM handles persistence.");
                                    // If KVM_SET_USER_MEMORY_REGION handles persistence for DAX, this is OK.
                                    // The spec implies FLUSH is still a valid command for the device.
                                    response_status = VIRTIO_PMEM_RESP_OK;
                                } else {
                                    error!("PMEM: FLUSH request but no mmap_region (non-DAX or DAX setup failed).");
                                    response_status = VIRTIO_PMEM_RESP_EIO;
                                }
                            } else {
                                warn!("PMEM: FLUSH request received, but VIRTIO_PMEM_F_FLUSH not negotiated.");
                                response_status = VIRTIO_PMEM_RESP_EIO; // Or OK if spec says to ignore? For now, EIO.
                            }
                        }
                        PmemReqType::Plug | PmemReqType::Unplug => {
                            // design_document.md:216: "minimal DAX implementation... VMM can treat PLUG and UNPLUG requests as no-ops"
                            warn!("PMEM: Received {:?} request, treating as no-op for minimal implementation.", req_type);
                            response_status = VIRTIO_PMEM_RESP_OK;
                        }
                        // Add other request types if any
                    }

                    // Prepare and write response
                    let pmem_resp = VirtioPmemResp { status: response_status.to_le() }; // Ensure little-endian
                    let resp_len = std::mem::size_of::<VirtioPmemResp>() as u32;

                    // Manually retrieve the descriptor using the index and queue's desc_table_ptr
                    if status_desc_idx < queue.actual_size() {
                        // SAFETY: status_desc_idx is within bounds.
                        let status_desc = unsafe { queue.desc_table_ptr.add(status_desc_idx as usize).read_volatile() };

                        if (status_desc.flags & crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE) != 0 && status_desc.len >= resp_len {
                            if let Ok(slice) = mem.get_slice(GuestAddress(status_desc.addr), resp_len as usize) {
                                slice.copy_from(pmem_resp.as_slice());
                            } else {
                                error!("PMEM: Failed to get slice for status descriptor {}", status_desc_idx);
                                break; // Stop processing this chain
                            }
                        } else {
                            error!("PMEM: Invalid or unsuitable status descriptor flags/len at index {}", status_desc_idx);
                            break; // Stop processing this chain
                        }
                    } else {
                        error!("PMEM: Status descriptor index {} out of bounds for queue size {}", status_desc_idx, queue.actual_size());
                        break; // Stop processing this chain
                    }
                    Self::add_used_descriptor(queue, req_desc_idx, resp_len, &self.irq_trigger);
                    used_any_descriptors = true;
                }
                Err(e) => {
                    error!("PMEM: Failed to parse request at head {}: {:?}", head.index, e);
                    // What to do with a malformed request?
                    // For now, we can't process it, so we might break or try to add it as an error.
                    // Adding with 0 len might be an option if we can identify the head.
                    // Self::add_used_descriptor(queue, head.index, 0, &self.irq_trigger);
                    // This could be risky if the descriptor chain is malformed.
                    break; // Stop processing queue for now
                }
            }
        }

        if used_any_descriptors && queue.prepare_kick() {
            self.irq_trigger.trigger_irq(IrqType::Vring).unwrap_or_else(|err| {
                error!("PMEM: Failed to trigger vring irq: {:?}", err);
                // self.metrics.event_fails.inc(); // TODO
            });
        } else if !used_any_descriptors {
            // self.metrics.no_avail_buffer.inc(); // TODO (if pop returned None initially)
            // Or, if loop ran but processed nothing due to errors, different metric.
        }
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        if !self.is_activated() {
            return;
        }
        // For pmem, if there's an mmap_region, ensure data is flushed to disk.
        if let Some(ref region) = self.mmap_region {
            let res = unsafe {
                libc::msync(
                    region.as_ptr() as *mut libc::c_void,
                    region.size(),
                    libc::MS_SYNC,
                )
            };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                error!("PMEM: msync failed during prepare_save: {:?}", err);
            }
        }
        // If not mmap'd by VMM (e.g. pure DAX with KVM handling), guest is responsible.
        // Or, could fsync the backing_file fd here as a fallback.
        // For now, relying on msync if mmap_region exists.
    }
}

impl VirtioDevice for VirtioPmem {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_PMEM
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let offset_usize = u64_to_usize(offset);

        if let Some(src_slice) = config_space_bytes.get(offset_usize..) {
            let len_to_copy = std::cmp::min(data.len(), src_slice.len());
            data[..len_to_copy].copy_from_slice(&src_slice[..len_to_copy]);
        } else {
            warn!("PMEM: Failed to read config space at offset {}", offset);
            // self.metrics.cfg_fails.inc(); // TODO
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Virtio-pmem config space is read-only by the driver.
        warn!(
            "PMEM: Guest attempted to write {} bytes to Pmem config space at offset {}, which is read-only.",
            data.len(),
            offset
        );
        // self.metrics.cfg_fails.inc(); // TODO
    }

    fn activate(&mut self, mem: GuestMemoryMmap<Option<AtomicBitmap>>) -> Result<(), ActivateError> {
        if self.is_activated() {
            warn!("PMEM: Device already activated.");
            return Ok(());
        }

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let event_idx = self.has_feature(VIRTIO_RING_F_EVENT_IDX.into());
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        // DAX / mmap setup if VIRTIO_PMEM_F_SHMEM_REGION is negotiated
        if self.use_dax && self.has_feature(VIRTIO_PMEM_F_SHMEM_REGION) {
            let prot = if self.read_only { libc::PROT_READ } else { libc::PROT_READ | libc::PROT_WRITE };
            let mmap_res = MmapRegion::build(
                Some(self.pmem_file_properties.backing_file.as_raw_fd()),
                self.pmem_file_properties.size.try_into().unwrap(),
                prot,
                libc::MAP_SHARED, // Essential for persistence and DAX
            );

            match mmap_res {
                Ok(region) => {
                    // Now, map this into guest physical address space using KVM_SET_USER_MEMORY_REGION
                    // This requires finding an available GPA range. Firecracker's VMM usually manages this.
                    // For now, this is a placeholder for the KVM interaction.
                    // The actual GPA needs to be communicated to the guest (e.g. via command line or a future ACPI/DT mechanism).
                    // The design doc (2.2, 4.2) mentions KVM_SET_USER_MEMORY_REGION.
                    // The VMM thread would typically handle this.
                    // We need to get a GuestAddress for this mapping.
                    // This part is complex and needs integration with VMM's memory management.
                    // For now, we store the MmapRegion and assume KVM mapping happens elsewhere or is deferred.
                    warn!("PMEM: DAX negotiated. Backing file mmap'd. KVM_SET_USER_MEMORY_REGION step needs VMM integration.");

                    // Placeholder for KVM_SET_USER_MEMORY_REGION logic (design_document.md:209, 458)
                    // This interaction typically happens in the VMM thread, which has access to the VmFd
                    // and the guest memory manager to allocate a suitable GuestAddress.
                    //
                    // 1. Obtain VmFd:
                    //    - This would likely be passed to the device or accessible via a VMM context.
                    //    - Example: `let vm_fd = vmm_context.vm_fd();`
                    //
                    // 2. Allocate Guest Physical Address (GPA):
                    //    - The VMM's memory manager needs to find/allocate a free region in the GPA space
                    //      of size `region.size()`.
                    //    - Example: `let allocated_gpa: GuestAddress = vmm_memory_manager.alloc_pmem_region(region.size())?;`
                    //    - This GPA also needs to be communicated to the guest (e.g., via kernel cmdline or future ACPI/DT).
                    //
                    // 3. Construct `kvm_userspace_memory_region`:
                    //    - Requires `kvm-bindings` crate.
                    //    - `use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_READONLY};` (or other flags)
                    //
                    //    let guest_phys_addr_val: u64 = allocated_gpa.raw_value();
                    //    let memory_size_val: u64 = region.size() as u64;
                    //    let userspace_addr_val: u64 = region.as_ptr() as u64;
                    //
                    //    // Determine flags. For DAX, the host mmap permissions (prot) should dictate writability.
                    //    // KVM_MEM_READONLY might be relevant if virtio read_only is true AND DAX is used,
                    //    // to prevent guest writes even if host mmap allowed it (though host mmap should be primary).
                    //    // For pmem, typically KVM_MEM_LOG_DIRTY_PAGES is not used unless tracking for migration.
                    //    let kvm_mem_flags = 0u32;
                    //    // if self.read_only { kvm_mem_flags |= KVM_MEM_READONLY; } // Check implications for DAX
                    //
                    //    let kvm_region = kvm_userspace_memory_region {
                    //        slot: vmm_memory_manager.get_next_pmem_kvm_slot()?, // Slot must be managed
                    //        flags: kvm_mem_flags,
                    //        guest_phys_addr: guest_phys_addr_val,
                    //        memory_size: memory_size_val,
                    //        userspace_addr: userspace_addr_val,
                    //    };
                    //
                    // 4. Call KVM_SET_USER_MEMORY_REGION ioctl:
                    //    - `use std::os::unix::io::AsRawFd;`
                    //    - `let ret = unsafe { libc::ioctl(vm_fd.as_raw_fd(), kvm_bindings::KVM_SET_USER_MEMORY_REGION(), &kvm_region) };`
                    //    - `if ret < 0 { error!("KVM_SET_USER_MEMORY_REGION failed: {}", std::io::Error::last_os_error()); return Err(ActivateError::BadActivate); }`
                    //
                    // 5. Store guest_mem_region_addr:
                    //    - `self.guest_mem_region_addr = Some(allocated_gpa);`
                    //
                    // warn!(
                    //    "PMEM: KVM_SET_USER_MEMORY_REGION placeholder: Slot={}, GPA=0x{:x}, Size=0x{:x}, HostAddr=0x{:x}",
                    //    kvm_region.slot, kvm_region.guest_phys_addr, kvm_region.memory_size, kvm_region.userspace_addr
                    // );
                    self.mmap_region = Some(region);
                    // self.guest_mem_region_addr = Some(determined_guest_address); // TODO: Set this after KVM mapping
                }
                Err(e) => {
                    error!("PMEM: Failed to mmap backing file for DAX: {:?}", e);
                    // self.metrics.activate_fails.inc(); // TODO
                    return Err(ActivateError::BadActivate); // Or a more specific error
                }
            }
        }


        if self.activate_evt.write(1).is_err() {
            // self.metrics.activate_fails.inc(); // TODO
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        // TODO: Perform any necessary cleanup, like unmapping if mmap_region is Some.
        if let Some(mmap_region) = self.mmap_region.take() {
            // MmapRegion handles unmap on drop, but explicit could be added if needed.
            warn!("PMEM: Resetting device, mmap_region was present.");
        }
        self.guest_mem_region_addr = None;
        // Call super::reset or equivalent if there's a common reset logic.
        // For now, just returning None as per original block device.
        None
    }
}

impl Drop for VirtioPmem {
    fn drop(&mut self) {
        // MmapRegion handles unmap on drop.
        // File handle in PmemFileProperties will be closed on drop.
        // Any other explicit cleanup can go here.
        if self.mmap_region.is_some() {
             warn!("PMEM: Dropping device with active mmap_region.");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::metadata;
    use std::io::{Read, Write};
    // use std::os::unix::ffi::OsStrExt; // Not used currently
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    // use crate::check_metric_after_block; // TODO: Adapt metrics
    // use crate::devices::virtio::pmem::virtio::IO_URING_NUM_ENTRIES; // Not applicable
    // use crate::devices::virtio::pmem::virtio::test_utils::{ // TODO: Adapt test_utils
    //     default_pmem, read_pmem_req_descriptors, set_queue,
    //     simulate_queue_event,
    // };
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_mem};
    use crate::vstate::memory::{Address, Bytes, GuestAddress};

    // Helper to setup a VirtQueue for request processing tests
    fn setup_vq_for_req_test(mem: &GuestMemoryMmap, vq: &mut VirtQueue, req_type: u32) -> (GuestAddress, GuestAddress) {
        let req_hdr_addr = GuestAddress(0x1000); // Use higher addresses to avoid overlap
        let status_addr = GuestAddress(0x1100);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Setup descriptors (req -> status)
        vq.avail.ring[0].set(0); // Put descriptor 0 in avail ring
        vq.avail.idx.set(1);     // Increment avail index
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1); // Req desc
        vq.dtable[1].set(status_addr.raw_value(), status_size, VIRTQ_DESC_F_WRITE, 0); // Status desc (writable)

        // Write request header
        let req = VirtioPmemReqHdr {
            type_: req_type.to_le(),
            ..Default::default()
        };
        mem.write_obj(req, req_hdr_addr).unwrap();

        (req_hdr_addr, status_addr)
    }

    // Helper to create a default VirtioPmemConfig for tests
    fn default_pmem_config(file_path: String, size_mib: u64) -> VirtioPmemConfig {
        VirtioPmemConfig {
            drive_id: "pmem_test_drive".to_string(),
            path_on_host: file_path,
            size_mib,
            is_read_only: false,
            use_dax: true,
        }
    }

    // Helper to create a default VirtioPmem device for tests
    fn default_pmem_device(config: VirtioPmemConfig) -> VirtioPmem {
        VirtioPmem::new(config).expect("Failed to create default VirtioPmem device")
    }

    #[test]
    fn test_pmem_file_properties() {
        let f = TempFile::new().unwrap();
        let file_path_str = f.as_path().to_str().unwrap().to_string();
        let size_mib = 16;
        let expected_size_bytes = size_mib * 1024 * 1024;
        f.as_file().set_len(expected_size_bytes).unwrap();

        let props = PmemFileProperties::new(file_path_str.clone(), false, size_mib).unwrap();
        assert_eq!(props.file_path, file_path_str);
        assert_eq!(props.size, expected_size_bytes);

        // Test file smaller than configured
        let f_small = TempFile::new().unwrap();
        let file_path_small_str = f_small.as_path().to_str().unwrap().to_string();
        f_small.as_file().set_len(expected_size_bytes / 2).unwrap();
        let props_small = PmemFileProperties::new(file_path_small_str.clone(), false, size_mib).unwrap();
        assert_eq!(props_small.size, expected_size_bytes); // Should have been truncated up

        // Test file larger than configured
        let f_large = TempFile::new().unwrap();
        let file_path_large_str = f_large.as_path().to_str().unwrap().to_string();
        f_large.as_file().set_len(expected_size_bytes * 2).unwrap();
        let props_large = PmemFileProperties::new(file_path_large_str.clone(), false, size_mib).unwrap();
        assert_eq!(props_large.size, expected_size_bytes); // Should use configured size

        let res_invalid_path = PmemFileProperties::new("invalid-pmem-path".to_string(), false, 1);
        assert!(matches!(res_invalid_path, Err(VirtioPmemError::BackingFile(_, _))));
    }

    #[test]
    fn test_virtio_pmem_features() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(16 * 1024 * 1024).unwrap();
        let config_ro_dax = VirtioPmemConfig {
            drive_id: "pmem0".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            size_mib: 16,
            is_read_only: true,
            use_dax: true,
        };
        let mut pmem_ro_dax = default_pmem_device(config_ro_dax);
        assert_eq!(pmem_ro_dax.device_type(), TYPE_PMEM);

        let mut expected_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            | (1u64 << VIRTIO_BLK_F_RO) // Bit 5
            | (1u64 << VIRTIO_PMEM_F_FLUSH) // Bit 9
            | (1u64 << VIRTIO_PMEM_F_SHMEM_REGION); // Bit 0
        assert_eq!(pmem_ro_dax.avail_features(), expected_features);

        assert_eq!(
            pmem_ro_dax.avail_features_by_page(0),
            (expected_features & 0xffffffff) as u32
        );
        assert_eq!(
            pmem_ro_dax.avail_features_by_page(1),
            (expected_features >> 32) as u32
        );
        for i in 2..10 {
            assert_eq!(pmem_ro_dax.avail_features_by_page(i), 0u32);
        }

        pmem_ro_dax.ack_features_by_page(0, u32::MAX);
        pmem_ro_dax.ack_features_by_page(1, u32::MAX);
        assert_eq!(pmem_ro_dax.acked_features(), expected_features);


        let config_rw_nodax = VirtioPmemConfig {
            drive_id: "pmem1".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            size_mib: 16,
            is_read_only: false,
            use_dax: false,
        };
        let pmem_rw_nodax = default_pmem_device(config_rw_nodax);
        expected_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            | (1u64 << VIRTIO_PMEM_F_FLUSH);
        assert_eq!(pmem_rw_nodax.avail_features(), expected_features);
    }

    #[test]
    fn test_virtio_pmem_read_config() {
        let f = TempFile::new().unwrap();
        let size_mib = 32;
        let expected_size_bytes = size_mib * 1024 * 1024;
        f.as_file().set_len(expected_size_bytes).unwrap();
        let config = default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib);
        let pmem = default_pmem_device(config);

        let mut actual_config_space_raw = [0u8; std::mem::size_of::<PmemConfigSpace>()];
        pmem.read_config(0, &mut actual_config_space_raw);
        
        let actual_config_space: PmemConfigSpace = unsafe { std::mem::transmute(actual_config_space_raw) };

        let expected_config_space = PmemConfigSpace {
            usable_region_size: expected_size_bytes.to_le(),
            unusable_region_size: 0u64.to_le(),
        };
        assert_eq!(actual_config_space.usable_region_size, expected_config_space.usable_region_size);
        assert_eq!(actual_config_space.unusable_region_size, expected_config_space.unusable_region_size);


        // Invalid read offset
        let mut data = [0u8; 8];
        pmem.read_config(std::mem::size_of::<PmemConfigSpace>() as u64 + 1, &mut data);
        // Should not panic, data should remain unchanged or be zeroed depending on get behavior.
        // For now, just checking no panic.
    }

    #[test]
    fn test_virtio_pmem_write_config() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(16 * 1024 * 1024).unwrap();
        let config = default_pmem_config(f.as_path().to_str().unwrap().to_string(), 16);
        let mut pmem = default_pmem_device(config);

        let data_to_write = [0xDE, 0xAD, 0xBE, 0xEF];
        // Write should be a no-op and log a warning.
        pmem.write_config(0, &data_to_write);

        let mut actual_config_space_raw = [0u8; std::mem::size_of::<PmemConfigSpace>()];
        pmem.read_config(0, &mut actual_config_space_raw);
        let actual_config_space: PmemConfigSpace = unsafe { std::mem::transmute(actual_config_space_raw) };

        // Ensure config space did not change to DEADBEEF
        assert_ne!(actual_config_space.usable_region_size, u64::from_le_bytes([0xDE, 0xAD, 0xBE, 0xEF,0,0,0,0]));
    }

    #[test]
    fn test_pmem_activate_dax() {
        let f = TempFile::new().unwrap();
        let size_mib = 8;
        let expected_size_bytes = size_mib * 1024 * 1024;
        f.as_file().set_len(expected_size_bytes).unwrap();
        let config = VirtioPmemConfig {
            drive_id: "pmem_dax".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            size_mib,
            is_read_only: false,
            use_dax: true,
        };
        let mut pmem = default_pmem_device(config);
        let mem = default_mem(); // Guest memory

        // Ack VIRTIO_PMEM_F_SHMEM_REGION
        pmem.set_acked_features(pmem.avail_features());
        assert!(pmem.has_feature(VIRTIO_PMEM_F_SHMEM_REGION));

        assert!(pmem.mmap_region.is_none());
        pmem.activate(mem.clone()).unwrap();
        assert!(pmem.is_activated());
        assert!(pmem.mmap_region.is_some());
        assert_eq!(pmem.mmap_region.as_ref().unwrap().size(), expected_size_bytes as usize);
        // TODO: Test KVM_SET_USER_MEMORY_REGION when VMM integration is available.
    }

    #[test]
    fn test_pmem_activate_no_dax() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(8 * 1024 * 1024).unwrap();
        let config = VirtioPmemConfig {
            drive_id: "pmem_nodax".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            size_mib: 8,
            is_read_only: false,
            use_dax: false, // Explicitly no DAX
        };
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();

        // Don't ack VIRTIO_PMEM_F_SHMEM_REGION even if available by default
        pmem.set_acked_features(pmem.avail_features() & !(1 << VIRTIO_PMEM_F_SHMEM_REGION));
        assert!(!pmem.has_feature(VIRTIO_PMEM_F_SHMEM_REGION));


        assert!(pmem.mmap_region.is_none());
        pmem.activate(mem.clone()).unwrap();
        assert!(pmem.is_activated());
        assert!(pmem.mmap_region.is_none()); // Should not mmap if SHMEM_REGION not negotiated
    }

    // TODO: Add tests for FLUSH request processing (mocking queue interactions)
    // TODO: Add tests for PLUG/UNPLUG (minimal no-op initially)
    // TODO: Add tests for persistence (save/restore) once persist.rs is adapted.

    #[test]
    fn test_pmem_process_flush_ok_mmap() {
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = VirtioPmemConfig { use_dax: true, ..default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib) };
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);

        // Activate device with DAX to get mmap_region
        pmem.set_acked_features(pmem.avail_features()); // Ack FLUSH and SHMEM_REGION
        assert!(pmem.has_feature(VIRTIO_PMEM_F_FLUSH));
        assert!(pmem.has_feature(VIRTIO_PMEM_F_SHMEM_REGION));
        pmem.activate(mem.clone()).unwrap();
        assert!(pmem.mmap_region.is_some());

        // Setup queue with FLUSH request
        let (_, status_addr) = setup_vq_for_req_test(&mem, &mut vq, VIRTIO_PMEM_REQ_TYPE_FLUSH);

        // Process queue
        pmem.process_queue(0);

        // Verify used descriptor and response
        assert_eq!(vq.used.idx.get(), 1); // One descriptor used
        assert_eq!(vq.used.ring[0].id.get(), 0); // Head index of the request chain
        assert_eq!(vq.used.ring[0].len.get(), std::mem::size_of::<VirtioPmemResp>() as u32);

        let resp: VirtioPmemResp = mem.read_obj(status_addr).unwrap();
        assert_eq!(u32::from_le(resp.status), VIRTIO_PMEM_RESP_OK);
    }

     #[test]
    fn test_pmem_process_flush_ok_dax_no_mmap() {
        // Simulate DAX case where VMM doesn't mmap (relies on KVM mapping)
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = VirtioPmemConfig { use_dax: true, ..default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib) };
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);

        // Activate device but manually remove mmap_region
        pmem.set_acked_features(pmem.avail_features()); // Ack FLUSH and SHMEM_REGION
        pmem.activate(mem.clone()).unwrap();
        pmem.mmap_region = None; // Simulate no VMM mmap
        assert!(pmem.use_dax);

        // Setup queue with FLUSH request
        let (_, status_addr) = setup_vq_for_req_test(&mem, &mut vq, VIRTIO_PMEM_REQ_TYPE_FLUSH);

        // Process queue
        pmem.process_queue(0);

        // Verify used descriptor and response (should be OK as per logic)
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].id.get(), 0);
        assert_eq!(vq.used.ring[0].len.get(), std::mem::size_of::<VirtioPmemResp>() as u32);
        let resp: VirtioPmemResp = mem.read_obj(status_addr).unwrap();
        assert_eq!(u32::from_le(resp.status), VIRTIO_PMEM_RESP_OK);
    }

    #[test]
    fn test_pmem_process_flush_feature_not_acked() {
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib);
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);

        // Activate device without acking FLUSH feature
        pmem.set_acked_features(pmem.avail_features() & !(1 << VIRTIO_PMEM_F_FLUSH));
        assert!(!pmem.has_feature(VIRTIO_PMEM_F_FLUSH));
        pmem.activate(mem.clone()).unwrap();

        // Setup queue with FLUSH request
        let (_, status_addr) = setup_vq_for_req_test(&mem, &mut vq, VIRTIO_PMEM_REQ_TYPE_FLUSH);

        // Process queue
        pmem.process_queue(0);

        // Verify used descriptor and response (should be EIO)
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].id.get(), 0);
        assert_eq!(vq.used.ring[0].len.get(), std::mem::size_of::<VirtioPmemResp>() as u32);
        let resp: VirtioPmemResp = mem.read_obj(status_addr).unwrap();
        assert_eq!(u32::from_le(resp.status), VIRTIO_PMEM_RESP_EIO);
    }

    #[test]
    fn test_pmem_process_plug_unplug_noop() {
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib);
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);

        pmem.activate(mem.clone()).unwrap();

        // Test PLUG
        let (_, status_addr_plug) = setup_vq_for_req_test(&mem, &mut vq, VIRTIO_PMEM_REQ_TYPE_PLUG);
        pmem.process_queue(0);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].id.get(), 0);
        let resp_plug: VirtioPmemResp = mem.read_obj(status_addr_plug).unwrap();
        assert_eq!(u32::from_le(resp_plug.status), VIRTIO_PMEM_RESP_OK);

        // Reset queue state for next request (simulate driver adding another)
        vq.used.idx.set(0); // Reset used index
        vq.avail.idx.set(1); // Make descriptor 0 available again

        // Test UNPLUG
        let (_, status_addr_unplug) = setup_vq_for_req_test(&mem, &mut vq, VIRTIO_PMEM_REQ_TYPE_UNPLUG);
        pmem.process_queue(0);
        assert_eq!(vq.used.idx.get(), 1); // Should have processed the second request
        assert_eq!(vq.used.ring[0].id.get(), 0);
        let resp_unplug: VirtioPmemResp = mem.read_obj(status_addr_unplug).unwrap();
        assert_eq!(u32::from_le(resp_unplug.status), VIRTIO_PMEM_RESP_OK);
    }

     #[test]
    fn test_pmem_process_queue_inactive() {
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib);
        let mut pmem = default_pmem_device(config);
        // Device is NOT activated

        // process_queue should be a no-op
        pmem.process_queue(0);
        assert_eq!(pmem.queues[0].used_idx(), 0); // No descriptors should be used
    }

    #[test]
    fn test_pmem_prepare_save() {
        let f = TempFile::new().unwrap();
        let size_mib = 4;
        f.as_file().set_len(size_mib * 1024 * 1024).unwrap();
        let config = VirtioPmemConfig { use_dax: true, ..default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib) };
        let mut pmem = default_pmem_device(config);
        let mem = default_mem();

        // Case 1: Not activated
        pmem.prepare_save(); // Should do nothing, no panic

        // Case 2: Activated without DAX (no mmap_region)
        pmem.set_acked_features(pmem.avail_features() & !(1 << VIRTIO_PMEM_F_SHMEM_REGION));
        pmem.activate(mem.clone()).unwrap();
        assert!(pmem.mmap_region.is_none());
        pmem.prepare_save(); // Should do nothing, no panic

        // Case 3: Activated with DAX (has mmap_region)
        let config_dax = VirtioPmemConfig { use_dax: true, ..default_pmem_config(f.as_path().to_str().unwrap().to_string(), size_mib) };
        let mut pmem_dax = default_pmem_device(config_dax);
        pmem_dax.set_acked_features(pmem_dax.avail_features());
        pmem_dax.activate(mem.clone()).unwrap();
        assert!(pmem_dax.mmap_region.is_some());
        // Write something to the mmap region to make it dirty (best effort)
        if let Some(ref region) = pmem_dax.mmap_region {
             let slice = unsafe { std::slice::from_raw_parts_mut(region.as_ptr() as *mut u8, region.size()) };
             slice[0] = 1;
        }
        pmem_dax.prepare_save(); // Should call msync, no panic expected
        // Verification that msync *actually* worked is hard in unit test,
        // but we check it doesn't panic and the logic path is covered.
    }
}