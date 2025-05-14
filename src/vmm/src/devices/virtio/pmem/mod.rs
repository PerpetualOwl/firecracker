// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio-pmem device.

pub mod device;
// TODO: Review and adapt event_handler for pmem.
// mod event_handler;
// TODO: Review and adapt io for pmem (mmap/msync focus).
// mod io;
// TODO: Adapt metrics for pmem.
// pub mod metrics;
pub mod persist;
// TODO: Implement pmem specific request handling.
pub mod request;
// TODO: Adapt test_utils for pmem.
// pub mod test_utils;

use vm_memory::GuestMemoryError;

pub use self::device::VirtioPmem;
pub use self::request::*; // Will be adapted for pmem requests.
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;

/// The number of queues for a pmem device.
pub const PMEM_NUM_QUEUES: usize = 1;
/// Queue sizes for pmem device.
pub const PMEM_QUEUE_SIZES: [u16; PMEM_NUM_QUEUES] = [FIRECRACKER_MAX_QUEUE_SIZE];

/// Errors the pmem device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioPmemError {
    /// Cannot create config.
    Config,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a backing file's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The data length is invalid for a request.
    InvalidDataLength,
    /// The requested operation specified an invalid offset or range.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// A descriptor index was not found in the queue: {0}
    DescriptorNotFound(u16),
    /// An unknown request type was received: {0}
    UnknownRequestType(u32),
    /// Error manipulating the backing file: {0} ({1})
    BackingFile(std::io::Error, String),
    /// Error during mmap operation on backing file: {0}
    Mmap(std::io::Error),
    /// Error during msync operation on backing file: {0}
    Msync(std::io::Error),
    /// Error mapping memory into guest address space via KVM: {0}
    KvmMemoryRegion(String),
    /// Error opening eventfd: {0}
    EventFd(std::io::Error),
    /// Error creating an irqfd: {0}
    IrqTrigger(std::io::Error),
    /// Persistence error: {0}
    Persist(crate::devices::virtio::persist::PersistError),
}