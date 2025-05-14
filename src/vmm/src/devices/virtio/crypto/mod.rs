// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio-crypto device.

pub mod device;
// pub mod event_handler; // To be adapted if needed
// pub mod persist;       // To be implemented
pub mod request;       // For controlq and dataq requests
// pub mod session;       // For managing crypto sessions

use vm_memory::GuestMemoryError;
use self::request::{VIRTIO_CRYPTO_OK, VIRTIO_CRYPTO_ERR, VIRTIO_CRYPTO_BADMSG, VIRTIO_CRYPTO_NOTSUPP, VIRTIO_CRYPTO_INVSESS, VIRTIO_CRYPTO_NOSESS};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;

pub use self::device::VirtioCrypto;

// According to virtio spec 1.2, section 5.8.3:
// "The virtio-crypto device uses two virtqueues: a control virtqueue and at least one data virtqueue."
// Minimal implementation will have 1 controlq and 1 dataq.
pub const CRYPTO_NUM_QUEUES: usize = 2; // 0: controlq, 1: dataq0
/// Queue sizes for crypto device.
pub const CRYPTO_QUEUE_SIZES: [u16; CRYPTO_NUM_QUEUES] = [FIRECRACKER_MAX_QUEUE_SIZE; CRYPTO_NUM_QUEUES];


/// Errors the crypto device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioCryptoError {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short. Expected: {0}
    QueueDescriptorTooSmall(usize),
    /// Guest gave us a descriptor that pointed to an invalid guest memory region.
    QueueDescriptorInvalid,
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError, String),
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// A descriptor index was not found in the queue: {0}
    DescriptorNotFound(u16),
    /// An unknown request type was received: {0}
    UnknownRequestType(u32),
    /// An unsupported opcode was received: {0}
    UnsupportedOpcode(u32),
    /// Error opening eventfd: {0}
    EventFd(std::io::Error),
    /// Error creating an irqfd: {0}
    IrqTrigger(std::io::Error),
    /// Persistence error: {0}
    Persist(crate::devices::virtio::persist::PersistError),
    /// Invalid crypto session ID.
    InvalidSessionId,
    /// No such crypto session ID exists.
    NoSuchSession,
    /// Crypto operation failed.
    CryptoOperationFailed,
    /// Feature not supported by device.
    FeatureNotSupported,
    /// Invalid parameters for a crypto operation.
    InvalidParameters,
    /// Invalid key length provided.
    InvalidKeyLength,
    /// Maximum number of sessions reached.
    MaxSessionsReached,
    /// Functionality not yet implemented.
    NotImplemented,
    /// Device was not active when an operation was attempted.
    DeviceNotActive,
    /// Attempted to create a session with an ID that is already in use.
    SessionIdInUse(u64),
    /// MAC verification failed.
    MacVerificationFailed,
    /// A required queue descriptor was missing.
    QueueDescriptorMissing,
}
impl VirtioCryptoError {
    /// Converts the error into a virtio status code byte.
    pub fn to_status_code(&self) -> u8 {
        match self {
            VirtioCryptoError::DescriptorChainTooShort => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::QueueDescriptorTooSmall(_) => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::QueueDescriptorInvalid => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::GuestMemory(_, _) => VIRTIO_CRYPTO_ERR, // Generic error for memory issues
            VirtioCryptoError::UnexpectedReadOnlyDescriptor => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::UnexpectedWriteOnlyDescriptor => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::DescriptorNotFound(_) => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::UnknownRequestType(_) => VIRTIO_CRYPTO_NOTSUPP,
            VirtioCryptoError::UnsupportedOpcode(_) => VIRTIO_CRYPTO_NOTSUPP,
            VirtioCryptoError::EventFd(_) => VIRTIO_CRYPTO_ERR,
            VirtioCryptoError::IrqTrigger(_) => VIRTIO_CRYPTO_ERR,
            VirtioCryptoError::Persist(_) => VIRTIO_CRYPTO_ERR,
            VirtioCryptoError::InvalidSessionId => VIRTIO_CRYPTO_INVSESS,
            VirtioCryptoError::NoSuchSession => VIRTIO_CRYPTO_NOSESS,
            VirtioCryptoError::CryptoOperationFailed => VIRTIO_CRYPTO_ERR,
            VirtioCryptoError::FeatureNotSupported => VIRTIO_CRYPTO_NOTSUPP,
            VirtioCryptoError::InvalidParameters => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::InvalidKeyLength => VIRTIO_CRYPTO_BADMSG,
            VirtioCryptoError::MaxSessionsReached => VIRTIO_CRYPTO_ERR, // Or a specific code if defined
            VirtioCryptoError::NotImplemented => VIRTIO_CRYPTO_NOTSUPP,
            VirtioCryptoError::DeviceNotActive => VIRTIO_CRYPTO_ERR, // Generic error
            VirtioCryptoError::SessionIdInUse(_) => VIRTIO_CRYPTO_ERR, // Generic error, should be rare
            VirtioCryptoError::MacVerificationFailed => VIRTIO_CRYPTO_ERR, // Or a specific MAC error if defined in virtio spec
            VirtioCryptoError::QueueDescriptorMissing => VIRTIO_CRYPTO_BADMSG,
        }
    }
}