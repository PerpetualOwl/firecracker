// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the virtio-crypto request structures based on Virtio Spec v1.2, Section 5.8.7.

use vm_memory::{bitmap::Bitmap, ByteValued, GuestAddress, GuestMemoryError};
use crate::devices::virtio::queue::DescriptorChain;
use super::VirtioCryptoError;

// Virtio Crypto Request Types (Virtio Spec 1.2, Table 5.8.7.1)
pub const VIRTIO_CRYPTO_OP_CREATE_SESSION: u32 = 0x0200;
pub const VIRTIO_CRYPTO_OP_DESTROY_SESSION: u32 = 0x0201;
pub const VIRTIO_CRYPTO_CIPHER_REQ: u32 = 0x0400; // Base for cipher requests
pub const VIRTIO_CRYPTO_HASH_REQ: u32 = 0x0600; // Base for hash requests
pub const VIRTIO_CRYPTO_MAC_REQ: u32 = 0x0800; // Base for MAC requests
pub const VIRTIO_CRYPTO_AEAD_REQ: u32 = 0x0a00; // Base for AEAD requests
pub const VIRTIO_CRYPTO_AKCIPHER_REQ: u32 = 0x0c00; // Base for asymmetric requests

// Virtio Crypto Request Opcodes (Virtio Spec 1.2, Section 5.8.7.1)
// These combine the service type and operation type.
// Example for Cipher:
pub const VIRTIO_CRYPTO_CIPHER_CREATE_SESSION: u32 = VIRTIO_CRYPTO_OP_CREATE_SESSION | VIRTIO_CRYPTO_SERVICE_CIPHER;
pub const VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION: u32 = VIRTIO_CRYPTO_OP_DESTROY_SESSION | VIRTIO_CRYPTO_SERVICE_CIPHER;
pub const VIRTIO_CRYPTO_CIPHER_ENCRYPT: u32 = VIRTIO_CRYPTO_CIPHER_REQ | 0x00;
pub const VIRTIO_CRYPTO_CIPHER_DECRYPT: u32 = VIRTIO_CRYPTO_CIPHER_REQ | 0x01;
// Example for MAC:
pub const VIRTIO_CRYPTO_MAC_CREATE_SESSION: u32 = VIRTIO_CRYPTO_OP_CREATE_SESSION | VIRTIO_CRYPTO_SERVICE_MAC;
pub const VIRTIO_CRYPTO_MAC_DESTROY_SESSION: u32 = VIRTIO_CRYPTO_OP_DESTROY_SESSION | VIRTIO_CRYPTO_SERVICE_MAC;
pub const VIRTIO_CRYPTO_MAC_GENERATE: u32 = VIRTIO_CRYPTO_MAC_REQ | 0x00;
pub const VIRTIO_CRYPTO_MAC_VERIFY: u32 = VIRTIO_CRYPTO_MAC_REQ | 0x01;

// Virtio Crypto Response Status Codes (Virtio Spec 1.2, Section 5.8.7.1)
pub const VIRTIO_CRYPTO_OK: u8 = 0;
pub const VIRTIO_CRYPTO_ERR: u8 = 1; // Unspecified error
pub const VIRTIO_CRYPTO_BADMSG: u8 = 2; // Request format error
pub const VIRTIO_CRYPTO_NOTSUPP: u8 = 3; // Request not supported
pub const VIRTIO_CRYPTO_INVSESS: u8 = 4; // Invalid session ID
pub const VIRTIO_CRYPTO_NOSESS: u8 = 5; // No such session
// ... other status codes as needed

// Common Request Header (Virtio Spec 1.2, Section 5.8.7.1)
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioCryptoRequestHeader {
    /// Session ID for session-based requests, 0 otherwise. (le64)
    pub session_id: u64,
    /// Request opcode (e.g., VIRTIO_CRYPTO_CIPHER_ENCRYPT). (le32)
    pub opcode: u32,
    /// Flags associated with the request. (le32)
    pub flags: u32,
    // Followed by service-specific request data
}
// SAFETY: `VirtioCryptoRequestHeader` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for VirtioCryptoRequestHeader {}

// Session Creation Parameters (Virtio Spec 1.2, Section 5.8.7.2)
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioCryptoSessionParams {
    /// Algorithm/mode specific parameters (e.g., cipher algorithm, hash type). (le32)
    pub algo_param1: u32,
    /// Additional algorithm/mode specific parameters. (le32)
    pub algo_param2: u32,
    /// Length of the key. (le32)
    pub key_len: u32,
    /// Reserved.
    pub reserved: u32,
    // Followed by the key data
}
// SAFETY: `VirtioCryptoSessionParams` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for VirtioCryptoSessionParams {}

// Session Creation Request Structure (Control Queue)
// Header (opcode = CREATE_SESSION | service) + SessionParams + Key
// The key follows SessionParams immediately in the same descriptor.

// Session Destruction Request Structure (Control Queue)
// Header (opcode = DESTROY_SESSION | service, session_id = ID to destroy)
// No additional parameters needed.

// Response Structure (Common for most requests)
// Just a single status byte written to the status descriptor.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioCryptoResponse {
    pub status: u8,
}
// SAFETY: `VirtioCryptoResponse` contains only a POD in `repr(C)`, without padding.
unsafe impl ByteValued for VirtioCryptoResponse {}

// Cipher Operation Parameters (Virtio Spec 1.2, Section 5.8.7.3)
// This structure is part of the dataq request, following the common header.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioCryptoCipherPara {
    /// Length of the IV. (le32)
    pub iv_len: u32,
    /// Length of the source data. (le32)
    pub src_len: u32,
    /// Length of the destination data. (le32)
    pub dst_len: u32,
    /// Reserved padding.
    pub padding: [u8; 12], // As per spec, though some diagrams show 4 bytes. Using 12 for full struct size of 24.
}
// SAFETY: `VirtioCryptoCipherPara` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for VirtioCryptoCipherPara {}

// MAC Operation Parameters (Virtio Spec 1.2, Section 5.8.7.5)
// This structure is part of the dataq request, following the common header.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioCryptoMacPara {
    /// Length of the source data. (le32)
    pub src_len: u32,
    /// Length of the MAC result. (le32)
    pub mac_len: u32,
    /// Reserved padding.
    pub padding: [u8; 16], // As per spec for struct size of 24.
}
// SAFETY: `VirtioCryptoMacPara` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for VirtioCryptoMacPara {}

// Helper function to parse the common header from a descriptor chain
pub fn parse_request_header<B: Bitmap>(
    mem: &vm_memory::GuestMemoryMmap<B>,
    desc_chain: &DescriptorChain,
) -> Result<VirtioCryptoRequestHeader, VirtioCryptoError> {
    // The first descriptor in the chain should contain the header.
    let header_desc_item = desc_chain.into_iter().next()
        .ok_or(VirtioCryptoError::DescriptorChainTooShort)?; // Chain was empty

    if header_desc_item.is_write_only() {
        // The header descriptor should be readable by the device.
        return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor);
    }

    if header_desc_item.len < std::mem::size_of::<VirtioCryptoRequestHeader>() as u32 {
        return Err(VirtioCryptoError::QueueDescriptorTooSmall(
            std::mem::size_of::<VirtioCryptoRequestHeader>(),
        ));
    }

    mem.read_obj::<VirtioCryptoRequestHeader>(header_desc_item.addr)
        .map_err(|e| {
            VirtioCryptoError::GuestMemory(e, "Failed to read request header".to_string())
        })
}

// TODO: Add parsing functions for specific request types (CreateSession, DestroySession, etc.)
// These will need to handle reading parameters and potentially keys from subsequent parts
// of the descriptor chain or the same descriptor as the header.

// Placeholder for service constants needed by request parsing/handling
const VIRTIO_CRYPTO_SERVICE_CIPHER: u32 = 1 << 0;
const VIRTIO_CRYPTO_SERVICE_MAC: u32 = 1 << 2;