// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the virtio-pmem request and response structures.
//! Based on Virtio Specification v1.2 - Section 5.10.7 Device Operation.

use vm_memory::{bitmap::Bitmap, ByteValued, GuestMemoryError, GuestMemoryMmap, ReadVolatile};
use crate::devices::virtio::queue::{DescriptorChain, Queue}; // Import DescriptorChain
use crate::logger::warn;
use super::VirtioPmemError;

// Virtio PMEM Request Types
pub const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
// PLUG and UNPLUG are deprecated in Virtio 1.2 for the pmem device,
// but we might need to handle them for compatibility or specific design choices.
// The design document mentions them.
pub const VIRTIO_PMEM_REQ_TYPE_PLUG: u32 = 1; // Deprecated in v1.2
pub const VIRTIO_PMEM_REQ_TYPE_UNPLUG: u32 = 2; // Deprecated in v1.2

// Virtio PMEM Response Codes
pub const VIRTIO_PMEM_RESP_OK: u32 = 0;
pub const VIRTIO_PMEM_RESP_EIO: u32 = 1;
// Other error codes can be added if needed, e.g., ENOMEM, EINVAL

/// The request header for virtio-pmem.
///
/// The driver sends requests in a virtqueue buffer with the following layout.
/// The header is followed by optional data (e.g., for future request types).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)] // packed to ensure no padding
pub struct VirtioPmemReqHdr {
    /// Type of the request (e.g., VIRTIO_PMEM_REQ_TYPE_FLUSH). (le32)
    pub type_: u32,
    /// Reserved for future use. (le32[15])
    pub reserved: [u32; 15],
}

// SAFETY: `VirtioPmemReqHdr` is a POD type because it only contains primitive data types
// and is `repr(C, packed)`.
unsafe impl ByteValued for VirtioPmemReqHdr {}

/// The response structure for virtio-pmem.
///
/// The device places the response in a separate virtqueue buffer.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)] // packed to ensure no padding
pub struct VirtioPmemResp {
    /// Return code for the request (e.g., VIRTIO_PMEM_RESP_OK). (le32)
    pub status: u32, // Renamed from 'ret' to match device.rs usage
}

// SAFETY: `VirtioPmemResp` is a POD type because it only contains primitive data types
// and is `repr(C, packed)`.
unsafe impl ByteValued for VirtioPmemResp {}

/// Enum representing the different types of virtio-pmem requests.
#[derive(Debug, PartialEq, Eq)]
pub enum PmemReqType {
    Flush,
    Plug,
    Unplug,
}

/// Represents a parsed virtio-pmem request from the virtqueue.
pub struct PmemRequest {
    /// The type of request.
    pub req_type: PmemReqType,
    /// The index of the descriptor containing the request header.
    pub req_desc_index: u16,
    /// The index of the descriptor designated for the response status.
    pub status_desc_index: u16,
}


impl<B: Bitmap> PmemRequest {
    /// Parses a virtio-pmem request from the descriptor chain starting at `head_index`.
    ///
    /// Returns the parsed request type, the index of the request descriptor,
    /// and the index of the status descriptor.
    ///
    /// # Arguments
    /// * `mem` - Guest memory map.
    /// * `queue` - The virtqueue containing the descriptors.
    /// * `head_index` - The index of the head descriptor for the request chain.
    pub fn parse(
        mem: &GuestMemoryMmap<B>,
        queue: &Queue,
        head_index: u16,
    ) -> Result<(PmemReqType, u16 /* req_desc_idx */, u16 /* status_desc_idx */), VirtioPmemError> where B: Bitmap {
        let chain = DescriptorChain::checked_new(queue.desc_table_ptr, queue.actual_size(), head_index)
            .ok_or(VirtioPmemError::DescriptorNotFound(head_index))?;

        let mut chain_iter = chain.into_iter();

        // 1. Find the request descriptor (must be readable)
        let req_desc_chain = chain_iter.next().ok_or(VirtioPmemError::DescriptorChainTooShort)?;

        if req_desc_chain.is_write_only() {
            return Err(VirtioPmemError::UnexpectedWriteOnlyDescriptor);
        }
        if req_desc_chain.len < std::mem::size_of::<VirtioPmemReqHdr>() as u32 {
             return Err(VirtioPmemError::DescriptorChainTooShort);
        }

        // 2. Read the request header
        let req_hdr: VirtioPmemReqHdr = mem.read_obj(req_desc_chain.addr)
            .map_err(|e| VirtioPmemError::GuestMemory(e))?;

        // 3. Find the status descriptor (must be writable) from the rest of the chain
        let mut status_desc_chain_opt: Option<DescriptorChain> = None;
        for desc_chain_item in chain_iter { // chain_iter continues from where req_desc_chain left off
            if desc_chain_item.is_write_only() {
                if desc_chain_item.len >= std::mem::size_of::<VirtioPmemResp>() as u32 {
                    status_desc_chain_opt = Some(desc_chain_item);
                    break;
                } else {
                    return Err(VirtioPmemError::DescriptorChainTooShort); // Writable descriptor too small
                }
            }
        }

        let status_desc_chain = status_desc_chain_opt.ok_or(VirtioPmemError::UnexpectedReadOnlyDescriptor)?; // No suitable writable descriptor found

        // 4. Determine request type
        let req_type = match u32::from_le(req_hdr.type_) {
            VIRTIO_PMEM_REQ_TYPE_FLUSH => PmemReqType::Flush,
            VIRTIO_PMEM_REQ_TYPE_PLUG => PmemReqType::Plug,
            VIRTIO_PMEM_REQ_TYPE_UNPLUG => PmemReqType::Unplug,
            other => {
                warn!("PMEM: Unknown request type: {}", other);
                return Err(VirtioPmemError::UnknownRequestType(other));
            }
        };

        Ok((req_type, req_desc_chain.index, status_desc_chain.index))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{default_mem, VirtQueue};
    use vm_memory::{Bytes, GuestAddress};

    #[test]
    fn test_parse_flush_request() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        assert!(vq.end().0 > 0x1000); // Ensure enough space for descriptors and data

        let req_hdr_addr = GuestAddress(0x100);
        let status_addr = GuestAddress(0x200);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Request descriptor (readable)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);

        // Status descriptor (writable)
        vq.dtable[1].set(status_addr.raw_value(), status_size, VIRTQ_DESC_F_WRITE, 0); // No next

        // Write Flush request header
        let flush_req = VirtioPmemReqHdr {
            type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(),
            ..Default::default()
        };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        // Parse
        let (req_type, req_idx, status_idx) = PmemRequest::parse(&mem, &vq.queue, 0).unwrap();

        assert_eq!(req_type, PmemReqType::Flush);
        assert_eq!(req_idx, 0);
        assert_eq!(status_idx, 1);
    }

    #[test]
    fn test_parse_plug_unplug_request() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let status_addr = GuestAddress(0x200);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Setup descriptors (req -> status)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable[1].set(status_addr.raw_value(), status_size, VIRTQ_DESC_F_WRITE, 0);

        // Test Plug
        let plug_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_PLUG.to_le(), ..Default::default() };
        mem.write_obj(plug_req, req_hdr_addr).unwrap();
        let (req_type, _, status_idx) = PmemRequest::parse(&mem, &vq.queue, 0).unwrap();
        assert_eq!(req_type, PmemReqType::Plug);
        assert_eq!(status_idx, 1);

        // Test Unplug
        let unplug_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_UNPLUG.to_le(), ..Default::default() };
        mem.write_obj(unplug_req, req_hdr_addr).unwrap();
        let (req_type, _, status_idx) = PmemRequest::parse(&mem, &vq.queue, 0).unwrap();
        assert_eq!(req_type, PmemReqType::Unplug);
        assert_eq!(status_idx, 1);
    }

    #[test]
    fn test_parse_error_req_write_only() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;

        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        // Mark request descriptor as write-only
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_WRITE, 0);

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        assert!(matches!(res, Err(VirtioPmemError::UnexpectedWriteOnlyDescriptor)));
    }

     #[test]
    fn test_parse_error_req_too_small() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        // Set size smaller than header
        let req_hdr_size_small = (std::mem::size_of::<VirtioPmemReqHdr>() - 1) as u32;

        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size_small, 0, 0);

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        assert!(matches!(res, Err(VirtioPmemError::DescriptorChainTooShort)));
    }

    #[test]
    fn test_parse_error_no_status_desc() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;

        // Only provide the request descriptor
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, 0, 0); // No next

        let flush_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(), ..Default::default() };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        // Should fail because no writable descriptor was found
        assert!(matches!(res, Err(VirtioPmemError::UnexpectedReadOnlyDescriptor)));
    }

    #[test]
    fn test_parse_error_status_read_only() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let status_addr = GuestAddress(0x200);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Setup descriptors (req -> status)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);
        // Mark status descriptor as readable (not writable)
        vq.dtable[1].set(status_addr.raw_value(), status_size, 0, 0);

        let flush_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(), ..Default::default() };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        // Should fail because the only potential status descriptor is not writable
        assert!(matches!(res, Err(VirtioPmemError::UnexpectedReadOnlyDescriptor)));
    }

    #[test]
    fn test_parse_error_status_too_small() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let status_addr = GuestAddress(0x200);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        // Set status size smaller than response struct
        let status_size_small = (std::mem::size_of::<VirtioPmemResp>() - 1) as u32;

        // Setup descriptors (req -> status)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable[1].set(status_addr.raw_value(), status_size_small, VIRTQ_DESC_F_WRITE, 0);

        let flush_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(), ..Default::default() };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        // Should fail because the writable descriptor is too small
        assert!(matches!(res, Err(VirtioPmemError::DescriptorChainTooShort)));
    }

    #[test]
    fn test_parse_error_unknown_type() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let status_addr = GuestAddress(0x200);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Setup descriptors (req -> status)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable[1].set(status_addr.raw_value(), status_size, VIRTQ_DESC_F_WRITE, 0);

        // Write unknown request type
        let unknown_req = VirtioPmemReqHdr { type_: 999u32.to_le(), ..Default::default() };
        mem.write_obj(unknown_req, req_hdr_addr).unwrap();

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        assert!(matches!(res, Err(VirtioPmemError::UnknownRequestType(999))));
    }

     #[test]
    fn test_parse_error_broken_chain() {
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;

        // Setup descriptors (req -> missing)
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        // Point to next descriptor 1, but descriptor 1 is not configured
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1);

        let flush_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(), ..Default::default() };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        let res = PmemRequest::parse(&mem, &vq.queue, 0);
        // Should fail because descriptor 1 is not found
        assert!(matches!(res, Err(VirtioPmemError::DescriptorNotFound(1))));
    }

    #[test]
    fn test_parse_longer_chain() {
        // Test chain: req -> data (read) -> status (write)
        let mem = default_mem();
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let req_hdr_addr = GuestAddress(0x100);
        let data_addr = GuestAddress(0x200);
        let status_addr = GuestAddress(0x300);
        let req_hdr_size = std::mem::size_of::<VirtioPmemReqHdr>() as u32;
        let data_size = 128u32;
        let status_size = std::mem::size_of::<VirtioPmemResp>() as u32;

        // Setup descriptors
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.dtable[0].set(req_hdr_addr.raw_value(), req_hdr_size, VIRTQ_DESC_F_NEXT, 1); // req -> data
        vq.dtable[1].set(data_addr.raw_value(), data_size, VIRTQ_DESC_F_NEXT, 2);       // data -> status
        vq.dtable[2].set(status_addr.raw_value(), status_size, VIRTQ_DESC_F_WRITE, 0);  // status (end)

        // Write Flush request header
        let flush_req = VirtioPmemReqHdr { type_: VIRTIO_PMEM_REQ_TYPE_FLUSH.to_le(), ..Default::default() };
        mem.write_obj(flush_req, req_hdr_addr).unwrap();

        // Parse
        let (req_type, req_idx, status_idx) = PmemRequest::parse(&mem, &vq.queue, 0).unwrap();

        assert_eq!(req_type, PmemReqType::Flush);
        assert_eq!(req_idx, 0); // Head index
        assert_eq!(status_idx, 2); // Index of the status descriptor
    }
}