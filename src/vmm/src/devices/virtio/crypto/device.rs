use aes::{cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray}, Aes128};
use block_modes::{Cbc, BlockMode, Pkcs7};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit}; // Aliased KeyInit
use sha2::Sha256;
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::any::Any;
use std::sync::atomic::AtomicU32;
use std::collections::HashMap; // For session management

use serde::{Deserialize, Serialize};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap, GuestMemoryError, bitmap::AtomicBitmap, Address};
use vmm_sys_util::eventfd::EventFd;
use crate::devices::virtio::queue::DescriptorChain; // Needed for processing
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice, DescriptorError}; // DescriptorError is now an alias for QueueError
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::ActivateError;
use crate::logger::{error, warn, IncMetric};
use crate::utils::u64_to_usize;

// Import request/response types
use super::request::*;

use super::{CRYPTO_NUM_QUEUES, CRYPTO_QUEUE_SIZES, VirtioCryptoError};
// TODO: Import request/response types when defined.
// use super::request::*;

// Placeholder for RustCrypto crate usage (design_document.md:385)
// Assuming these would be in Cargo.toml and then imported here.
// For example:
// use aes::Aes128;
// use cbc::{Encryptor, Decryptor};
// use hmac::{Hmac, Mac};
// use sha2::Sha256;
// use block_modes::{BlockMode, Cbc};
// use block_modes::block_padding::Pkcs7;

// Type alias for a cipher instance, e.g., AES-128-CBC encryptor/decryptor
// type Aes128CbcEnc = Encryptor<Aes128, Cbc<Aes128, Pkcs7>>;
// type Aes128CbcDec = Decryptor<Aes128, Cbc<Aes128, Pkcs7>>;
// Type alias for HMAC-SHA256 instance
// type HmacSha256 = Hmac<Sha256>;

const AES_BLOCK_SIZE: usize = 16;
// Virtio Device Type for Crypto
pub const TYPE_CRYPTO: u32 = 20; // VIRTIO_ID_CRYPTODEV from virtio spec

// Feature bits for virtio-crypto (Virtio Spec 1.2, Section 5.8.4)
// Minimal set: VIRTIO_F_VERSION_1 is usually handled by the common device layer.
// No specific crypto features are strictly *required* for a minimal device to be
// recognized, but the guest will query capabilities via config space.
// pub const VIRTIO_CRYPTO_F_REVISION_1: u64 = 0; // Example, actual bit might vary or be implicit

// Virtio Crypto Device Status (Virtio Spec 1.2, Section 5.8.6.1)
const VIRTIO_CRYPTO_S_HW_READY: u32 = 1 << 0; // Device has been initialized and is ready

// Config space fields (Virtio Spec 1.2, Section 5.8.6)
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct CryptoConfigSpace {
    /// Device status flags (e.g., VIRTIO_CRYPTO_S_HW_READY). (le32)
    pub status: u32,
    /// Maximum number of data virtqueues supported. (le32)
    pub max_data_queues: u32,
    /// Bitmask of supported crypto services (e.g., CIPHER, MAC). (le32)
    pub crypto_services: u32,
    /// Cipher algorithms mask (lower 32 bits). (le32)
    pub cipher_algo_l: u32,
    /// Cipher algorithms mask (upper 32 bits). (le32)
    pub cipher_algo_h: u32,
    /// Hash algorithms mask. (le32)
    pub hash_algo: u32,
    /// MAC algorithms mask (lower 32 bits). (le32)
    pub mac_algo_l: u32,
    /// MAC algorithms mask (upper 32 bits). (le32)
    pub mac_algo_h: u32,
    /// AEAD algorithms mask. (le32)
    pub aead_algo: u32,
    /// Maximum cipher key length in bytes. (le32)
    pub max_cipher_key_len: u32,
    /// Maximum authentication key length in bytes. (le32)
    pub max_auth_key_len: u32,
    /// Reserved. (le32)
    pub reserved: u32,
    /// Maximum size of crypto request content in bytes. (le64)
    pub max_size: u64,
    /// Asymmetric cipher algorithms mask. (le32)
    pub akcipher_algo: u32,
    // Additional fields if any from newer specs or for specific features.
}

// SAFETY: `CryptoConfigSpace` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for CryptoConfigSpace {}

// Minimal supported services and algorithms (design_document.md:345)
// For `crypto_services` bitmask:
const VIRTIO_CRYPTO_SERVICE_CIPHER: u32 = 1 << 0;
const VIRTIO_CRYPTO_SERVICE_MAC: u32 = 1 << 2;
// const VIRTIO_CRYPTO_SERVICE_AKCIPHER: u32 = 1 << 4; // Optional

// For algorithm masks (example for AES-128-CBC and HMAC-SHA256)
// These are specific to the virtio-crypto spec definitions for algorithms.
// Placeholder values, actual values depend on the spec's algorithm numbering.
const VIRTIO_CRYPTO_CIPHER_AES_CBC: u32 = 1 << 1; // Example
const VIRTIO_CRYPTO_MAC_HMAC_SHA256: u32 = 1 << 1; // Example


/// API Configuration for the virtio-crypto device.
/// Based on design_document.md:127-130
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioCryptoConfig {
    /// Unique identifier for the crypto device.
    pub crypto_id: String,
    /// Number of data virtqueues (minimal implementation likely supports only 1).
    #[serde(default = "default_num_data_queues")]
    pub num_data_queues: u32,
}

fn default_num_data_queues() -> u32 {
    1 // As per design_document.md:133
}

/// Trait representing an active crypto session state (design_document.md:438)
pub trait CryptoSession: std::fmt::Debug + Send + Sync + Any {
    // Methods for processing data, specific to the session type
    // fn process(&mut self, input_descs: &[Descriptor], output_descs: &[Descriptor], mem: &GuestMemoryMmap) -> Result<u32, VirtioCryptoError>;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn algorithm(&self) -> CryptoAlgorithm;
    // Potentially methods to get algorithm info, etc.
    // fn algorithm(&self) -> SupportedAlgorithms; // Example
}

// Concrete session implementations

// Type alias for AES-128-CBC encryptor/decryptor
type Aes128CbcEnc = block_modes::Cbc<aes::Aes128, Pkcs7>;
type Aes128CbcDec = block_modes::Cbc<aes::Aes128, Pkcs7>;
// Type alias for HMAC-SHA256 instance
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct AesCbcEncryptSession {
    cipher: Aes128CbcEnc,
}
impl CryptoSession for AesCbcEncryptSession {
    // Placeholder process method
    // fn process(&mut self, ...) -> Result<u32, VirtioCryptoError> { Err(VirtioCryptoError::NotImplemented) }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
    fn algorithm(&self) -> CryptoAlgorithm {
        CryptoAlgorithm::Aes128CbcEncrypt
    }
}

#[derive(Debug)]
struct AesCbcDecryptSession {
    cipher: Aes128CbcDec,
}
impl CryptoSession for AesCbcDecryptSession {
    // Placeholder process method
    // fn process(&mut self, ...) -> Result<u32, VirtioCryptoError> { Err(VirtioCryptoError::NotImplemented) }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
    fn algorithm(&self) -> CryptoAlgorithm {
        CryptoAlgorithm::Aes128CbcDecrypt
    }
}

#[derive(Debug)]
struct HmacSha256Session {
    mac: HmacSha256,
}
impl CryptoSession for HmacSha256Session {
    // Placeholder process method
    // fn process(&mut self, ...) -> Result<u32, VirtioCryptoError> { Err(VirtioCryptoError::NotImplemented) }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
    fn algorithm(&self) -> CryptoAlgorithm {
        CryptoAlgorithm::HmacSha256
    }
}

// Enum to represent the specific algorithm for dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoAlgorithm {
   Aes128CbcEncrypt,
   Aes128CbcDecrypt,
   HmacSha256,
}

/// Virtio device for cryptographic acceleration.
#[derive(Debug)]
pub struct VirtioCrypto {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: CryptoConfigSpace,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>, // Index 0: controlq, Index 1..N: dataq(s)
    pub queue_evts: Vec<EventFd>, // Should match CRYPTO_NUM_QUEUES
    pub device_state: DeviceState,
    pub irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub id: String,
    pub sessions: HashMap<u64, Box<dyn CryptoSession>>, // Session ID to state object
    pub next_session_id: u64,

    // TODO: Define and use CryptoDeviceMetrics
    // pub metrics: Arc<CryptoDeviceMetrics>,
}

impl VirtioCrypto {
    pub fn new(config: VirtioCryptoConfig) -> Result<Self, VirtioCryptoError> {
        // VIRTIO_F_VERSION_1 is a common feature.
        let avail_features = 1u64 << crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1
                           | 1u64 << crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
        
        let mut queue_evts = Vec::with_capacity(CRYPTO_NUM_QUEUES);
        for _ in 0..CRYPTO_NUM_QUEUES {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioCryptoError::EventFd)?);
        }
        let queues = CRYPTO_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        // Initialize config space based on minimal supported features
        let config_space = CryptoConfigSpace {
            status: 0, // VIRTIO_CRYPTO_S_HW_READY will be set on activation if backend is ready
            max_data_queues: 1, // Minimal implementation
            crypto_services: VIRTIO_CRYPTO_SERVICE_CIPHER | VIRTIO_CRYPTO_SERVICE_MAC,
            cipher_algo_l: VIRTIO_CRYPTO_CIPHER_AES_CBC,
            mac_algo_l: VIRTIO_CRYPTO_MAC_HMAC_SHA256,
            max_cipher_key_len: 16, // For AES-128
            max_auth_key_len: 32,  // For HMAC-SHA256 (SHA256 block size is 64, but key can be up to block size)
            max_size: 65536, // Example max request size
            ..Default::default()
        };

        Ok(VirtioCrypto {
            avail_features,
            acked_features: 0,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioCryptoError::EventFd)?,
            queues,
            queue_evts,
            device_state: DeviceState::Inactive,
            irq_trigger: IrqTrigger::new().map_err(VirtioCryptoError::IrqTrigger)?,
            id: config.crypto_id.clone(),
            sessions: HashMap::new(),
            next_session_id: 1, // Start session IDs from 1
            // metrics: CryptoMetricsPerDevice::alloc(config.crypto_id), // TODO
        })
    }

    /// Processes the control virtqueue.
    /// Returns true if the queue processing loop should continue.
    pub fn process_control_queue(&mut self) -> bool {
        if !self.is_activated() {
            warn!("CRYPTO: Tried to process control queue on inactive device.");
            return false;
        }

        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => unreachable!("Device is activated but no memory available"),
        };

        let control_queue = &mut self.queues[0]; // Index 0 is control queue
        let mut used_any = false;

        while let Some(chain) = control_queue.pop(mem) {
            let chain_head_index = chain.head_index();
            let status = match parse_request_header(mem, &chain) {
                Ok(header) => {
                    match header.opcode {
                        VIRTIO_CRYPTO_CIPHER_CREATE_SESSION | VIRTIO_CRYPTO_MAC_CREATE_SESSION => {
                            self.handle_create_session(&chain, header)
                        }
                        VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION | VIRTIO_CRYPTO_MAC_DESTROY_SESSION => {
                            self.handle_destroy_session(&chain, header)
                        }
                        _ => {
                            warn!("CRYPTO: Unsupported control queue opcode: {}", header.opcode);
                            Err(VirtioCryptoError::UnsupportedOpcode(header.opcode))
                        }
                    }
                }
                Err(e) => {
                    error!("CRYPTO: Failed to parse request header: {:?}", e);
                    Err(e) // Propagate parsing error
                }
            };

            self.write_response(&chain, status, 0); // 0 for control queue
            self.queues[0].add_used(mem, chain_head_index, std::mem::size_of::<VirtioCryptoResponse>() as u32).expect("Failed to add used");
            used_any = true;
        }

        if used_any {
            if control_queue.needs_notification(mem).unwrap_or(true) {
                self.irq_trigger.trigger_irq(IrqType::Vring).expect("Failed to signal control queue");
            }
        }

        // For now, always return false to avoid tight loops if queue isn't advancing
        // In a real event loop, this might depend on whether descriptors were processed.
        false
    }

    /// Handles a Create Session request from the control queue.
    fn handle_create_session(
        &mut self,
        chain: &DescriptorChain,
        mut header: VirtioCryptoRequestHeader, // Make mutable to update session_id
    ) -> Result<(), VirtioCryptoError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => return Err(VirtioCryptoError::DeviceNotActive),
        };

        // The request header is in the first descriptor. SessionParams and key follow.
        let mut desc_iter = chain.into_iter();

        let header_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?;
        // Header was already parsed by parse_request_header, we use its address if needed.

        // Parse SessionParams
        let params_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?;
        if params_desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); }
        if params_desc_item.len < std::mem::size_of::<VirtioCryptoSessionParams>() as u32 {
            return Err(VirtioCryptoError::QueueDescriptorTooSmall(std::mem::size_of::<VirtioCryptoSessionParams>()));
        }
        let params: VirtioCryptoSessionParams = mem.read_obj(params_desc_item.addr)
            .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read session params".to_string()))?;

        // Read Key Data
        let key_len = u64_to_usize(params.key_len as u64);
        if key_len == 0 || key_len > 256 { // Arbitrary reasonable max key length
            return Err(VirtioCryptoError::InvalidKeyLength);
        }
        let mut key_data = vec![0u8; key_len];
        
        // Key data might be in the same descriptor as params (if it fits after params),
        // or in subsequent descriptors.
        let params_struct_size = std::mem::size_of::<VirtioCryptoSessionParams>();
        let mut bytes_of_key_read = 0;

        // Check if key starts in the params_desc_item
        if params_desc_item.len > params_struct_size as u32 {
            let key_start_in_params_desc = params_desc_item.addr.checked_add(params_struct_size as u64)
                .ok_or(VirtioCryptoError::GuestMemory(GuestMemoryError::InvalidGuestAddress(params_desc_item.addr), "Key address overflow in params_desc".to_string()))?;
            let key_bytes_in_params_desc = (params_desc_item.len - params_struct_size as u32) as usize;
            let to_read_from_params_desc = std::cmp::min(key_bytes_in_params_desc, key_len);

            mem.read_slice(&mut key_data[..to_read_from_params_desc], key_start_in_params_desc)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read key data from params_desc".to_string()))?;
            bytes_of_key_read += to_read_from_params_desc;
        }

        // Read remaining key bytes from subsequent descriptors
        while bytes_of_key_read < key_len {
            let key_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?; // Not enough descriptors for key
            if key_desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); }
            
            let to_read_from_current_desc = std::cmp::min(key_desc_item.len as usize, key_len - bytes_of_key_read);
            if to_read_from_current_desc == 0 { break; } // Should not happen if key_len > bytes_of_key_read

            mem.read_slice(&mut key_data[bytes_of_key_read .. bytes_of_key_read + to_read_from_current_desc], key_desc_item.addr)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read key data from subsequent desc".to_string()))?;
            bytes_of_key_read += to_read_from_current_desc;
        }

        if bytes_of_key_read < key_len {
            return Err(VirtioCryptoError::DescriptorChainTooShort); // Not enough data for the full key
        }

        let session_id = self.next_session_id;
        if self.sessions.contains_key(&session_id) {
            return Err(VirtioCryptoError::SessionIdInUse(session_id));
        }

        let session: Box<dyn CryptoSession> = match header.opcode {
            VIRTIO_CRYPTO_CIPHER_CREATE_SESSION => {
                if key_len != 16 { return Err(VirtioCryptoError::InvalidKeyLength); }
                let key_arr = GenericArray::from_slice(&key_data);
                if params.algo_param2 == 0 { // ENCRYPT
                    let cipher = Aes128CbcEnc::new(key_arr, GenericArray::from_slice(&[0u8; 16]));
                    Box::new(AesCbcEncryptSession { cipher })
                } else { // DECRYPT
                    let cipher = Aes128CbcDec::new(key_arr, GenericArray::from_slice(&[0u8; 16]));
                    Box::new(AesCbcDecryptSession { cipher })
                }
            }
            VIRTIO_CRYPTO_MAC_CREATE_SESSION => {
                let mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&key_data)
                    .map_err(|_| VirtioCryptoError::InvalidKeyLength)?;
                Box::new(HmacSha256Session { mac })
            }
            _ => return Err(VirtioCryptoError::UnsupportedOpcode(header.opcode)),
        };

        self.sessions.insert(session_id, session);
        self.next_session_id += 1;

        header.session_id = session_id.to_le();
        mem.write_obj(header, header_desc_item.addr)
            .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to write back session ID".to_string()))?;

        Ok(())
    }

    /// Handles a Destroy Session request from the control queue.
    fn handle_destroy_session(
        &mut self,
        _chain: &DescriptorChain, // Not strictly needed if only using header
        header: VirtioCryptoRequestHeader, // Contains session_id to destroy
    ) -> Result<(), VirtioCryptoError> {
        let session_id = u64::from_le(header.session_id); // Ensure correct endianness

        if self.sessions.remove(&session_id).is_some() {
            warn!("CRYPTO: Destroyed session ID {}", session_id);
            Ok(())
        } else {
            warn!("CRYPTO: Attempted to destroy non-existent session ID {}", session_id);
            Err(VirtioCryptoError::NoSuchSession)
        }
    }

    /// Writes the response status to the status descriptor in the chain.
    fn write_response(&self, chain: &DescriptorChain, result: Result<(), VirtioCryptoError>, _queue_idx: usize) { // queue_idx not used if add_used is external
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => {
                // This should not happen if the device is processing a queue.
                error!("CRYPTO: write_response called on inactive device.");
                // Cannot add to used queue if memory is not available.
                // The request will likely time out on the guest side.
                return;
            }
        };

        let status_code = match result {
            Ok(()) => VIRTIO_CRYPTO_OK,
            Err(e) => e.to_status_code(), // Convert error enum to virtio status code
        };
        let response = VirtioCryptoResponse { status: status_code };

        // Find the last writable descriptor in the chain for the status.
        let mut status_desc_item_opt: Option<DescriptorChain> = None;
        for desc_item in chain.into_iter().collect::<Vec<_>>().into_iter().rev() { // Iterate backwards to find the last writable
            if desc_item.is_write_only() {
                status_desc_item_opt = Some(desc_item);
                break;
            }
        }

        if let Some(status_desc_item) = status_desc_item_opt {
            if status_desc_item.len >= std::mem::size_of::<VirtioCryptoResponse>() as u32 {
                if let Err(e) = mem.write_obj(response, status_desc_item.addr) {
                    error!("CRYPTO: Failed to write response status: {:?}", e);
                }
            } else {
                error!("CRYPTO: Status descriptor (idx {}) too small for response.", status_desc_item.index);
            }
        } else {
            error!("CRYPTO: No writable descriptor found in chain for status response.");
        }
        // The length added to the used ring should be the size of the response written.
        // The caller (process_control_queue / process_data_queue) will call add_used.
    }

    /// Processes a data virtqueue.
    /// Returns true if the queue processing loop should continue.
    pub fn process_data_queue(&mut self, queue_idx: usize) -> bool {
        if !self.is_activated() {
            warn!("CRYPTO: Tried to process data queue {} on inactive device.", queue_idx);
            return false;
        }
        if queue_idx == 0 || queue_idx >= self.queues.len() {
            error!("CRYPTO: Invalid data queue index {}.", queue_idx);
            return false;
        }

        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => unreachable!("Device is activated but no memory available"),
        };

        let data_queue = &mut self.queues[queue_idx];
        let mut used_any = false;

        while let Some(chain) = data_queue.pop() {
            let status = match parse_request_header(mem, &chain) {
                Ok(header) => {
                    // Dispatch based on the higher bits of opcode (service type)
                    match header.opcode & 0xFF00 { // Mask to get service type part
                        VIRTIO_CRYPTO_CIPHER_REQ => self.handle_cipher_request(&chain, header),
                        VIRTIO_CRYPTO_MAC_REQ => self.handle_mac_request(&chain, header),
                        _ => {
                            warn!("CRYPTO: Unsupported data queue opcode: {:#0x}", header.opcode);
                            Err(VirtioCryptoError::UnsupportedOpcode(header.opcode))
                        }
                    }
                }
                Err(e) => {
                    error!("CRYPTO: Failed to parse data request header: {:?}", e);
                    Err(e)
                }
            };
            // Data queue responses are also just a status byte.
            self.write_response(&chain, status, queue_idx);
            data_queue.add_used(chain.index,).expect("Failed to add used for data queue");
            used_any = true;
        }

        if used_any {
            if data_queue.try_enable_notification() {
                 self.irq_trigger.trigger_irq(IrqType::Vring).expect("Failed to signal data queue");
            }
        }
        false
    }

    fn handle_cipher_request(&mut self, chain: &DescriptorChain, header: VirtioCryptoRequestHeader) -> Result<(), VirtioCryptoError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => return Err(VirtioCryptoError::DeviceNotActive),
        };

        let session_id = u64::from_le(header.session_id);
        // Get a mutable reference to the session.
        // `get_mut` is used because block-modes ciphers require `&mut self` for encryption/decryption.
        let session = self.sessions.get_mut(&session_id).ok_or(VirtioCryptoError::NoSuchSession)?;

        // Descriptor layout for cipher request (after common header):
        // 1. virtio_crypto_cipher_para
        // 2. IV
        // 3. Source data (one or more descriptors)
        // 4. Destination data (one or more descriptors)

        let mut desc_iter = chain.into_iter();
        let _header_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?; // Already parsed

        // Parse VirtioCryptoCipherPara
        let params_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?;
        if params_desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); }
        if params_desc_item.len < std::mem::size_of::<VirtioCryptoCipherPara>() as u32 {
            return Err(VirtioCryptoError::QueueDescriptorTooSmall(std::mem::size_of::<VirtioCryptoCipherPara>()));
        }
        let params: VirtioCryptoCipherPara = mem.read_obj(params_desc_item.addr)
            .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read cipher params".to_string()))?;

        let iv_len = u32::from_le(params.iv_len) as usize;
        let src_len = u32::from_le(params.src_len) as usize;
        let dst_len = u32::from_le(params.dst_len) as usize; // Guest's hint for dst buffer size

        if iv_len != 16 || src_len == 0 { // AES-CBC IV is 16 bytes
            return Err(VirtioCryptoError::InvalidParameters);
        }

        // Read IV
        let mut iv_data = vec![0u8; iv_len];
        let params_struct_size = std::mem::size_of::<VirtioCryptoCipherPara>();
        let mut bytes_of_iv_read = 0;

        if params_desc_item.len > params_struct_size as u32 { // IV might start in params_desc_item
            let iv_start_in_params_desc = params_desc_item.addr.checked_add(params_struct_size as u64)
                .ok_or(VirtioCryptoError::GuestMemory(GuestMemoryError::InvalidGuestAddress(params_desc_item.addr), "IV address overflow in params_desc".to_string()))?;
            let iv_bytes_in_params_desc = (params_desc_item.len - params_struct_size as u32) as usize;
            let to_read_from_params_desc = std::cmp::min(iv_bytes_in_params_desc, iv_len);
            
            mem.read_slice(&mut iv_data[..to_read_from_params_desc], iv_start_in_params_desc)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read IV from params_desc".to_string()))?;
            bytes_of_iv_read += to_read_from_params_desc;
        }

        while bytes_of_iv_read < iv_len {
            let iv_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?;
            if iv_desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); }
            let to_read = std::cmp::min(iv_desc_item.len as usize, iv_len - bytes_of_iv_read);
            mem.read_slice(&mut iv_data[bytes_of_iv_read .. bytes_of_iv_read + to_read], iv_desc_item.addr)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read IV from subsequent desc".to_string()))?;
            bytes_of_iv_read += to_read;
        }
         if bytes_of_iv_read < iv_len { return Err(VirtioCryptoError::DescriptorChainTooShort); }


        // Read Source Data (Scatter-gather)
        let mut src_data = vec![0u8; src_len];
        let mut total_src_bytes_read = 0;
        // Current desc_iter is positioned after IV descriptors.
        // We need to collect all readable descriptors that constitute source data.
        let mut src_desc_items = Vec::new();
        // The remaining descriptors in desc_iter could be for src or dst.
        // The virtio spec implies src descriptors come before dst descriptors.
        // We'll iterate and collect readable ones until src_len is met.
        
        // Re-iterate the chain from the beginning to correctly segment readable/writable for src/dst
        let mut full_chain_iter = chain.into_iter();
        // Skip header, params, and IV descriptors (assuming they were contiguous for simplicity of skipping)
        // A more robust way would be to count how many descriptors were consumed for header, params, IV.
        // For now, let's assume 1 for header, 1 for params, and enough for IV.
        // This part needs careful handling of descriptor iteration state.
        // Let's restart iteration and manually skip.
        let mut current_iter_for_src = chain.into_iter();
        current_iter_for_src.next(); // Skip header
        current_iter_for_src.next(); // Skip params_desc_item
        // Skip IV descriptors (this is simplified, assumes IV was read contiguously)
        let mut iv_descs_to_skip = (iv_len + (params_desc_item.len as usize - params_struct_size) -1) / AES_BLOCK_SIZE; // Rough estimate
        if params_desc_item.len <= params_struct_size as u32 { iv_descs_to_skip = (iv_len + AES_BLOCK_SIZE -1) / AES_BLOCK_SIZE; }


        for _ in 0..iv_descs_to_skip { current_iter_for_src.next(); }


        for desc_item in current_iter_for_src { // Iterate remaining for src and then dst
            if total_src_bytes_read < src_len {
                if desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); } // Src should be readable
                let to_read = std::cmp::min(desc_item.len as usize, src_len - total_src_bytes_read);
                mem.read_slice(&mut src_data[total_src_bytes_read .. total_src_bytes_read + to_read], desc_item.addr)
                    .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read src_data".to_string()))?;
                total_src_bytes_read += to_read;
                src_desc_items.push(desc_item); // Keep track for later to find start of dst
            } else {
                // Once src_data is fully read, the remaining descriptors are for dst
                break;
            }
        }
        if total_src_bytes_read < src_len { return Err(VirtioCryptoError::DescriptorChainTooShort); }


        let block_size = 16; // AES block size
        let max_possible_dst_len = if header.opcode == VIRTIO_CRYPTO_CIPHER_ENCRYPT {
            (src_len + block_size -1) / block_size * block_size // Padded length for encryption
        } else {
            src_len
        };

        if dst_len == 0 || (header.opcode == VIRTIO_CRYPTO_CIPHER_ENCRYPT && dst_len < max_possible_dst_len) || (header.opcode == VIRTIO_CRYPTO_CIPHER_DECRYPT && dst_len < src_len) {
             warn!("CRYPTO: dst_len {} might be problematic. src_len: {}, max_possible_dst_len for encrypt: {}", dst_len, src_len, max_possible_dst_len);
        }
        
        let mut temp_output_buffer = vec![0u8; max_possible_dst_len]; // Buffer for crypto op
        if header.opcode == VIRTIO_CRYPTO_CIPHER_ENCRYPT {
            temp_output_buffer[..src_len].copy_from_slice(&src_data);
        } else { // DECRYPT
             // For decrypt, src_data is ciphertext, copy it to temp_output_buffer up to its actual length (src_len)
            temp_output_buffer[..src_len].copy_from_slice(&src_data);
        }


        let iv_generic_array = GenericArray::from_slice(&iv_data);
        let processed_len = match header.opcode {
            VIRTIO_CRYPTO_CIPHER_ENCRYPT => {
                let enc_session = session.as_any_mut().downcast_mut::<AesCbcEncryptSession>().ok_or(VirtioCryptoError::CryptoOperationFailed)?;
                let result = enc_session.cipher.encrypt_padded_mut::<Pkcs7>(&mut temp_output_buffer, src_len)
                    .map_err(|_| VirtioCryptoError::CryptoOperationFailed)?; // block-modes PadError
                result.len()
            }
            VIRTIO_CRYPTO_CIPHER_DECRYPT => {
                let dec_session = session.as_any_mut().downcast_mut::<AesCbcDecryptSession>().ok_or(VirtioCryptoError::CryptoOperationFailed)?;
                let result = dec_session.cipher.decrypt_padded_mut::<Pkcs7>(&mut temp_output_buffer[..src_len])
                    .map_err(|_| VirtioCryptoError::CryptoOperationFailed)?; // block-modes UnpadError
                result.len()
            }
            _ => return Err(VirtioCryptoError::UnsupportedOpcode(header.opcode)),
        };

        // Write Destination Data (Scatter-gather)
        let mut total_dst_bytes_written = 0;
        // Re-iterate chain to find writable descriptors for dst, skipping those used for src
        let mut dst_iter = chain.into_iter();
        // Skip header, params, IV, and src descriptors
        dst_iter.next(); // header
        dst_iter.next(); // params
        for _ in 0..iv_descs_to_skip { dst_iter.next(); } // IV
        for _ in 0..src_desc_items.len() { dst_iter.next(); } // src data descriptors

        for desc_item in dst_iter {
            if total_dst_bytes_written >= processed_len { break; }
            if !desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedReadOnlyDescriptor); } // Dst should be writable
            
            let to_write = std::cmp::min(desc_item.len as usize, processed_len - total_dst_bytes_written);
            if to_write == 0 { continue; }

            mem.write_slice(&temp_output_buffer[total_dst_bytes_written .. total_dst_bytes_written + to_write], desc_item.addr)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to write dst_data".to_string()))?;
            total_dst_bytes_written += to_write;
        }
        if total_dst_bytes_written < processed_len { return Err(VirtioCryptoError::QueueDescriptorTooSmall(processed_len)); } // Not enough space in dst descriptors

        Ok(())
    }

    fn handle_mac_request(&mut self, chain: &DescriptorChain, header: VirtioCryptoRequestHeader) -> Result<(), VirtioCryptoError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            _ => return Err(VirtioCryptoError::DeviceNotActive),
        };

        let session_id = u64::from_le(header.session_id);
        let session = self.sessions.get_mut(&session_id).ok_or(VirtioCryptoError::NoSuchSession)?;

        // Descriptor layout for MAC request (after common header):
        // 1. virtio_crypto_mac_para
        // 2. Source data (one or more descriptors)
        // 3. MAC result (output for generate, input for verify)

        let mut desc_iter = chain.into_iter();
        let _header_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?; // Already parsed by caller

        // Parse VirtioCryptoMacPara
        let params_desc_item = desc_iter.next().ok_or(VirtioCryptoError::DescriptorChainTooShort)?;
        if params_desc_item.is_write_only() { return Err(VirtioCryptoError::UnexpectedWriteOnlyDescriptor); }
        if params_desc_item.len < std::mem::size_of::<VirtioCryptoMacPara>() as u32 {
            return Err(VirtioCryptoError::QueueDescriptorTooSmall(std::mem::size_of::<VirtioCryptoMacPara>()));
        }
        let params: VirtioCryptoMacPara = mem.read_obj(params_desc_item.addr)
            .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read MAC params".to_string()))?;

        let src_len = u32::from_le(params.src_len) as usize;
        let mac_len = u32::from_le(params.mac_len) as usize;

        if src_len == 0 {
            return Err(VirtioCryptoError::InvalidParameters);
        }

        // Read Source Data (Scatter-gather)
        let mut src_data = vec![0u8; src_len];
        let mut total_src_bytes_read = 0;
        // desc_iter is now positioned after params_desc_item.
        // Iterate through remaining descriptors to find source data.
        // The MAC result descriptor will be the last writable one in the *original* chain.
        
        // We need a mutable iterator to consume descriptors for src_data
        // The original desc_iter is consumed by .next() calls.
        // We need to restart iteration from after params_desc_item for src_data.
        let mut src_data_iter = chain.into_iter();
        src_data_iter.next(); // Skip header
        src_data_iter.next(); // Skip params

        for desc_item in src_data_iter {
            if total_src_bytes_read >= src_len {
                // If we encounter a writable one, it might be the mac_result_desc
                if desc_item.is_write_only() { break; }
            }
            if desc_item.is_write_only() { // Source data descriptors must be readable
                 // Found a writable descriptor before fully reading src_data
                break;
            }
            let to_read = std::cmp::min(desc_item.len as usize, src_len - total_src_bytes_read);
            mem.read_slice(&mut src_data[total_src_bytes_read .. total_src_bytes_read + to_read], desc_item.addr)
                .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read src_data for MAC".to_string()))?;
            total_src_bytes_read += to_read;
            if total_src_bytes_read >= src_len { break; } // Exit after reading enough for src_data
        }
        if total_src_bytes_read < src_len { return Err(VirtioCryptoError::DescriptorChainTooShort); }

        let hmac_session = session.as_any_mut().downcast_mut::<HmacSha256Session>().ok_or(VirtioCryptoError::CryptoOperationFailed)?;

        // Find the MAC result descriptor (last writable one in the original chain)
        let mut mac_result_desc_opt: Option<DescriptorChain> = None;
        for desc_item in chain.into_iter().collect::<Vec<_>>().into_iter().rev() { // Iterate original chain backwards
            if desc_item.is_write_only() {
                mac_result_desc_opt = Some(desc_item);
                break;
            }
        }
        let mac_result_desc = mac_result_desc_opt.ok_or(VirtioCryptoError::QueueDescriptorMissing)?;

        if mac_len != 32 { // HMAC-SHA256 output is 32 bytes
            warn!("CRYPTO: MAC length {} provided by guest is not 32 for HMAC-SHA256.", mac_len);
            return Err(VirtioCryptoError::InvalidParameters);
        }
        if mac_result_desc.len < mac_len as u32 {
            return Err(VirtioCryptoError::QueueDescriptorTooSmall(mac_len));
        }

        match header.opcode {
            VIRTIO_CRYPTO_MAC_GENERATE => {
                hmac_session.mac.update(&src_data);
                let result = <HmacSha256 as Mac>::finalize_reset(&mut hmac_session.mac);
                let computed_tag = result.into_bytes();

                if computed_tag.len() != mac_len {
                    error!("CRYPTO: Computed HMAC-SHA256 tag length {} does not match guest mac_len {}", computed_tag.len(), mac_len);
                    return Err(VirtioCryptoError::CryptoOperationFailed);
                }
                mem.write_slice(computed_tag.as_slice(), mac_result_desc.addr)
                    .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to write MAC result".to_string()))?;
                Ok(())
            }
            VIRTIO_CRYPTO_MAC_VERIFY => {
                let mut provided_tag = vec![0u8; mac_len];
                // For VERIFY, the guest provides the tag in mac_result_desc.
                // The descriptor flag VIRTQ_DESC_F_WRITE means device *may* write.
                // If not set, device *may* read. Guest should set it appropriately.
                // If guest set it as writable by device, it's an issue for verify.
                if mac_result_desc.is_write_only() {
                     warn!("CRYPTO: MAC_VERIFY reading from a descriptor (idx {}) marked as device-writable by guest.", mac_result_desc.index);
                }
                mem.read_slice(&mut provided_tag, mac_result_desc.addr)
                    .map_err(|e| VirtioCryptoError::GuestMemory(e, "Failed to read provided MAC for verification".to_string()))?;

                hmac_session.mac.update(&src_data);
                let verification_result = <HmacSha256 as Mac>::verify_slice_reset(&mut hmac_session.mac, &provided_tag);

                match verification_result {
                    Ok(()) => Ok(()),
                    Err(_) => Err(VirtioCryptoError::MacVerificationFailed),
                }
            }
            _ => {
                warn!("CRYPTO: Unexpected opcode {} in handle_mac_request", header.opcode);
                Err(VirtioCryptoError::UnsupportedOpcode(header.opcode))
            }
        }
    }
}

impl VirtioDevice for VirtioCrypto {
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
        TYPE_CRYPTO
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
            warn!("CRYPTO: Failed to read config space at offset {}", offset);
            // self.metrics.cfg_fails.inc(); // TODO
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Virtio-crypto config space is read-only by the driver.
        warn!(
            "CRYPTO: Guest attempted to write {} bytes to Crypto config space at offset {}, which is read-only.",
            data.len(),
            offset
        );
        // self.metrics.cfg_fails.inc(); // TODO
    }

    fn activate(&mut self, mem: GuestMemoryMmap<Option<AtomicBitmap>>) -> Result<(), ActivateError> {
        if self.is_activated() {
            warn!("CRYPTO: Device already activated.");
            return Ok(());
        }

        for q_idx in 0..self.queues.len() {
            self.queues[q_idx].initialize(&mem)
                .map_err(|e| {
                    error!("Failed to init queue {}: {:?}", q_idx, e);
                    ActivateError::QueueMemoryError(e)
                })?;
        }
        
        let event_idx = self.has_feature(crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX.into());
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        // TODO: Initialize crypto backend (e.g., RustCrypto contexts)
        // For a minimal direct Rust backend, we can assume it's "ready" once activated.
        // More complex backends (e.g., hardware offload) might have actual hardware readiness checks.
        self.config_space.status |= VIRTIO_CRYPTO_S_HW_READY.to_le();
        warn!("CRYPTO: Device activated. Backend assumed ready. VIRTIO_CRYPTO_S_HW_READY set.");


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
        // TODO: Perform any necessary cleanup, like clearing sessions.
        self.sessions.clear();
        self.next_session_id = 1;
        self.config_space.status = 0; // Clear HW_READY on reset
        warn!("CRYPTO: Resetting device. Sessions cleared, HW_READY status cleared.");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::{default_mem, VirtQueue};
    use crate::devices::virtio::queue::{Descriptor, DESC_F_NEXT, DESC_F_WRITE};
    use vm_memory::{GuestAddress, GuestMemory};

    // Helper to create a default crypto device for tests
    fn create_test_crypto_device() -> VirtioCrypto {
        VirtioCrypto::new(default_crypto_config()).unwrap()
    }

    // Helper to activate a device
    fn activate_device(device: &mut VirtioCrypto, mem: &GuestMemoryMmap) {
        device.activate(mem.clone()).unwrap();
        // Manually set queues to ready for testing processing logic directly
        for queue in device.queues_mut() {
            queue.set_ready(true);
        }
    }
    
    // Helper to build a descriptor chain for tests
    // This is a simplified version. A more complex one might be needed for varied scenarios.
    fn build_test_chain(
        mem: &GuestMemoryMmap,
        descriptors: Vec<(GuestAddress, u32, u16)>, // (addr, len, flags)
        queue_idx: usize,
        device: &mut VirtioCrypto,
    ) -> DescriptorChain {
        let vq = VirtQueue::new(GuestAddress(0), mem, 16); // Dummy address, size 16
        let mut desc_data = Vec::new();
        let mut next_idx = 0u16;

        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let mut current_flags = flags.clone();
            if i < descriptors.len() - 1 {
                current_flags |= DESC_F_NEXT;
                next_idx = (i + 1) as u16;
            } else {
                next_idx = 0; // No next for the last one, or could be loop if needed
            }
            let desc = Descriptor::new(addr.0, len.clone(), current_flags, next_idx);
            desc_data.push(desc);
            // Write descriptor to guest memory (simplified - assumes contiguous descriptor table)
            // In a real scenario, queue.add_descriptor_chain would handle this.
            // For direct pop testing, we need to manually set up the queue's internal state
            // or use a more integrated VirtQueue test utility.
            // For now, we'll assume the test directly calls process_x_queue with a manually constructed chain.
        }
        
        // This is a bit of a hack for testing. We are not fully simulating the virtqueue population.
        // We are creating a DescriptorChain directly.
        // The head_index would be 0 for this simple chain.
        // The device's queue needs to be populated correctly for `pop` to work.
        // For now, let's assume we are testing the `handle_` functions more directly
        // by constructing the chain and passing it.

        let queue = &mut device.queues[queue_idx];
        let head_idx = queue.add_chain(&desc_data).unwrap();
        
        queue.pop(mem).unwrap() // This will consume the chain we just added
    }


    fn default_crypto_config() -> VirtioCryptoConfig {
        VirtioCryptoConfig {
            crypto_id: "crypto_test_dev".to_string(),
            num_data_queues: 1,
        }
    }

    #[test]
    fn test_virtio_crypto_new() {
        let config = default_crypto_config();
        let crypto_dev = VirtioCrypto::new(config.clone()).unwrap();

        assert_eq!(crypto_dev.id, "crypto_test_dev");
        assert_eq!(crypto_dev.device_type(), TYPE_CRYPTO);
        assert_eq!(crypto_dev.queues.len(), CRYPTO_NUM_QUEUES);
        assert_eq!(crypto_dev.queue_evts.len(), CRYPTO_NUM_QUEUES);
        assert!(!crypto_dev.is_activated());

        // Check default config space values
        assert_eq!(crypto_dev.config_space.status, 0); // HW_READY not set yet
        assert_eq!(u32::from_le(crypto_dev.config_space.max_data_queues), 1);
        let expected_services = VIRTIO_CRYPTO_SERVICE_CIPHER | VIRTIO_CRYPTO_SERVICE_MAC;
        assert_eq!(u32::from_le(crypto_dev.config_space.crypto_services), expected_services);
        assert_eq!(u32::from_le(crypto_dev.config_space.cipher_algo_l), VIRTIO_CRYPTO_CIPHER_AES_CBC);
        assert_eq!(u32::from_le(crypto_dev.config_space.mac_algo_l), VIRTIO_CRYPTO_MAC_HMAC_SHA256);
        assert_eq!(u32::from_le(crypto_dev.config_space.max_cipher_key_len), 16);
        assert_eq!(u32::from_le(crypto_dev.config_space.max_auth_key_len), 32);
    }

    #[test]
    fn test_virtio_crypto_activate_reset() {
        let config = default_crypto_config();
        let mut crypto_dev = VirtioCrypto::new(config).unwrap();
        let mem = default_mem();

        assert!(!crypto_dev.is_activated());
        assert_eq!(u32::from_le(crypto_dev.config_space.status) & VIRTIO_CRYPTO_S_HW_READY, 0);

        crypto_dev.activate(mem).unwrap();
        assert!(crypto_dev.is_activated());
        assert_ne!(u32::from_le(crypto_dev.config_space.status) & VIRTIO_CRYPTO_S_HW_READY, 0);

        crypto_dev.reset();
        assert!(!crypto_dev.is_activated()); // Reset should deactivate or mark for re-init
        assert_eq!(u32::from_le(crypto_dev.config_space.status) & VIRTIO_CRYPTO_S_HW_READY, 0);
        assert!(crypto_dev.sessions.is_empty());
        assert_eq!(crypto_dev.next_session_id, 1);
    }

    #[test]
    fn test_virtio_crypto_read_write_config() {
        let config = default_crypto_config();
        let mut crypto_dev = VirtioCrypto::new(config).unwrap();
        
        // Read initial config
        let mut data = [0u8; std::mem::size_of::<CryptoConfigSpace>()];
        crypto_dev.read_config(0, &mut data);
        let initial_config_read: CryptoConfigSpace = unsafe { std::mem::transmute(data) };
        assert_eq!(initial_config_read.max_data_queues, 1u32.to_le()); // Check one field

        // Attempt to write (should be no-op and log warning)
        let new_val = 5u32.to_le_bytes();
        crypto_dev.write_config(offset_of!(CryptoConfigSpace, max_data_queues) as u64, &new_val);

        // Read again, should be unchanged
        crypto_dev.read_config(0, &mut data);
        let config_after_write: CryptoConfigSpace = unsafe { std::mem::transmute(data) };
        assert_eq!(config_after_write.max_data_queues, 1u32.to_le());
    }

    #[test]
    fn test_handle_create_cipher_session() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        let key = [0x42u8; 16];
        let header_addr = GuestAddress(0x1000);
        let params_addr = GuestAddress(0x1100);
        let key_addr = GuestAddress(0x1200);
        let status_addr = GuestAddress(0x1300);

        // Prepare request header
        let req_header = VirtioCryptoRequestHeader {
            opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION,
            session_id: 0, // Will be filled by device
            flags: 0,
            // other fields can be 0 for this test
            ..Default::default()
        };
        mem.write_obj(req_header, header_addr).unwrap();

        // Prepare session params
        let session_params = VirtioCryptoSessionParams {
            algo_param1: VIRTIO_CRYPTO_CIPHER_AES_CBC.to_le(), // Algorithm (e.g. AES_CBC)
            algo_param2: 0, // Operation (0 for encrypt, 1 for decrypt - placeholder)
            key_len: (key.len() as u32).to_le(),
            hash_mode: 0, // Not used for cipher
            // other fields 0
            ..Default::default()
        };
        mem.write_obj(session_params, params_addr).unwrap();
        mem.write_slice(&key, key_addr).unwrap();


        let descriptors = vec![
            (header_addr, std::mem::size_of::<VirtioCryptoRequestHeader>() as u32, 0), // Header (read-only)
            (params_addr, std::mem::size_of::<VirtioCryptoSessionParams>() as u32, 0), // Params (read-only)
            (key_addr, key.len() as u32, 0), // Key (read-only)
            (status_addr, std::mem::size_of::<VirtioCryptoResponse>() as u32, DESC_F_WRITE), // Status (write-only)
        ];
        
        // Manually build chain for direct handle_create_session testing
        // This bypasses queue.pop() for more direct unit testing of the handler.
        let mut chain_descs = Vec::new();
        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < descriptors.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < descriptors.len() - 1 { current_flags |= DESC_F_NEXT; }
            chain_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let chain = DescriptorChain::new(&chain_descs, 0, &mem).unwrap();


        let result = device.handle_create_session(&chain, req_header);
        assert!(result.is_ok());
        assert_eq!(device.sessions.len(), 1);
        assert_eq!(device.next_session_id, 2); // Incremented after first session

        // Check if session_id was written back to header
        let written_header: VirtioCryptoRequestHeader = mem.read_obj(header_addr).unwrap();
        assert_eq!(u64::from_le(written_header.session_id), 1); // First session ID

        // Check response status
        let response: VirtioCryptoResponse = mem.read_obj(status_addr).unwrap();
        // We are not calling write_response directly here, so status_addr won't be written by this test setup.
        // This test focuses on the session creation logic itself.
        // To test write_response, we'd call process_control_queue.
    }

    #[test]
    fn test_handle_create_mac_session() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        let key = [0xABu8; 32]; // HMAC-SHA256 key
        let header_addr = GuestAddress(0x2000);
        let params_addr = GuestAddress(0x2100);
        let key_addr = GuestAddress(0x2200);

        let req_header = VirtioCryptoRequestHeader {
            opcode: VIRTIO_CRYPTO_MAC_CREATE_SESSION,
            session_id: 0,
            ..Default::default()
        };
        mem.write_obj(req_header, header_addr).unwrap();

        let session_params = VirtioCryptoSessionParams {
            algo_param1: VIRTIO_CRYPTO_MAC_HMAC_SHA256.to_le(),
            key_len: (key.len() as u32).to_le(),
            ..Default::default()
        };
        mem.write_obj(session_params, params_addr).unwrap();
        mem.write_slice(&key, key_addr).unwrap();

        let descriptors = vec![
            (header_addr, std::mem::size_of::<VirtioCryptoRequestHeader>() as u32, 0),
            (params_addr, std::mem::size_of::<VirtioCryptoSessionParams>() as u32, 0),
            (key_addr, key.len() as u32, 0),
            // No explicit status descriptor needed if testing handle_create_session directly
        ];
        let mut chain_descs = Vec::new();
        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < descriptors.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < descriptors.len() - 1 { current_flags |= DESC_F_NEXT; }
            chain_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let chain = DescriptorChain::new(&chain_descs, 0, &mem).unwrap();

        let result = device.handle_create_session(&chain, req_header);
        assert!(result.is_ok());
        assert_eq!(device.sessions.len(), 1);
        let session = device.sessions.get(&1).unwrap(); // session_id should be 1
        assert_eq!(session.algorithm(), CryptoAlgorithm::HmacSha256);
    }

    #[test]
    fn test_handle_destroy_session() {
        let mut device = create_test_crypto_device();
        let mem = default_mem(); // Not strictly needed for destroy if not using chain
        activate_device(&mut device, &mem);


        // First, create a session to destroy
        let key = [0x11u8; 16];
        let create_req_header = VirtioCryptoRequestHeader {
            opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, session_id: 0, flags: 0, ..Default::default()
        };
        let create_session_params = VirtioCryptoSessionParams {
            algo_param2: 0, key_len: (key.len() as u32).to_le(), ..Default::default()
        };
        // Simplified setup for create, assuming direct call or pre-population
        let dummy_addr = GuestAddress(0x3000);
        mem.write_obj(create_req_header, dummy_addr).unwrap();
        mem.write_obj(create_session_params, dummy_addr.checked_add(100).unwrap()).unwrap();
        mem.write_slice(&key, dummy_addr.checked_add(200).unwrap()).unwrap();

        let create_descriptors = vec![
            (dummy_addr, std::mem::size_of::<VirtioCryptoRequestHeader>() as u32, 0),
            (dummy_addr.checked_add(100).unwrap(), std::mem::size_of::<VirtioCryptoSessionParams>() as u32, 0),
            (dummy_addr.checked_add(200).unwrap(), key.len() as u32, 0),
        ];
        let mut create_chain_descs = Vec::new();
         for (i, (addr, len, flags)) in create_descriptors.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descriptors.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descriptors.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_chain_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_chain_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        assert_eq!(device.sessions.len(), 1);
        let session_id_to_destroy = 1u64; // First session created

        // Now, prepare destroy request
        let destroy_req_header = VirtioCryptoRequestHeader {
            opcode: VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION,
            session_id: session_id_to_destroy.to_le(), // ID of session to destroy
            ..Default::default()
        };
        // Dummy chain for destroy, as it only uses the header's session_id
        let dummy_destroy_chain = DescriptorChain::new(&[Descriptor::new(0,0,0,0)], 0, &mem).unwrap_err(); // This will error, but we don't use it.
                                                                                                    // We need a valid chain if process_control_queue is called.
                                                                                                    // For direct handle_destroy_session, chain content doesn't matter much.

        let result = device.handle_destroy_session(&create_chain, destroy_req_header); // Can reuse create_chain as placeholder
        assert!(result.is_ok());
        assert!(device.sessions.is_empty());

        // Try to destroy non-existent session
        let result_non_existent = device.handle_destroy_session(&create_chain, destroy_req_header); // Try destroying same ID again
        assert!(matches!(result_non_existent, Err(VirtioCryptoError::NoSuchSession)));
    }

    // Known Answer Tests (KATs)

    const AES_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    const AES_IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const AES_PLAINTEXT_32B: [u8; 32] = [ // Two blocks
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    ];
    const AES_CIPHERTEXT_32B_PKCS7: [u8; 32] = [ // PKCS7 padding doesn't add a block if input is multiple of block size
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    ];
     const AES_PLAINTEXT_40B: [u8; 40] = [ // Two full blocks, one partial
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    ];
    const AES_CIPHERTEXT_48B_PKCS7: [u8; 48] = [ // Padded to 3 blocks
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    ];


    fn setup_cipher_kat_request(
        mem: &GuestMemoryMmap,
        _device: &mut VirtioCrypto, // Not strictly needed if we build chain manually for handle_cipher_request
        session_id: u64,
        opcode: u32, // VIRTIO_CRYPTO_CIPHER_ENCRYPT or VIRTIO_CRYPTO_CIPHER_DECRYPT
        iv: &[u8],
        src_data: &[u8],
        dst_buffer_len: usize, // Guest's allocated destination buffer length
    ) -> (VirtioCryptoRequestHeader, DescriptorChain, GuestAddress) {
        let header_addr = GuestAddress(0x4000);
        let params_addr = GuestAddress(0x4100);
        let iv_addr = GuestAddress(0x4200);
        let src_addr = GuestAddress(0x4300);
        let dst_addr = GuestAddress(0x4400); // Ensure enough space from src_addr
        let status_addr = GuestAddress(0x4800); // Further ensure space

        let req_header = VirtioCryptoRequestHeader {
            opcode,
            session_id: session_id.to_le(),
            flags: 0,
            ..Default::default()
        };
        mem.write_obj(req_header, header_addr).unwrap();

        let cipher_params = VirtioCryptoCipherPara {
            iv_len: (iv.len() as u32).to_le(),
            src_len: (src_data.len() as u32).to_le(),
            dst_len: (dst_buffer_len as u32).to_le(), // Guest indicates how much space it allocated
        };
        mem.write_obj(cipher_params, params_addr).unwrap();
        mem.write_slice(iv, iv_addr).unwrap();
        mem.write_slice(src_data, src_addr).unwrap();
        // Destination buffer is zeroed by guest, or we can do it for test clarity
        mem.write_slice(&vec![0u8; dst_buffer_len], dst_addr).unwrap();


        let descriptors = vec![
            (header_addr, std::mem::size_of::<VirtioCryptoRequestHeader>() as u32, 0),
            (params_addr, std::mem::size_of::<VirtioCryptoCipherPara>() as u32, 0),
            (iv_addr, iv.len() as u32, 0),
            (src_addr, src_data.len() as u32, 0),
            (dst_addr, dst_buffer_len as u32, DESC_F_WRITE),
            (status_addr, std::mem::size_of::<VirtioCryptoResponse>() as u32, DESC_F_WRITE),
        ];

        let mut chain_descs = Vec::new();
        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < descriptors.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < descriptors.len() - 1 { current_flags |= DESC_F_NEXT; }
            chain_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let chain = DescriptorChain::new(&chain_descs, 0, &mem).unwrap();
        
        (req_header, chain, dst_addr)
    }

    #[test]
    fn test_aes_cbc_encrypt_kat_32b() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // 1. Create Encrypt Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { algo_param2: 0, key_len: (AES_KEY.len() as u32).to_le(), ..Default::default() }; // algo_param2 = 0 for encrypt
        let ch_addr = GuestAddress(0x5000);
        let cp_addr = GuestAddress(0x5100);
        let ck_addr = GuestAddress(0x5200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&AES_KEY, ck_addr).unwrap();
        let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, AES_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1; // First session

        // 2. Perform Encryption
        let (enc_header, enc_chain, dst_addr) = setup_cipher_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_CIPHER_ENCRYPT,
            &AES_IV, &AES_PLAINTEXT_32B, AES_CIPHERTEXT_32B_PKCS7.len()
        );
        let result = device.handle_cipher_request(&enc_chain, enc_header);
        assert!(result.is_ok(), "Encryption failed: {:?}", result.err());

        let mut output_buffer = vec![0u8; AES_CIPHERTEXT_32B_PKCS7.len()];
        mem.read_slice(&mut output_buffer, dst_addr).unwrap();
        assert_eq!(output_buffer, AES_CIPHERTEXT_32B_PKCS7);
    }

    #[test]
    fn test_aes_cbc_decrypt_kat_32b() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // 1. Create Decrypt Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, ..Default::default() };
        // algo_param2 = 1 for decrypt (placeholder, actual value might differ based on spec)
        let create_params = VirtioCryptoSessionParams { algo_param2: 1, key_len: (AES_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0x6000);
        let cp_addr = GuestAddress(0x6100);
        let ck_addr = GuestAddress(0x6200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&AES_KEY, ck_addr).unwrap();
         let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, AES_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // 2. Perform Decryption
        let (dec_header, dec_chain, dst_addr) = setup_cipher_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_CIPHER_DECRYPT,
            &AES_IV, &AES_CIPHERTEXT_32B_PKCS7, AES_PLAINTEXT_32B.len()
        );
        let result = device.handle_cipher_request(&dec_chain, dec_header);
        assert!(result.is_ok(), "Decryption failed: {:?}", result.err());

        let mut output_buffer = vec![0u8; AES_PLAINTEXT_32B.len()];
        mem.read_slice(&mut output_buffer, dst_addr).unwrap();
        assert_eq!(output_buffer, AES_PLAINTEXT_32B);
    }
    
    #[test]
    fn test_aes_cbc_encrypt_kat_40b_padded() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // Create Encrypt Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { algo_param2: 0, key_len: (AES_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0x5000); // Reuse addresses if tests are independent
        let cp_addr = GuestAddress(0x5100);
        let ck_addr = GuestAddress(0x5200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&AES_KEY, ck_addr).unwrap();
        let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, AES_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // Perform Encryption
        let (enc_header, enc_chain, dst_addr) = setup_cipher_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_CIPHER_ENCRYPT,
            &AES_IV, &AES_PLAINTEXT_40B, AES_CIPHERTEXT_48B_PKCS7.len()
        );
        let result = device.handle_cipher_request(&enc_chain, enc_header);
        assert!(result.is_ok(), "Encryption (40B) failed: {:?}", result.err());

        let mut output_buffer = vec![0u8; AES_CIPHERTEXT_48B_PKCS7.len()];
        mem.read_slice(&mut output_buffer, dst_addr).unwrap();
        assert_eq!(output_buffer, AES_CIPHERTEXT_48B_PKCS7);
    }

    #[test]
    fn test_aes_cbc_decrypt_kat_48b_padded() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // Create Decrypt Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { algo_param2: 1, key_len: (AES_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0x6000); // Reuse addresses
        let cp_addr = GuestAddress(0x6100);
        let ck_addr = GuestAddress(0x6200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&AES_KEY, ck_addr).unwrap();
         let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, AES_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // Perform Decryption
        let (dec_header, dec_chain, dst_addr) = setup_cipher_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_CIPHER_DECRYPT,
            &AES_IV, &AES_CIPHERTEXT_48B_PKCS7, AES_PLAINTEXT_40B.len()
        );
        let result = device.handle_cipher_request(&dec_chain, dec_header);
        assert!(result.is_ok(), "Decryption (48B) failed: {:?}", result.err());

        let mut output_buffer = vec![0u8; AES_PLAINTEXT_40B.len()];
        mem.read_slice(&mut output_buffer, dst_addr).unwrap();
        assert_eq!(output_buffer, AES_PLAINTEXT_40B);
    }

    const HMAC_KEY: [u8; 4] = *b"Jefe"; // Test key from RFC 2202 (using a shorter key for simplicity, full key is 20 bytes "Jefe")
                                       // RustCrypto's Hmac<Sha256> handles keys of various lengths correctly.
    const HMAC_DATA: [u8; 28] = *b"what do ya want for nothing?";
    // Expected tag for HMAC-SHA256 with key "Jefe" and data "what do ya want for nothing?"
    // This specific tag is for the key "Jefe" (4 bytes).
    // If using the full 20-byte key "Jefe" padded with zeros, the tag would be different.
    // For simplicity and to match common test vectors, we use the 4-byte key.
    const HMAC_SHA256_TAG_FOR_JEFE: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    ];


    fn setup_mac_kat_request(
        mem: &GuestMemoryMmap,
        _device: &mut VirtioCrypto, // Not strictly needed for direct handle_mac_request test
        session_id: u64,
        opcode: u32, // VIRTIO_CRYPTO_MAC_GENERATE or VIRTIO_CRYPTO_MAC_VERIFY
        src_data: &[u8],
        mac_buffer_len: usize, // Guest's allocated MAC buffer length
        mac_data_for_verify: Option<&[u8]>, // MAC tag to write for verification
    ) -> (VirtioCryptoRequestHeader, DescriptorChain, GuestAddress) {
        let header_addr = GuestAddress(0x7000);
        let params_addr = GuestAddress(0x7100);
        let src_addr = GuestAddress(0x7200);
        let mac_result_addr = GuestAddress(0x7300); // Ensure enough space from src_addr
        let status_addr = GuestAddress(0x7800); // Further ensure space

        let req_header = VirtioCryptoRequestHeader {
            opcode,
            session_id: session_id.to_le(),
            flags: 0,
            ..Default::default()
        };
        mem.write_obj(req_header, header_addr).unwrap();

        let mac_params = VirtioCryptoMacPara {
            src_len: (src_data.len() as u32).to_le(),
            mac_len: (mac_buffer_len as u32).to_le(),
        };
        mem.write_obj(mac_params, params_addr).unwrap();
        mem.write_slice(src_data, src_addr).unwrap();

        // For MAC_VERIFY, the guest provides the MAC tag in the mac_result_addr buffer.
        // For MAC_GENERATE, the device writes the MAC tag to mac_result_addr.
        if opcode == VIRTIO_CRYPTO_MAC_VERIFY {
            if let Some(tag) = mac_data_for_verify {
                assert_eq!(tag.len(), mac_buffer_len, "Provided tag length for verify must match mac_buffer_len");
                mem.write_slice(tag, mac_result_addr).unwrap();
            } else {
                // If no tag provided for verify (e.g. testing error case), zero the buffer
                mem.write_slice(&vec![0u8; mac_buffer_len], mac_result_addr).unwrap();
            }
        } else { // For MAC_GENERATE, zero out the guest's buffer for clarity
            mem.write_slice(&vec![0u8; mac_buffer_len], mac_result_addr).unwrap();
        }


        let descriptors = vec![
            (header_addr, std::mem::size_of::<VirtioCryptoRequestHeader>() as u32, 0),
            (params_addr, std::mem::size_of::<VirtioCryptoMacPara>() as u32, 0),
            (src_addr, src_data.len() as u32, 0),
            // For MAC_VERIFY, mac_result_addr is read by device. For MAC_GENERATE, it's written.
            // The DESC_F_WRITE flag means the device *may* write to it.
            (mac_result_addr, mac_buffer_len as u32, DESC_F_WRITE),
            (status_addr, std::mem::size_of::<VirtioCryptoResponse>() as u32, DESC_F_WRITE),
        ];
        
        let mut chain_descs = Vec::new();
        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < descriptors.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < descriptors.len() - 1 { current_flags |= DESC_F_NEXT; }
            chain_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let chain = DescriptorChain::new(&chain_descs, 0, &mem).unwrap();

        (req_header, chain, mac_result_addr)
    }


    #[test]
    fn test_hmac_sha256_generate_kat() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // 1. Create HMAC Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_MAC_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { key_len: (HMAC_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0x8000);
        let cp_addr = GuestAddress(0x8100);
        let ck_addr = GuestAddress(0x8200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&HMAC_KEY, ck_addr).unwrap();
        let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, HMAC_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // 2. Perform MAC Generation
        let (mac_header, mac_chain, mac_result_addr) = setup_mac_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_MAC_GENERATE,
            &HMAC_DATA, HMAC_SHA256_TAG_FOR_JEFE.len(), None
        );
        let result = device.handle_mac_request(&mac_chain, mac_header);
        assert!(result.is_ok(), "MAC Generation failed: {:?}", result.err());

        let mut output_buffer = vec![0u8; HMAC_SHA256_TAG_FOR_JEFE.len()];
        mem.read_slice(&mut output_buffer, mac_result_addr).unwrap();
        assert_eq!(output_buffer, HMAC_SHA256_TAG_FOR_JEFE);
    }

    #[test]
    fn test_hmac_sha256_verify_kat_ok() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // 1. Create HMAC Session (same as generate)
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_MAC_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { key_len: (HMAC_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0x9000);
        let cp_addr = GuestAddress(0x9100);
        let ck_addr = GuestAddress(0x9200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&HMAC_KEY, ck_addr).unwrap();
        let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, HMAC_KEY.len() as u32, 0),
        ];
         let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // 2. Perform MAC Verification (Correct Tag)
        let (mac_header, mac_chain, _mac_result_addr) = setup_mac_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_MAC_VERIFY,
            &HMAC_DATA, HMAC_SHA256_TAG_FOR_JEFE.len(), Some(&HMAC_SHA256_TAG_FOR_JEFE)
        );
        let result = device.handle_mac_request(&mac_chain, mac_header);
        assert!(result.is_ok(), "MAC Verification (Correct Tag) failed: {:?}", result.err());
    }

    #[test]
    fn test_hmac_sha256_verify_kat_fail() {
        let mut device = create_test_crypto_device();
        let mem = default_mem();
        activate_device(&mut device, &mem);

        // 1. Create HMAC Session
        let create_req_header = VirtioCryptoRequestHeader { opcode: VIRTIO_CRYPTO_MAC_CREATE_SESSION, ..Default::default() };
        let create_params = VirtioCryptoSessionParams { key_len: (HMAC_KEY.len() as u32).to_le(), ..Default::default() };
        let ch_addr = GuestAddress(0xA000);
        let cp_addr = GuestAddress(0xA100);
        let ck_addr = GuestAddress(0xA200);
        mem.write_obj(create_req_header, ch_addr).unwrap();
        mem.write_obj(create_params, cp_addr).unwrap();
        mem.write_slice(&HMAC_KEY, ck_addr).unwrap();
        let create_descs_tuples = vec![
            (ch_addr, std::mem::size_of_val(&create_req_header) as u32, 0),
            (cp_addr, std::mem::size_of_val(&create_params) as u32, 0),
            (ck_addr, HMAC_KEY.len() as u32, 0),
        ];
        let mut create_descs = Vec::new();
        for (i, (addr, len, flags)) in create_descs_tuples.iter().enumerate() {
            let mut current_flags = *flags;
            let next_idx = if i < create_descs_tuples.len() - 1 { (i + 1) as u16 } else { 0 };
            if i < create_descs_tuples.len() - 1 { current_flags |= DESC_F_NEXT; }
            create_descs.push(Descriptor::new(addr.0, *len, current_flags, next_idx));
        }
        let create_chain = DescriptorChain::new(&create_descs, 0, &mem).unwrap();
        device.handle_create_session(&create_chain, create_req_header).unwrap();
        let session_id = 1;

        // 2. Perform MAC Verification (Incorrect Tag)
        let mut incorrect_tag = HMAC_SHA256_TAG_FOR_JEFE.clone();
        incorrect_tag[0] ^= 0xff; // Flip some bits in the tag

        let (mac_header, mac_chain, _mac_result_addr) = setup_mac_kat_request(
            &mem, &mut device, session_id, VIRTIO_CRYPTO_MAC_VERIFY,
            &HMAC_DATA, incorrect_tag.len(), Some(&incorrect_tag)
        );
        let result = device.handle_mac_request(&mac_chain, mac_header);
        assert!(matches!(result, Err(VirtioCryptoError::MacVerificationFailed)));
    }
}