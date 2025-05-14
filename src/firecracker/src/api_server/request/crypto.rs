// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::Body;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::crypto::VirtioCryptoConfig; // Path to the config struct

use crate::api_server::parsed_request::{
    checked_id, ParsedRequest, RequestError,
};

pub(crate) fn parse_put_crypto(
    body: &Body,
    crypto_id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match crypto_id_from_path {
        Some(id) => {
            let checked_crypto_id = checked_id(id)?;
            let crypto_config: VirtioCryptoConfig = serde_json::from_slice(body.raw()).map_err(|e| {
                RequestError::SerdeJson(e)
            })?;

            if checked_crypto_id != crypto_config.crypto_id.as_str() {
                return Err(RequestError::Generic(
                    super::super::StatusCode::BadRequest,
                    "Path crypto_id does not match body crypto_id.".to_string()
                ));
            }
            Ok(ParsedRequest::new_sync(VmmAction::InsertCryptoDevice( // Ensure this VmmAction variant exists
                crypto_config,
            )))
        }
        None => {
            Err(RequestError::Generic(
                super::super::StatusCode::BadRequest,
                "Crypto device ID not specified in path.".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm::vmm_config::crypto::VirtioCryptoConfig;

    #[test]
    fn test_parse_put_crypto_request() {
        let body = r#"{
                "crypto_id": "crypto0",
                "num_data_queues": 1
            }"#;
        let result = parse_put_crypto(&Body::new(body), Some("crypto0"));
        assert!(result.is_ok());
        match result.unwrap().into_parts().0 {
            RequestAction::Sync(action) => match *action {
                VmmAction::InsertCryptoDevice(config) => { // Ensure this VmmAction variant exists
                    assert_eq!(config.crypto_id, "crypto0");
                    assert_eq!(config.num_data_queues, 1);
                }
                _ => panic!("Wrong VmmAction type"),
            },
        }

        // Test ID mismatch
        let result_mismatch = parse_put_crypto(&Body::new(body), Some("crypto1"));
        assert!(result_mismatch.is_err());
        match result_mismatch.err().unwrap() {
            RequestError::Generic(_, msg) => {
                assert_eq!(msg, "Path crypto_id does not match body crypto_id.");
            }
            _ => panic!("Wrong error type"),
        }

        // Test missing ID in path
        let result_no_id = parse_put_crypto(&Body::new(body), None);
        assert!(result_no_id.is_err());
         match result_no_id.err().unwrap() {
            RequestError::Generic(_, msg) => {
                assert_eq!(msg, "Crypto device ID not specified in path.");
            }
            _ => panic!("Wrong error type"),
        }

        // Test invalid body
        let invalid_body = r#"{ "invalid_field": "value" }"#;
        let result_invalid_body = parse_put_crypto(&Body::new(invalid_body), Some("crypto0"));
        assert!(result_invalid_body.is_err());
        match result_invalid_body.err().unwrap() {
            RequestError::SerdeJson(_) => {}
            _ => panic!("Wrong error type for invalid body"),
        }

        // Test default num_data_queues
        let body_default_queues = r#"{
                "crypto_id": "crypto2"
            }"#;
        let result_default_queues = parse_put_crypto(&Body::new(body_default_queues), Some("crypto2"));
        assert!(result_default_queues.is_ok());
        match result_default_queues.unwrap().into_parts().0 {
            RequestAction::Sync(action) => match *action {
                VmmAction::InsertCryptoDevice(config) => {
                    assert_eq!(config.crypto_id, "crypto2");
                    assert_eq!(config.num_data_queues, 1); // Check default
                }
                _ => panic!("Wrong VmmAction type"),
            },
        }
    }
}