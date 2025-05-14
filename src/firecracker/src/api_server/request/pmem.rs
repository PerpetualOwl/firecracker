// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::Body;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::pmem::PmemDeviceConfig; // Assuming this path is correct

use crate::api_server::parsed_request::{
    checked_id, method_to_error, ParsedRequest, RequestError,
};

pub(crate) fn parse_put_pmem(
    body: &Body,
    drive_id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match drive_id_from_path {
        Some(id) => {
            let checked_drive_id = checked_id(id)?;
            let pmem_config: PmemDeviceConfig = serde_json::from_slice(body.raw()).map_err(|e| {
                RequestError::SerdeJson(e)
            })?;

            if checked_drive_id != pmem_config.drive_id.as_str() {
                return Err(RequestError::Generic(
                    super::super::StatusCode::BadRequest,
                    "Path drive_id does not match body drive_id.".to_string()
                ));
            }
            Ok(ParsedRequest::new_sync(VmmAction::InsertPmemDevice(
                pmem_config,
            )))
        }
        None => {
            // This case should ideally be caught by the router regex,
            // but as a safeguard:
            Err(RequestError::Generic(
                super::super::StatusCode::BadRequest,
                "Pmem drive ID not specified in path.".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm::vmm_config::pmem::PmemDeviceConfig;

    #[test]
    fn test_parse_put_pmem_request() {
        let body = r#"{
                "drive_id": "pmem0",
                "path_on_host": "/path/to/file.img",
                "size_mib": 64,
                "is_read_only": false,
                "use_dax": true
            }"#;
        let result = parse_put_pmem(&Body::new(body), Some("pmem0"));
        assert!(result.is_ok());
        match result.unwrap().into_parts().0 {
            RequestAction::Sync(action) => match *action {
                VmmAction::InsertPmemDevice(config) => {
                    assert_eq!(config.drive_id, "pmem0");
                    assert_eq!(config.path_on_host, "/path/to/file.img");
                    assert_eq!(config.size_mib, 64);
                    assert!(!config.is_read_only);
                    assert!(config.use_dax);
                }
                _ => panic!("Wrong VmmAction type"),
            },
        }

        // Test ID mismatch
        let result_mismatch = parse_put_pmem(&Body::new(body), Some("pmem1"));
        assert!(result_mismatch.is_err());
        match result_mismatch.err().unwrap() {
            RequestError::Generic(_, msg) => {
                assert_eq!(msg, "Path drive_id does not match body drive_id.");
            }
            _ => panic!("Wrong error type"),
        }

        // Test missing ID in path
        let result_no_id = parse_put_pmem(&Body::new(body), None);
        assert!(result_no_id.is_err());
         match result_no_id.err().unwrap() {
            RequestError::Generic(_, msg) => {
                assert_eq!(msg, "Pmem drive ID not specified in path.");
            }
            _ => panic!("Wrong error type"),
        }

        // Test invalid body
        let invalid_body = r#"{ "invalid_field": "value" }"#;
        let result_invalid_body = parse_put_pmem(&Body::new(invalid_body), Some("pmem0"));
        assert!(result_invalid_body.is_err());
        match result_invalid_body.err().unwrap() {
            RequestError::SerdeJson(_) => {}
            _ => panic!("Wrong error type for invalid body"),
        }
    }
}