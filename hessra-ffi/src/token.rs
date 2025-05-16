use std::ffi::CStr;
use std::os::raw::c_char;

use crate::config::HessraPublicKey;
use crate::error::HessraResult;

/// Parse a token from a string and verify it
#[no_mangle]
pub extern "C" fn hessra_token_verify(
    token_string: *const c_char,
    public_key: *mut HessraPublicKey,
    subject: *const c_char,
    resource: *const c_char,
    operation: *const c_char,
) -> HessraResult {
    if token_string.is_null() || public_key.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let c_str = unsafe { CStr::from_ptr(token_string) };
    let token_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_TOKEN,
    };

    let key_ref = unsafe { &*public_key };
    let public_key = match key_ref.public_key() {
        Some(k) => k,
        None => return HessraResult::ERROR_INVALID_KEY,
    };

    let subject_str = if !subject.is_null() {
        match unsafe { CStr::from_ptr(subject) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    let resource_str = if !resource.is_null() {
        match unsafe { CStr::from_ptr(resource) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    let operation_str = if !operation.is_null() {
        match unsafe { CStr::from_ptr(operation) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    // Handle optional parameters
    let subject_ref = subject_str.unwrap_or("");
    let resource_ref = resource_str.unwrap_or("");
    let operation_ref = operation_str.unwrap_or("");

    match hessra_token::verify_token_local(
        token_str,
        *public_key,
        subject_ref,
        resource_ref,
        operation_ref,
    ) {
        Ok(_) => HessraResult::SUCCESS,
        Err(err) => err.into(),
    }
}

/// Parse a token from a string with service chain validation
#[no_mangle]
pub extern "C" fn hessra_token_verify_service_chain(
    token_string: *const c_char,
    public_key: *mut HessraPublicKey,
    subject: *const c_char,
    resource: *const c_char,
    operation: *const c_char,
    service_nodes_json: *const c_char,
    component: *const c_char,
) -> HessraResult {
    if token_string.is_null() || public_key.is_null() || service_nodes_json.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let c_str = unsafe { CStr::from_ptr(token_string) };
    let token_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_TOKEN,
    };

    let key_ref = unsafe { &*public_key };
    let public_key = match key_ref.public_key() {
        Some(k) => k,
        None => return HessraResult::ERROR_INVALID_KEY,
    };

    let subject_str = if !subject.is_null() {
        match unsafe { CStr::from_ptr(subject) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    let resource_str = if !resource.is_null() {
        match unsafe { CStr::from_ptr(resource) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    let operation_str = if !operation.is_null() {
        match unsafe { CStr::from_ptr(operation) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    let c_nodes_json = unsafe { CStr::from_ptr(service_nodes_json) };
    let nodes_json = match c_nodes_json.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
    };

    let service_nodes: Vec<hessra_token::ServiceNode> = match serde_json::from_str(nodes_json) {
        Ok(nodes) => nodes,
        Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
    };

    let component_str = if !component.is_null() {
        match unsafe { CStr::from_ptr(component) }.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
        }
    } else {
        None
    };

    // Handle optional parameters
    let subject_ref = subject_str.unwrap_or("");
    let resource_ref = resource_str.unwrap_or("");
    let operation_ref = operation_str.unwrap_or("");

    match hessra_token::verify_service_chain_token_local(
        token_str,
        *public_key,
        subject_ref,
        resource_ref,
        operation_ref,
        service_nodes,
        component_str,
    ) {
        Ok(_) => HessraResult::SUCCESS,
        Err(err) => err.into(),
    }
}
