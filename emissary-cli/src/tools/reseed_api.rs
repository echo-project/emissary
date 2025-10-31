use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// const RESEED_HOST_BASE_URL: &str = "http://95.216.98.234:8080";
const RESEED_HOST_BASE_URL: &str = "http://127.0.0.1:8080";

/// Response structure for the keys API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticSigningKeysResponse {
    pub static_key: String,
    pub signing_key: String,
    pub router_id: String,
}

/// Request structure for updating router info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRouterInfoRequest {
    pub static_key: String,
    pub signing_key: String,
    pub padding: String,
    pub router_id: String,
}

/// Response structure for the router-info API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRouterInfoResponse {
    pub status: String,
    pub router_id: String,
    pub ip_address: String,
}

/// Request structure for storing netdb data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreNetdbRequest {
    pub router_id: String,
    pub netdb_data: String,
}

/// Response structure for the store-netdb API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreNetdbResponse {
    pub status: String,
    pub router_id: String,
    pub netdb_data: String,
}

async fn get_static_signing_keys_async() -> Result<StaticSigningKeysResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!("{}/api/v1/keys", RESEED_HOST_BASE_URL);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send request to {}: {}", url, e))?;

    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        return Err(anyhow!(
            "Server returned error status {}: {}",
            status,
            response_text
        ));
    }

    let key_response: StaticSigningKeysResponse = serde_json::from_str(&response_text)
        .map_err(|e| anyhow!("Failed to parse response as JSON: {}", e))?;

    Ok(key_response)
}

/// Fetches keys from the reseed API server.
///
/// Makes a GET request to `/api/v1/keys` endpoint and returns the generated keys.
/// This is a synchronous function that internally uses a tokio runtime to perform
/// the HTTP request.
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails
/// - The server returns a non-success status code
/// - The response cannot be parsed as JSON
/// - The response is missing required fields
pub fn get_static_signing_keys() -> Result<StaticSigningKeysResponse> {
    // Try to use the current tokio runtime handle if available
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already in a tokio runtime, so we can't use block_on directly.
            // Instead, spawn a new thread with its own runtime to avoid conflicts.
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .expect("Failed to create tokio runtime");
                rt.block_on(get_static_signing_keys_async())
            })
            .join()
            .map_err(|_| anyhow!("Thread panicked while fetching keys"))?
        }
        Err(_) => {
            // No runtime available, create a new one
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;
            rt.block_on(get_static_signing_keys_async())
        }
    }
}

async fn update_router_id_async(request: UpdateRouterInfoRequest) -> Result<UpdateRouterInfoResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!("{}/api/v1/router-info", RESEED_HOST_BASE_URL);

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send request to {}: {}", url, e))?;

    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        // Try to parse error response
        if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&response_text) {
            if let Some(error_msg) = error_json.get("error").and_then(|v| v.as_str()) {
                return Err(anyhow!(
                    "Server returned error status {}: {}",
                    status,
                    error_msg
                ));
            }
        }
        return Err(anyhow!(
            "Server returned error status {}: {}",
            status,
            response_text
        ));
    }

    let router_info_response: UpdateRouterInfoResponse = serde_json::from_str(&response_text)
        .map_err(|e| anyhow!("Failed to parse response as JSON: {}", e))?;

    Ok(router_info_response)
}

/// Updates router ID on the reseed API server.
///
/// Makes a POST request to `/api/v1/router-info` endpoint with the provided router info
/// and returns the update response. This is a synchronous function that internally uses
/// a tokio runtime to perform the HTTP request.
///
/// # Arguments
///
/// * `request` - The router info update request containing static_key, signing_key,
///   padding, and router_id
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails
/// - The server returns a non-success status code
/// - The response cannot be parsed as JSON
/// - The response is missing required fields
pub fn update_router_id(request: UpdateRouterInfoRequest) -> Result<UpdateRouterInfoResponse> {
    // Try to use the current tokio runtime handle if available
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already in a tokio runtime, so we can't use block_on directly.
            // Instead, spawn a new thread with its own runtime to avoid conflicts.
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .expect("Failed to create tokio runtime");
                rt.block_on(update_router_id_async(request))
            })
            .join()
            .map_err(|_| anyhow!("Thread panicked while updating router ID"))?
        }
        Err(_) => {
            // No runtime available, create a new one
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;
            rt.block_on(update_router_id_async(request))
        }
    }
}

async fn upload_net_db_async(request: StoreNetdbRequest) -> Result<StoreNetdbResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!("{}/api/v1/store-netdb", RESEED_HOST_BASE_URL);

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send request to {}: {}", url, e))?;

    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        // Try to parse error response
        if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&response_text) {
            if let Some(error_msg) = error_json.get("error").and_then(|v| v.as_str()) {
                return Err(anyhow!(
                    "Server returned error status {}: {}",
                    status,
                    error_msg
                ));
            }
        }
        return Err(anyhow!(
            "Server returned error status {}: {}",
            status,
            response_text
        ));
    }

    let store_netdb_response: StoreNetdbResponse = serde_json::from_str(&response_text)
        .map_err(|e| anyhow!("Failed to parse response as JSON: {}", e))?;

    Ok(store_netdb_response)
}

/// Uploads netdb data to the reseed API server.
///
/// Makes a POST request to `/api/v1/store-netdb` endpoint with the provided netdb data
/// and returns the store response. This is a synchronous function that internally uses
/// a tokio runtime to perform the HTTP request.
///
/// # Arguments
///
/// * `request` - The netdb store request containing router_id and netdb_data
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails
/// - The server returns a non-success status code
/// - The response cannot be parsed as JSON
/// - The response is missing required fields
pub fn upload_net_db(request: StoreNetdbRequest) -> Result<StoreNetdbResponse> {
    // Try to use the current tokio runtime handle if available
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already in a tokio runtime, so we can't use block_on directly.
            // Instead, spawn a new thread with its own runtime to avoid conflicts.
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .expect("Failed to create tokio runtime");
                rt.block_on(upload_net_db_async(request))
            })
            .join()
            .map_err(|_| anyhow!("Thread panicked while uploading netdb data"))?
        }
        Err(_) => {
            // No runtime available, create a new one
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;
            rt.block_on(upload_net_db_async(request))
        }
    }
}
