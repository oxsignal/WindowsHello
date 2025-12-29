use reqwest::Client;
use crate::types::{AuthRequest, ChallengeResponse};

pub struct NetworkManager {
    client: Client,
    base_url: String,
}

impl NetworkManager {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    /// Request a unique challenge (nonce) from the server
    pub async fn fetch_challenge(&self, key_name: &str) -> Result<ChallengeResponse, reqwest::Error> {
        let url = format!("{}/challenge?key_name={}", self.base_url, key_name);
        let response = self.client.get(&url).send().await?;
        
        // Ensure the response is successful before parsing JSON
        response.error_for_status()?.json().await
    }

    /// Send the signature and attestation data to the server for final verification
    pub async fn send_authentication(&self, auth_data: &AuthRequest) -> Result<String, reqwest::Error> {
        let url = format!("{}/authenticate", self.base_url);
        let response = self.client.post(&url)
            .json(auth_data)
            .send()
            .await?;

        // Return the server response body as a string
        response.error_for_status()?.text().await
    }
}