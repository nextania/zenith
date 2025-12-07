use crate::dns_provider::DnsProvider;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, info};

#[derive(Clone)]
pub struct CloudflareClient {
    api_key: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

impl CloudflareClient {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            client,
        }
    }

    async fn get_zone_id(&self, domain: &str) -> Result<String> {
        let url = "https://api.cloudflare.com/client/v4/zones";
        let response = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", &self.api_key))
            .query(&[("name", domain)])
            .send()
            .await?;
        let cf_response: CloudflareResponse<Vec<Zone>> = response.json().await?;
        if !cf_response.success {
            return Err(anyhow!(
                "Cloudflare API error: {:?}",
                cf_response.errors
            ));
        }

        cf_response
            .result
            .and_then(|zones| zones.into_iter().next())
            .map(|zone| zone.id)
            .ok_or_else(|| anyhow!("Zone not found for domain: {}", domain))
    }

    pub async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        content: &str,
    ) -> Result<String> {
        info!("Creating TXT record: {} = {}", record_name, content);
        let zone_id = self.get_zone_id(domain).await?;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );
        let body = json!({
            "type": "TXT",
            "name": record_name,
            "content": content,
            "ttl": 120,
        });
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", &self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;
        if !cf_response.success {
            return Err(anyhow!(
                "Failed to create TXT record: {:?}",
                cf_response.errors
            ));
        }
        let record_id = cf_response
            .result
            .ok_or_else(|| anyhow!("No record ID in response"))?
            .id;
        debug!("Created TXT record with ID: {}", record_id);

        // Wait for DNS propagation
        tokio::time::sleep(Duration::from_secs(30)).await;

        Ok(record_id)
    }

    pub async fn delete_txt_record(
        &self,
        domain: &str,
        record_id: &str,
    ) -> Result<()> {
        info!("Deleting TXT record with ID: {}", record_id);
        let zone_id = self.get_zone_id(domain).await?;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        );
        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", &self.api_key))
            .send()
            .await?;
        let cf_response: CloudflareResponse<serde_json::Value> = response.json().await?;
        if !cf_response.success {
            return Err(anyhow!(
                "Failed to delete TXT record: {:?}",
                cf_response.errors
            ));
        }

        debug!("Successfully deleted TXT record");
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for CloudflareClient {
    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        content: &str,
    ) -> Result<String> {
        self.create_txt_record(domain, record_name, content).await
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        self.delete_txt_record(domain, record_id).await
    }

    fn provider_name(&self) -> &str {
        "Cloudflare"
    }
}
