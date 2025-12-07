use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        content: &str,
    ) -> Result<String>;

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()>;

    fn provider_name(&self) -> &str;
}
