use crate::dns_provider::DnsProvider;
use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, info};
use x509_parser::pem::parse_x509_pem;

pub struct AcmeService {
    dns_provider: Arc<dyn DnsProvider>,
    account_email: String,
    use_production: bool,
}

pub struct CertificateResult {
    pub private_key: String,
    pub certificate: String,
    pub chain: String,
}

impl AcmeService {
    pub fn new(
        dns_provider: Arc<dyn DnsProvider>,
        account_email: String,
        use_production: bool,
    ) -> Self {
        Self {
            dns_provider,
            account_email,
            use_production,
        }
    }

    async fn get_or_create_account(&self, key_path: &Path) -> Result<(Account, AccountCredentials)> {
        if key_path.exists() {
            info!("Loading existing account credentials from {:?}", key_path);
            let credentials_pem = fs::read_to_string(key_path).await?;
            let credentials: AccountCredentials = serde_json::from_str(&credentials_pem)?;
            let account = Account::from_credentials(credentials).await?;
            let credentials_pem = fs::read_to_string(key_path).await?;
            let credentials: AccountCredentials = serde_json::from_str(&credentials_pem)?;
            
            Ok((account, credentials))
        } else {
            info!("Creating new ACME account");
            let url = if self.use_production {
                info!("Using Let's Encrypt production environment");
                LetsEncrypt::Production.url()
            } else {
                info!("Using Let's Encrypt staging environment");
                LetsEncrypt::Staging.url()
            };
            let (account, credentials) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.account_email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url,
                None,
            )
            .await?;

            let credentials_json = serde_json::to_string_pretty(&credentials)?;
            fs::write(key_path, credentials_json).await?;
            info!("ACME account created and saved");
            Ok((account, credentials))
        }
    }

    pub async fn request_certificate(
        &self,
        domains: Vec<String>,
        account_key_path: &Path,
        cert_key_path: &Path,
    ) -> Result<CertificateResult> {
        info!("Requesting certificate for domains: {:?}", domains);
        let (account, _credentials) = self.get_or_create_account(account_key_path).await?;
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();

        info!("Creating new order");
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await?;

        debug!("Order created, status: {:?}", order.state().status);
        let authorizations = order.authorizations().await?;
        for authz in &authorizations {
            debug!("Authorization status: {:?}", authz.status);
            if matches!(authz.status, instant_acme::AuthorizationStatus::Valid) {
                info!("Authorization already valid");
                continue;
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .ok_or_else(|| anyhow!("No DNS-01 challenge found"))?;

            info!("Processing DNS-01 challenge");
            let domain = match &authz.identifier {
                Identifier::Dns(d) => d,
            };
            let base_domain = self.get_base_domain(domain);
            let record_name = format!("_acme-challenge.{}", domain);
            let key_authorization = order.key_authorization(challenge).dns_value();
            let record_id = self
                .dns_provider
                .create_txt_record(&base_domain, &record_name, &key_authorization)
                .await?;

            info!("Validating challenge");
            order.set_challenge_ready(&challenge.url).await?;
            let mut attempts = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                order.refresh().await?;
                let state = order.state();
                debug!("Order status: {:?}", state.status);
                match state.status {
                    OrderStatus::Ready | OrderStatus::Valid => {
                        info!("Challenge validated successfully");
                        break;
                    }
                    OrderStatus::Invalid => {
                        self.dns_provider
                            .delete_txt_record(&base_domain, &record_id)
                            .await
                            .ok();
                        return Err(anyhow!("Challenge validation failed"));
                    }
                    OrderStatus::Pending | OrderStatus::Processing => {
                        attempts += 1;
                        if attempts > 30 {
                            self.dns_provider
                                .delete_txt_record(&base_domain, &record_id)
                                .await
                                .ok();
                            return Err(anyhow!("Challenge validation timeout"));
                        }
                    }
                }
            }
            self.dns_provider
                .delete_txt_record(&base_domain, &record_id)
                .await?;
        }

        info!("Generating certificate private key");
        let cert_key_pair = if cert_key_path.exists() {
            let pem = fs::read_to_string(cert_key_path).await?;
            KeyPair::from_pem(&pem)?
        } else {
            let key_pair = KeyPair::generate()?;
            fs::write(cert_key_path, key_pair.serialize_pem()).await?;
            key_pair
        };
        let mut params = CertificateParams::new(domains.clone())?;
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            domains[0].clone(),
        );
        let csr = params.serialize_request(&cert_key_pair)?;

        info!("Finalizing order");
        order.finalize(csr.der()).await?;
        let mut attempts = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            order.refresh().await?;
            let state = order.state();
            debug!("Order status: {:?}", state.status);
            match state.status {
                OrderStatus::Valid => {
                    info!("Certificate ready");
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(anyhow!("Order became invalid"));
                }
                _ => {
                    attempts += 1;
                    if attempts > 30 {
                        return Err(anyhow!("Certificate issuance timeout"));
                    }
                }
            }
        }
        let cert_chain_pem = order
            .certificate()
            .await?
            .ok_or_else(|| anyhow!("Certificate not available"))?;
        info!("Certificate issued successfully");

        let parts: Vec<&str> = cert_chain_pem.split("-----END CERTIFICATE-----").collect();
        let certificate = if !parts.is_empty() {
            format!("{}-----END CERTIFICATE-----", parts[0])
        } else {
            cert_chain_pem.clone()
        };
        let chain = if parts.len() > 1 {
            parts[1..].join("-----END CERTIFICATE-----")
        } else {
            String::new()
        };

        Ok(CertificateResult {
            private_key: cert_key_pair.serialize_pem(),
            certificate,
            chain,
        })
    }

    fn get_base_domain(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        }
    }

    pub async fn needs_renewal(&self, cert_path: &Path) -> Result<bool> {
        if !cert_path.exists() {
            return Ok(true);
        }

        let cert_pem = fs::read(cert_path).await?;
        let pem = parse_x509_pem(&cert_pem)
            .map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
        let cert = pem.1.parse_x509()
            .map_err(|e| anyhow!("Failed to parse X509 certificate: {}", e))?;
        let not_after = cert.validity().not_after;
        let expiration_timestamp = not_after.timestamp();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let seconds_remaining = expiration_timestamp - now;
        let days_remaining = seconds_remaining / 86400;
        
        info!("Certificate expires in {} days", days_remaining);
        
        if days_remaining < 30 {
            info!("Certificate needs renewal (less than 30 days remaining)");
            Ok(true)
        } else {
            info!("Certificate is still valid");
            Ok(false)
        }
    }
}
