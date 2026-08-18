use keyring::{Entry, Error as KeyringError};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const APPLICATION_KEY_NAME: &str = "database-key-v1";
const APPLICATION_KEY_LEN: usize = 32;
const MAX_SECRET_LEN: usize = 64 * 1024;
const MAX_COMPONENT_LEN: usize = 128;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("credential vault is unavailable")]
    Credential(#[source] KeyringError),
    #[error("credential stored for {0} is invalid")]
    CorruptCredential(&'static str),
    #[error("invalid credential identifier")]
    InvalidIdentifier,
    #[error("secret must contain between 1 and {MAX_SECRET_LEN} bytes")]
    InvalidSecretLength,
}

/// OS-backed credential storage. The service name is public metadata; secret values are never
/// written to application configuration, logs, or the database.
#[derive(Debug, Clone)]
pub struct CredentialVault {
    service: String,
}

impl CredentialVault {
    pub fn new(service: impl Into<String>) -> Result<Self, VaultError> {
        let service = service.into();
        validate_component(&service)?;
        Ok(Self { service })
    }

    /// Loads the 256-bit application key, creating it with the operating system CSPRNG when this
    /// installation has no key yet. The returned allocation is wiped when dropped.
    pub fn load_or_create_application_key(
        &self,
    ) -> Result<Zeroizing<[u8; APPLICATION_KEY_LEN]>, VaultError> {
        let entry = self.entry(APPLICATION_KEY_NAME)?;
        match entry.get_secret() {
            Ok(mut stored) => {
                if stored.len() != APPLICATION_KEY_LEN {
                    stored.zeroize();
                    return Err(VaultError::CorruptCredential("application database key"));
                }
                let mut key = Zeroizing::new([0_u8; APPLICATION_KEY_LEN]);
                key.copy_from_slice(&stored);
                stored.zeroize();
                Ok(key)
            }
            Err(KeyringError::NoEntry) => {
                let mut key = Zeroizing::new([0_u8; APPLICATION_KEY_LEN]);
                OsRng.fill_bytes(key.as_mut());
                entry
                    .set_secret(key.as_ref())
                    .map_err(VaultError::Credential)?;
                Ok(key)
            }
            Err(error) => Err(VaultError::Credential(error)),
        }
    }

    /// Removes the database key from the OS vault. Existing encrypted data becomes unrecoverable.
    pub fn delete_application_key(&self) -> Result<(), VaultError> {
        self.delete_entry(APPLICATION_KEY_NAME)
    }

    pub fn set_secret(
        &self,
        account_id: &str,
        kind: &str,
        secret: &[u8],
    ) -> Result<(), VaultError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(VaultError::InvalidSecretLength);
        }
        let name = provider_secret_name(account_id, kind)?;
        self.entry(&name)?
            .set_secret(secret)
            .map_err(VaultError::Credential)
    }

    pub fn get_secret(
        &self,
        account_id: &str,
        kind: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let name = provider_secret_name(account_id, kind)?;
        match self.entry(&name)?.get_secret() {
            Ok(secret) => {
                if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
                    let mut secret = secret;
                    secret.zeroize();
                    return Err(VaultError::CorruptCredential("provider credential"));
                }
                Ok(Some(Zeroizing::new(secret)))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(VaultError::Credential(error)),
        }
    }

    pub fn delete_secret(&self, account_id: &str, kind: &str) -> Result<(), VaultError> {
        let name = provider_secret_name(account_id, kind)?;
        self.delete_entry(&name)
    }

    fn entry(&self, name: &str) -> Result<Entry, VaultError> {
        Entry::new(&self.service, name).map_err(VaultError::Credential)
    }

    fn delete_entry(&self, name: &str) -> Result<(), VaultError> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(VaultError::Credential(error)),
        }
    }
}

fn provider_secret_name(account_id: &str, kind: &str) -> Result<String, VaultError> {
    validate_component(account_id)?;
    validate_component(kind)?;
    Ok(format!("account:{account_id}:{kind}"))
}

fn validate_component(value: &str) -> Result<(), VaultError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
    {
        return Err(VaultError::InvalidIdentifier);
    }
    Ok(())
}
