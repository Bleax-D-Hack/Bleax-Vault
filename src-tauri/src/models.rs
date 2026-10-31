use crate::os_memory::{lock_memory, unlock_memory};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct SecretString(pub String);

impl SecretString {
    pub fn new(s: String) -> Self {
        // Verrouillage de la capacité allouée (incluant le slack space) pour prévenir les fuites de padding
        lock_memory(s.as_ptr(), s.capacity());
        Self(s)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        unlock_memory(self.0.as_ptr(), self.0.capacity());

        self.0.zeroize();
    }
}

impl Default for SecretString {
    fn default() -> Self {
        SecretString::new(String::new())
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultPayload {
    pub schema_version: u32,
    pub vault_updated_at: i64,
    pub entries: Vec<VaultEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    pub id: String,
    pub last_modified: i64,
    pub title: String,
    pub content: EntryContent,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum EntryContent {
    Login {
        username: String,
        password: SecretString,
        url: Option<String>,
        totp_secret: Option<String>,
    },
    SecureNote {
        text: SecretString,
    },
}

impl VaultPayload {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            vault_updated_at: 0,
            entries: Vec::new(),
        }
    }

    pub fn to_masked(&self) -> VaultPayloadMasked {
        let masked_entries = self
            .entries
            .iter()
            .map(|e| match &e.content {
                EntryContent::Login {
                    username,
                    password,
                    url,
                    ..
                } => VaultEntryMasked {
                    id: e.id.clone(),
                    last_modified: e.last_modified,
                    title: e.title.clone(),
                    entry_type: "Login".to_string(),
                    username: Some(username.clone()),
                    url: url.clone(),
                    has_password: !password.0.is_empty(),
                    has_note: false,
                },
                EntryContent::SecureNote { text } => VaultEntryMasked {
                    id: e.id.clone(),
                    last_modified: e.last_modified,
                    title: e.title.clone(),
                    entry_type: "SecureNote".to_string(),
                    username: None,
                    url: None,
                    has_password: false,
                    has_note: !text.0.is_empty(),
                },
            })
            .collect();

        VaultPayloadMasked {
            schema_version: self.schema_version,
            vault_updated_at: self.vault_updated_at,
            entries: masked_entries,
        }
    }
}

#[derive(Serialize)]
pub struct VaultPayloadMasked {
    pub schema_version: u32,
    pub vault_updated_at: i64,
    pub entries: Vec<VaultEntryMasked>,
}

#[derive(Serialize)]
pub struct VaultEntryMasked {
    pub id: String,
    pub last_modified: i64,
    pub title: String,
    pub entry_type: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub has_password: bool,
    pub has_note: bool,
}
