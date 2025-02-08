use anyhow::Result;
use serde_json;
use std::fs;
use std::path::PathBuf;
use crate::supabase::Session;

#[derive(Clone, Debug)]
pub struct SessionStorage {
    file_path: PathBuf,
}

impl SessionStorage {
    pub fn new() -> Self {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("chronosync");
        fs::create_dir_all(&path).unwrap_or_default();
        path.push("session.json");
        
        Self {
            file_path: path,
        }
    }

    pub fn save_session(&self, session: &Session) -> Result<()> {
        let json = serde_json::to_string(session)?;
        fs::write(&self.file_path, json)?;
        Ok(())
    }

    pub fn load_session(&self) -> Result<Option<Session>> {
        if !self.file_path.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(&self.file_path)?;
        let session = serde_json::from_str(&content)?;
        Ok(Some(session))
    }

    pub fn clear_session(&self) -> Result<()> {
        if self.file_path.exists() {
            fs::remove_file(&self.file_path)?;
        }
        Ok(())
    }
} 