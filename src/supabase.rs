use anyhow::Result;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use std::sync::Arc;
use once_cell::sync::OnceCell;
use urlencoding;
use log;

static SUPABASE_CLIENT: OnceCell<SupabaseClient> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct SupabaseClient {
    client: Arc<Client>,
    url: String,
    anon_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub enum Provider {
    Google,
    Apple,
}

impl SupabaseClient {
    pub fn initialize(url: String, anon_key: String) -> Result<()> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "apikey",
            header::HeaderValue::from_str(&anon_key)?,
        );
        
        let client = Client::builder()
            .default_headers(headers)
            .build()?;

        let supabase = Self {
            client: Arc::new(client),
            url,
            anon_key,
        };

        SUPABASE_CLIENT.set(supabase)
            .map_err(|_| anyhow::anyhow!("Supabase client already initialized"))?;

        Ok(())
    }

    pub fn get() -> Result<&'static SupabaseClient> {
        SUPABASE_CLIENT.get()
            .ok_or_else(|| anyhow::anyhow!("Supabase client not initialized"))
    }

    pub fn get_oauth_url(&self, provider: Provider) -> String {
        format!(
            "{}/auth/v1/authorize?provider={}&redirect_to={}/auth/callback",
            self.url,
            match provider {
                Provider::Google => "google",
                Provider::Apple => "apple",
            },
            self.url
        )
    }

    pub async fn exchange_code_for_session(&self, code: &str) -> Result<Session> {
        let response = self.client
            .post(&format!("{}/auth/v1/token?grant_type=authorization_code", self.url))
            .json(&json!({
                "code": code,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Failed to exchange code: {}", error));
        }

        let data = response.json::<serde_json::Value>().await?;
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?
            .to_string();
        
        let user_id = Uuid::parse_str(
            data["user"]["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("No user id in response"))?,
        )?;

        Ok(Session {
            access_token,
            user_id,
        })
    }

    pub async fn sign_up(&self, email: &str, password: &str) -> Result<Session> {
        let response = self.client
            .post(&format!("{}/auth/v1/signup", self.url))
            .json(&json!({
                "email": email,
                "password": password
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Failed to sign up: {}", error));
        }

        let data = response.json::<serde_json::Value>().await?;
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?
            .to_string();
        
        let user_id = Uuid::parse_str(
            data["user"]["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("No user id in response"))?,
        )?;

        Ok(Session {
            access_token,
            user_id,
        })
    }

    pub async fn sign_in(&self, email: &str, password: &str) -> Result<Session> {
        let response = self.client
            .post(&format!("{}/auth/v1/token?grant_type=password", self.url))
            .json(&json!({
                "email": email,
                "password": password
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Failed to sign in: {}", error));
        }

        let data = response.json::<serde_json::Value>().await?;
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?
            .to_string();
        
        let user_id = Uuid::parse_str(
            data["user"]["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("No user id in response"))?,
        )?;

        Ok(Session {
            access_token,
            user_id,
        })
    }

    pub async fn insert_app_usage<T: Serialize>(&self, session: &Session, data: &T) -> Result<()> {
        let response = self.client
            .post(&format!("{}/rest/v1/app_usage", self.url))
            .bearer_auth(&session.access_token)
            .json(data)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Failed to insert app usage: {}", error));
        }

        Ok(())
    }

    pub async fn sign_in_with_oauth(&self, provider: Provider, callback_url: &str) -> Result<String> {
        let provider_str = match provider {
            Provider::Google => "google",
            Provider::Apple => "apple",
        };
        log::info!("OAuth provider: {}", provider_str);
        log::info!("Callback URL before encoding: {}", callback_url);

        let encoded_callback = urlencoding::encode(callback_url);
        log::info!("Encoded callback URL: {}", encoded_callback);

        let auth_url = format!(
            "{}/auth/v1/authorize?provider={}&redirect_to={}&response_type=code&scope=email",
            self.url,
            provider_str,
            encoded_callback
        );
        log::info!("Generated OAuth URL: {}", auth_url);
        
        Ok(auth_url)
    }

    pub async fn upload_icon(&self, file_path: &std::path::Path, file_name: &str) -> Result<()> {
        let file_content = tokio::fs::read(file_path).await?;
        
        let response = self.client
            .post(&format!("{}/storage/v1/object/app-icons/{}", self.url, file_name))
            .header("Authorization", format!("Bearer {}", self.anon_key))
            .body(file_content)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Failed to upload icon: {}", error));
        }

        Ok(())
    }
} 