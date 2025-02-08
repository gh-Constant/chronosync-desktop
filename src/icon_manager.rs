use anyhow::Result;
use ico;
use image::{ImageBuffer, Rgba};
use path_slash::PathExt;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use parking_lot::Mutex;
use once_cell::sync::Lazy;

static UPLOADED_ICONS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub struct IconManager;

impl IconManager {
    pub async fn extract_and_upload_icon(exe_path: &str) -> Result<Option<String>> {
        // Skip if not an exe file
        if !exe_path.to_lowercase().ends_with(".exe") {
            return Ok(None);
        }

        // Get app name from path
        let app_name = Path::new(exe_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        // Check if we've already uploaded this icon
        {
            let uploaded = UPLOADED_ICONS.lock();
            if uploaded.contains(&app_name) {
                return Ok(Some(format!("{}.png", app_name)));
            }
        }

        // Try to open the exe file
        let mut file = match File::open(exe_path) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };

        // Try to read icons
        let icon_dir = match ico::IconDir::read(&mut file) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        // Get the largest icon
        let entry = icon_dir.entries()
            .iter()
            .max_by_key(|e| e.width() as u32 * e.height() as u32);

        if let Some(entry) = entry {
            // Convert icon to PNG
            let icon_image = entry.decode()?;
            let width = entry.width() as u32;
            let height = entry.height() as u32;
            
            let image: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_raw(
                width,
                height,
                icon_image.rgba_data().to_vec(),
            ).ok_or_else(|| anyhow::anyhow!("Failed to create image buffer"))?;

            // Create temporary file
            let temp_dir = std::env::temp_dir();
            let temp_path = temp_dir.join(format!("{}.png", app_name));
            image.save(&temp_path)?;

            // Upload to Supabase
            if let Ok(supabase) = crate::supabase::SupabaseClient::get() {
                let file_name = format!("{}.png", app_name);
                if let Ok(_) = supabase.upload_icon(&temp_path, &file_name).await {
                    // Mark as uploaded
                    UPLOADED_ICONS.lock().insert(app_name.clone());
                    return Ok(Some(file_name));
                }
            }
        }

        Ok(None)
    }
} 