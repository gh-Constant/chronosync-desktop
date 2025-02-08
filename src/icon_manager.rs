use anyhow::Result;
use image::RgbaImage;
use itertools::Itertools;
use path_slash::PathExt;
use std::collections::HashSet;
use std::path::Path;
use parking_lot::Mutex;
use once_cell::sync::Lazy;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, GetDIBits, SelectObject, DeleteDC, DeleteObject,
    BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, HDC, HGDIOBJ,
};
use windows::Win32::UI::Shell::ExtractIconExW;
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, GetIconInfoExW, HICON, ICONINFOEXW,
};

use crate::color_convert::bgra_to_rgba;

static UPLOADED_ICONS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub struct IconManager;

impl IconManager {
    pub async fn extract_and_upload_icon(exe_path: &str) -> Result<Option<String>> {
        // Skip if not an exe file
        if !exe_path.to_lowercase().ends_with(".exe") {
            log::debug!("Skipping non-exe file: {}", exe_path);
            return Ok(None);
        }

        // Get app name from path
        let app_name = Path::new(exe_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        log::info!("Attempting to extract icon for: {}", app_name);

        // Check if we've already uploaded this icon
        {
            let uploaded = UPLOADED_ICONS.lock();
            if uploaded.contains(&app_name) {
                log::debug!("Icon already uploaded for: {}", app_name);
                return Ok(Some(format!("{}.png", app_name)));
            }
        }

        // Extract icons from exe
        let images = match get_images_from_exe(exe_path) {
            Ok(imgs) => imgs,
            Err(e) => {
                log::warn!("Failed to extract icons from {}: {}", exe_path, e);
                return Ok(None);
            }
        };

        // Get the largest icon
        let largest_icon = images.into_iter().max_by_key(|img| img.width() * img.height());
        
        let Some(icon) = largest_icon else {
            log::warn!("No valid icons found in {}", exe_path);
            return Ok(None);
        };

        // Create temporary file
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("{}.png", app_name));
        if let Err(e) = icon.save(&temp_path) {
            log::warn!("Failed to save icon to temporary file: {}", e);
            return Ok(None);
        }

        // Upload to Supabase
        if let Ok(supabase) = crate::supabase::SupabaseClient::get() {
            let file_name = format!("{}.png", app_name);
            match supabase.upload_icon(&temp_path, &file_name).await {
                Ok(_) => {
                    log::info!("Successfully uploaded icon for: {}", app_name);
                    UPLOADED_ICONS.lock().insert(app_name.clone());
                    return Ok(Some(file_name));
                }
                Err(e) => {
                    log::error!("Failed to upload icon for {}: {}", app_name, e);
                    return Ok(None);
                }
            }
        } else {
            log::error!("Failed to get Supabase client");
        }

        Ok(None)
    }
}

fn get_images_from_exe(executable_path: &str) -> Result<Vec<RgbaImage>> {
    unsafe {
        let path_cstr = U16CString::from_str(executable_path)?;
        let path_pcwstr = PCWSTR(path_cstr.as_ptr());
        let num_icons_total = ExtractIconExW(path_pcwstr, -1, None, None, 0);
        if num_icons_total == 0 {
            return Ok(Vec::new());
        }

        let mut large_icons = vec![HICON::default(); num_icons_total as usize];
        let mut small_icons = vec![HICON::default(); num_icons_total as usize];
        let num_icons_fetched = ExtractIconExW(
            path_pcwstr,
            0,
            Some(large_icons.as_mut_ptr()),
            Some(small_icons.as_mut_ptr()),
            num_icons_total,
        );

        if num_icons_fetched == 0 {
            return Ok(Vec::new());
        }

        let images = large_icons
            .iter()
            .chain(small_icons.iter())
            .map(|icon| convert_hicon_to_rgba_image(icon))
            .filter_map(|r| match r {
                Ok(img) => Some(img),
                Err(e) => {
                    log::warn!("Failed to convert HICON to RgbaImage: {}", e);
                    None
                }
            })
            .collect_vec();

        // Cleanup
        large_icons
            .iter()
            .chain(small_icons.iter())
            .filter(|icon| !icon.is_invalid())
            .for_each(|icon| {
                if let Err(e) = DestroyIcon(*icon) {
                    log::warn!("Failed to destroy icon: {}", e);
                }
            });

        Ok(images)
    }
}

fn convert_hicon_to_rgba_image(hicon: &HICON) -> Result<RgbaImage> {
    unsafe {
        let mut icon_info = ICONINFOEXW::default();
        icon_info.cbSize = std::mem::size_of::<ICONINFOEXW>() as u32;

        if !GetIconInfoExW(*hicon, &mut icon_info).as_bool() {
            return Err(anyhow::anyhow!("Failed to get icon info"));
        }

        let hdc_screen = CreateCompatibleDC(None);
        let hdc_mem = CreateCompatibleDC(hdc_screen);
        let hbm_old = SelectObject(hdc_mem, icon_info.hbmColor);

        let mut bmp_info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: icon_info.xHotspot as i32 * 2,
                biHeight: -(icon_info.yHotspot as i32 * 2),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: DIB_RGB_COLORS.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut buffer: Vec<u8> = vec![0; (icon_info.xHotspot * 2 * icon_info.yHotspot * 2 * 4) as usize];

        if GetDIBits(
            hdc_mem,
            icon_info.hbmColor,
            0,
            icon_info.yHotspot * 2,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut bmp_info,
            DIB_RGB_COLORS,
        ) == 0
        {
            return Err(anyhow::anyhow!("Failed to get DIB bits"));
        }

        // Cleanup
        SelectObject(hdc_mem, hbm_old);
        DeleteDC(hdc_mem);
        DeleteDC(hdc_screen);
        DeleteObject(icon_info.hbmColor);
        DeleteObject(icon_info.hbmMask);

        // Convert BGRA to RGBA
        bgra_to_rgba(&mut buffer);

        let image = image::RgbaImage::from_raw(
            icon_info.xHotspot * 2,
            icon_info.yHotspot * 2,
            buffer,
        ).ok_or_else(|| anyhow::anyhow!("Failed to create image from buffer"))?;

        Ok(image)
    }
} 