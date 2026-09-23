use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use image::{GenericImageView, ImageFormat, ImageReader};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    display_path,
    error::{AppError, AppResult},
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImageInfo {
    pub path: String,
    pub format: String,
    pub width: u32,
    pub height: u32,
    pub file_sha256: String,
    pub pixel_sha256: String,
}

impl ImageInfo {
    pub fn dimensions(&self) -> String {
        format!("{} x {}", self.width, self.height)
    }
}

pub fn inspect_image(path: &Path) -> AppResult<ImageInfo> {
    if !path.is_file() {
        return Err(AppError::runtime(format!(
            "input is not a regular file: {}",
            display_path(path)
        )));
    }

    let reader = ImageReader::open(path)
        .map_err(|e| AppError::runtime(format!("cannot open {}: {e}", display_path(path))))?
        .with_guessed_format()
        .map_err(|e| {
            AppError::runtime(format!(
                "cannot detect image format for {}: {e}",
                display_path(path)
            ))
        })?;
    let format = reader.format().ok_or_else(|| {
        AppError::runtime(format!(
            "cannot detect image format for {}",
            display_path(path)
        ))
    })?;
    let mime = mime_for_format(format)?;
    let decoded = reader
        .decode()
        .map_err(|e| AppError::runtime(format!("cannot decode {}: {e}", display_path(path))))?;
    let (width, height) = decoded.dimensions();

    let mut pixel_hasher = Sha256::new();
    pixel_hasher.update(b"banksy-c2pa:canonical-rgba16:v1\0");
    pixel_hasher.update(width.to_be_bytes());
    pixel_hasher.update(height.to_be_bytes());
    pixel_hasher.update(4_u32.to_be_bytes());
    for value in decoded.to_rgba16().into_raw() {
        pixel_hasher.update(value.to_be_bytes());
    }

    Ok(ImageInfo {
        path: display_path(path),
        format: mime.into(),
        width,
        height,
        file_sha256: file_sha256(path)?,
        pixel_sha256: hex::encode(pixel_hasher.finalize()),
    })
}

pub fn pixels_equal(left: &Path, right: &Path) -> AppResult<bool> {
    let left = inspect_image(left)?;
    let right = inspect_image(right)?;
    Ok(left.width == right.width
        && left.height == right.height
        && left.pixel_sha256 == right.pixel_sha256)
}

pub fn mime_for_path(path: &Path) -> AppResult<&'static str> {
    let reader = ImageReader::open(path)
        .map_err(|e| AppError::runtime(format!("cannot open {}: {e}", display_path(path))))?
        .with_guessed_format()
        .map_err(|e| AppError::runtime(format!("cannot inspect {}: {e}", display_path(path))))?;
    let format = reader.format().ok_or_else(|| {
        AppError::runtime(format!(
            "cannot detect image format for {}",
            display_path(path)
        ))
    })?;
    mime_for_format(format)
}

pub fn extension_for_mime(mime: &str) -> &'static str {
    match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        _ => "bin",
    }
}

fn mime_for_format(format: ImageFormat) -> AppResult<&'static str> {
    match format {
        ImageFormat::Png => Ok("image/png"),
        ImageFormat::Jpeg => Ok("image/jpeg"),
        _ => Err(AppError::runtime(format!(
            "unsupported image format {format:?}; version 1 supports PNG and JPEG"
        ))),
    }
}

pub fn file_sha256(path: &Path) -> AppResult<String> {
    let file = File::open(path)
        .map_err(|e| AppError::runtime(format!("cannot read {}: {e}", display_path(path))))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|e| AppError::runtime(format!("cannot read {}: {e}", display_path(path))))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    #[test]
    fn semantic_pixel_hash_ignores_container_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.png");
        let b = dir.path().join("b.png");
        let image = ImageBuffer::from_pixel(3, 2, Rgba([12_u8, 34, 56, 255]));
        image.save(&a).unwrap();
        image.save(&b).unwrap();
        assert!(pixels_equal(&a, &b).unwrap());
    }

    #[test]
    fn semantic_pixel_hash_detects_one_pixel_change() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.png");
        let b = dir.path().join("b.png");
        let image = ImageBuffer::from_pixel(2, 2, Rgba([12_u8, 34, 56, 255]));
        image.save(&a).unwrap();
        let mut changed = image;
        changed.put_pixel(1, 1, Rgba([13_u8, 34, 56, 255]));
        changed.save(&b).unwrap();
        assert!(!pixels_equal(&a, &b).unwrap());
    }
}
