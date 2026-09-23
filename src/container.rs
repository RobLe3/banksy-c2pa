use std::{fs, path::Path};

use crc32fast::Hasher;
use serde::Serialize;

use crate::{
    display_path,
    error::{AppError, AppResult},
};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ContainerCredentialReport {
    pub format: &'static str,
    pub location: &'static str,
    pub embedded: bool,
    pub store_count: usize,
    pub store_bytes: u64,
    pub before_media_data: Option<bool>,
    pub crc_valid: Option<bool>,
    pub structure_valid: bool,
    pub trailing_bytes: u64,
    pub issues: Vec<String>,
}

impl ContainerCredentialReport {
    pub fn valid_generated_embedding(&self) -> bool {
        self.embedded
            && self.store_count == 1
            && self.structure_valid
            && self.before_media_data != Some(false)
    }
}

pub fn inspect_container(path: &Path) -> AppResult<ContainerCredentialReport> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::runtime(format!("cannot read {}: {error}", display_path(path)))
    })?;
    if bytes.starts_with(PNG_SIGNATURE) {
        inspect_png(&bytes)
    } else if bytes.starts_with(&[0xff, 0xd8]) {
        inspect_jpeg(&bytes)
    } else {
        Err(AppError::verification(format!(
            "unsupported container format: {}",
            display_path(path)
        )))
    }
}

fn inspect_png(bytes: &[u8]) -> AppResult<ContainerCredentialReport> {
    let mut position = PNG_SIGNATURE.len();
    let mut chunks = 0_usize;
    let mut store_count = 0_usize;
    let mut store_bytes = 0_u64;
    let mut store_before_idat = true;
    let mut seen_ihdr = false;
    let mut seen_idat = false;
    let mut seen_iend = false;
    let mut all_crc_valid = true;
    let mut issues = Vec::new();

    while position < bytes.len() {
        let header_end = position.checked_add(8).ok_or_else(|| {
            AppError::verification("PNG chunk header offset overflowed address space")
        })?;
        if header_end > bytes.len() {
            issues.push("truncated PNG chunk header".into());
            break;
        }
        let length = u32::from_be_bytes(
            bytes[position..position + 4]
                .try_into()
                .expect("four-byte PNG chunk length"),
        ) as usize;
        let chunk_type = &bytes[position + 4..position + 8];
        let data_start = header_end;
        let data_end = match data_start.checked_add(length) {
            Some(end) => end,
            None => {
                issues.push("PNG chunk length overflow".into());
                break;
            }
        };
        let chunk_end = match data_end.checked_add(4) {
            Some(end) => end,
            None => {
                issues.push("PNG chunk CRC offset overflow".into());
                break;
            }
        };
        if chunk_end > bytes.len() {
            issues.push(format!(
                "truncated {} chunk",
                String::from_utf8_lossy(chunk_type)
            ));
            break;
        }

        let expected_crc = u32::from_be_bytes(
            bytes[data_end..chunk_end]
                .try_into()
                .expect("four-byte PNG CRC"),
        );
        let mut hasher = Hasher::new();
        hasher.update(chunk_type);
        hasher.update(&bytes[data_start..data_end]);
        if hasher.finalize() != expected_crc {
            all_crc_valid = false;
            issues.push(format!(
                "{} chunk has an invalid CRC",
                String::from_utf8_lossy(chunk_type)
            ));
        }

        if !chunk_type.iter().all(u8::is_ascii_alphabetic) {
            issues.push("PNG chunk type contains a non-alphabetic byte".into());
        }
        if chunk_type == b"IHDR" {
            if seen_ihdr {
                issues.push("PNG contains more than one IHDR chunk".into());
            }
            if chunks != 0 {
                issues.push("IHDR is not the first PNG chunk".into());
            }
            if length != 13 {
                issues.push("IHDR chunk does not have the required 13-byte length".into());
            }
            seen_ihdr = true;
        } else if chunks == 0 {
            issues.push("IHDR is not the first PNG chunk".into());
        }
        if chunk_type == b"IDAT" {
            seen_idat = true;
        } else if chunk_type == b"caBX" {
            store_count += 1;
            store_bytes = store_bytes.saturating_add(length as u64);
            store_before_idat &= !seen_idat;
            if length == 0 {
                issues.push("caBX chunk is empty".into());
            }
        } else if chunk_type == b"IEND" {
            if length != 0 {
                issues.push("IEND chunk is not empty".into());
            }
            seen_iend = true;
            position = chunk_end;
            break;
        }
        chunks += 1;
        position = chunk_end;
    }

    if !seen_ihdr {
        issues.push("PNG contains no IHDR chunk".into());
    }
    if !seen_idat {
        issues.push("PNG contains no IDAT image data".into());
    }
    if !seen_iend {
        issues.push("PNG contains no complete IEND chunk".into());
    }
    let trailing_bytes = bytes.len().saturating_sub(position) as u64;
    if trailing_bytes > 0 {
        issues.push(format!("{trailing_bytes} trailing bytes after IEND"));
    }
    if store_count > 1 {
        issues.push(format!("PNG contains {store_count} caBX chunks"));
    }

    Ok(ContainerCredentialReport {
        format: "image/png",
        location: "PNG caBX",
        embedded: store_count == 1,
        store_count,
        store_bytes,
        before_media_data: (store_count > 0).then_some(store_before_idat),
        crc_valid: Some(all_crc_valid),
        structure_valid: issues.is_empty(),
        trailing_bytes,
        issues,
    })
}

fn inspect_jpeg(bytes: &[u8]) -> AppResult<ContainerCredentialReport> {
    let mut position = 2_usize;
    let mut reached_scan = false;
    let mut seen_eoi = false;
    let mut store_count = 0_usize;
    let mut store_bytes = 0_u64;
    let mut jumbf_segments = 0_usize;
    let mut active_en: Option<[u8; 2]> = None;
    let mut expected_sequence = 1_u32;
    let mut issues = Vec::new();

    while position < bytes.len() {
        if bytes[position] != 0xff {
            issues.push(format!("expected JPEG marker at byte {position}"));
            break;
        }
        while position < bytes.len() && bytes[position] == 0xff {
            position += 1;
        }
        if position >= bytes.len() {
            issues.push("truncated JPEG marker".into());
            break;
        }
        let marker = bytes[position];
        position += 1;
        if marker == 0xd9 {
            seen_eoi = true;
            break;
        }
        if marker == 0xda {
            reached_scan = true;
            seen_eoi = bytes.ends_with(&[0xff, 0xd9]);
            break;
        }
        if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
            continue;
        }
        if position + 2 > bytes.len() {
            issues.push("truncated JPEG segment length".into());
            break;
        }
        let length = u16::from_be_bytes([bytes[position], bytes[position + 1]]) as usize;
        if length < 2 {
            issues.push(format!("JPEG marker FF{marker:02X} has an invalid length"));
            break;
        }
        let payload_start = position + 2;
        let payload_end = match position.checked_add(length) {
            Some(end) => end,
            None => {
                issues.push("JPEG segment length overflow".into());
                break;
            }
        };
        if payload_end > bytes.len() {
            issues.push(format!("truncated JPEG marker FF{marker:02X}"));
            break;
        }
        let payload = &bytes[payload_start..payload_end];
        if marker == 0xeb && payload.len() >= 8 && &payload[0..2] == b"JP" {
            let en = [payload[2], payload[3]];
            let sequence = u32::from_be_bytes(
                payload[4..8]
                    .try_into()
                    .expect("four-byte JPEG XT sequence"),
            );
            let starts_store = payload.len() >= 28 && &payload[24..28] == b"c2pa";
            if starts_store {
                store_count += 1;
                active_en = Some(en);
                expected_sequence = 2;
                jumbf_segments += 1;
                store_bytes = store_bytes.saturating_add(payload.len().saturating_sub(8) as u64);
                if sequence != 1 {
                    issues.push("first C2PA JPEG XT segment does not have sequence 1".into());
                }
            } else if active_en == Some(en) {
                jumbf_segments += 1;
                if sequence != expected_sequence {
                    issues.push(format!(
                        "C2PA JPEG XT sequence is discontinuous at segment {sequence}"
                    ));
                }
                expected_sequence = sequence.saturating_add(1);
                store_bytes = store_bytes.saturating_add(payload.len().saturating_sub(16) as u64);
            }
        }
        position = payload_end;
    }

    if !reached_scan {
        issues.push("JPEG contains no start-of-scan marker".into());
    }
    if !seen_eoi {
        issues.push("JPEG contains no end-of-image marker".into());
    }
    if store_count > 1 {
        issues.push(format!("JPEG contains {store_count} C2PA JUMBF stores"));
    }

    Ok(ContainerCredentialReport {
        format: "image/jpeg",
        location: "JPEG APP11 JUMBF",
        embedded: store_count == 1 && jumbf_segments > 0,
        store_count,
        store_bytes,
        before_media_data: (store_count > 0).then_some(true),
        crc_valid: None,
        structure_valid: issues.is_empty(),
        trailing_bytes: 0,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(kind);
        out.extend(data);
        let mut hasher = Hasher::new();
        hasher.update(kind);
        hasher.update(data);
        out.extend(hasher.finalize().to_be_bytes());
        out
    }

    fn minimal_png(with_cabx: bool) -> Vec<u8> {
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
        if with_cabx {
            out.extend(chunk(b"caBX", b"jumbf"));
        }
        out.extend(chunk(b"IDAT", b"data"));
        out.extend(chunk(b"IEND", b""));
        out
    }

    #[test]
    fn detects_png_cabx_and_validates_crc() {
        let report = inspect_png(&minimal_png(true)).unwrap();
        assert!(report.valid_generated_embedding());
        assert_eq!(report.store_bytes, 5);
        assert_eq!(report.crc_valid, Some(true));
    }

    #[test]
    fn missing_cabx_is_structurally_valid_but_not_embedded() {
        let report = inspect_png(&minimal_png(false)).unwrap();
        assert!(report.structure_valid);
        assert!(!report.embedded);
    }

    #[test]
    fn detects_bad_crc_and_trailing_bytes() {
        let mut png = minimal_png(true);
        png[20] ^= 1;
        png.extend(b"trailing");
        let report = inspect_png(&png).unwrap();
        assert!(!report.structure_valid);
        assert!(!report.valid_generated_embedding());
        assert_eq!(report.trailing_bytes, 8);
    }

    #[test]
    fn cabx_after_idat_is_not_accepted_for_generated_output() {
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
        out.extend(chunk(b"IDAT", b"data"));
        out.extend(chunk(b"caBX", b"jumbf"));
        out.extend(chunk(b"IEND", b""));
        let report = inspect_png(&out).unwrap();
        assert!(report.structure_valid);
        assert_eq!(report.before_media_data, Some(false));
        assert!(!report.valid_generated_embedding());
    }

    #[test]
    fn rejects_a_non_image_with_verification_exit_code() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-image.png");
        fs::write(&path, b"not a PNG").unwrap();
        let error = inspect_container(&path).unwrap_err();
        assert_eq!(error.exit_code(), 3);
    }
}
