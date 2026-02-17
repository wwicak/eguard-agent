use std::collections::HashMap;
use std::path::Path;

use goblin::elf::Elf;
use sha2::{Digest, Sha256};

pub const INTEGRITY_SECTION_SET: [&str; 2] = [".text", ".rodata"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionDigest {
    pub section: String,
    pub sha256_hex: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityMeasurement {
    pub combined_sha256_hex: String,
    pub section_digests: Vec<SectionDigest>,
}

pub fn measure_self_integrity() -> Result<IntegrityMeasurement, String> {
    measure_executable_sections(Path::new("/proc/self/exe"), &INTEGRITY_SECTION_SET)
}

pub fn measure_executable_sections(
    path: &Path,
    sections: &[&str],
) -> Result<IntegrityMeasurement, String> {
    if sections.is_empty() {
        return Err("integrity sections list cannot be empty".to_string());
    }

    let binary = std::fs::read(path)
        .map_err(|err| format!("read executable {}: {}", path.display(), err))?;
    let elf = Elf::parse(&binary)
        .map_err(|err| format!("parse elf executable {}: {}", path.display(), err))?;

    let mut ranges: HashMap<&str, (usize, usize)> = HashMap::new();
    for header in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(header.sh_name) else {
            continue;
        };
        if !sections.contains(&name) {
            continue;
        }

        let start = usize::try_from(header.sh_offset)
            .map_err(|_| format!("section '{}' offset out of range", name))?;
        let size = usize::try_from(header.sh_size)
            .map_err(|_| format!("section '{}' size out of range", name))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| format!("section '{}' range overflow", name))?;

        if end > binary.len() {
            return Err(format!(
                "section '{}' exceeds executable size (end={} size={})",
                name,
                end,
                binary.len()
            ));
        }

        ranges.insert(name, (start, end));
    }

    let mut combined_hasher = Sha256::new();
    let mut section_digests = Vec::with_capacity(sections.len());
    for section in sections {
        let (start, end) = ranges
            .get(section)
            .copied()
            .ok_or_else(|| format!("required section '{}' not found", section))?;
        let section_bytes = &binary[start..end];
        combined_hasher.update(section_bytes);

        let section_hash = Sha256::digest(section_bytes);
        section_digests.push(SectionDigest {
            section: (*section).to_string(),
            sha256_hex: encode_hex(&section_hash),
            size_bytes: section_bytes.len(),
        });
    }

    let combined_sha256_hex = encode_hex(&combined_hasher.finalize());
    Ok(IntegrityMeasurement {
        combined_sha256_hex,
        section_digests,
    })
}

pub fn hash_file_sha256(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("read {}: {}", path.display(), err))?;
    let digest = Sha256::digest(&bytes);
    Ok(encode_hex(&digest))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
