// extract.rs — decrypt a SATAN2CV container and extract inline-tar archive to a directory.
// Handles containers produced by encrypt_dir() and destroy_and_encrypt().
// For single-file containers (encrypt_file), use decrypt_container() instead.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::algo::Engine;
use crate::container::{open, read_sector, SECTOR_SIZE};
use crate::header::CvHeader;

// ── Streaming sector reader ───────────────────────────────────────────────────

struct ContainerReader {
    file: std::fs::File,
    engine: Engine,
    n_sectors: u64,
    data_len: u64,
    sector: u64,
    buf: [u8; SECTOR_SIZE],
    buf_pos: usize,
    buf_end: usize,
}

impl ContainerReader {
    fn new(file: std::fs::File, engine: Engine, hdr: &CvHeader) -> Self {
        let data_len = hdr.volume_size;
        let n_sectors = data_len.div_ceil(SECTOR_SIZE as u64);
        ContainerReader {
            file,
            engine,
            n_sectors,
            data_len,
            sector: 0,
            buf: [0u8; SECTOR_SIZE],
            buf_pos: 0,
            buf_end: 0,
        }
    }
}

impl Read for ContainerReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.buf_pos >= self.buf_end {
            if self.sector >= self.n_sectors {
                return Ok(0);
            }

            read_sector(&mut self.file, &self.engine, self.sector, &mut self.buf)
                .map_err(std::io::Error::other)?;

            self.buf_pos = 0;
            let sector_start = self.sector * SECTOR_SIZE as u64;
            self.buf_end = (self.data_len - sector_start).min(SECTOR_SIZE as u64) as usize;
            self.sector += 1;
        }

        let n = (self.buf_end - self.buf_pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + n]);
        self.buf_pos += n;
        Ok(n)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Decrypt a SATAN2CV container and extract its inline-tar contents to `dst_dir`.
/// Returns total plaintext bytes extracted.
pub fn extract_dir(src: &str, dst_dir: &str, passphrase: &[u8]) -> Result<u64, String> {
    let (hdr, engine, file) = open(src, passphrase)?;

    fs::create_dir_all(dst_dir).map_err(|e| format!("create dir '{}': {}", dst_dir, e))?;

    let mut reader = ContainerReader::new(file, engine, &hdr);
    parse_inline_tar(&mut reader, dst_dir)
}

// ── Inline-tar parser ─────────────────────────────────────────────────────────

/// Parse the inline-tar format and materialize entries under `dst_dir`.
/// Format: [u16 LE path_len][path bytes][u64 LE file_size][file_size bytes] ...
///         Terminated by path_len == 0.
/// Paths ending with '/' are directories; all others are files.
fn parse_inline_tar<R: Read>(reader: &mut R, dst_dir: &str) -> Result<u64, String> {
    let mut total = 0u64;

    loop {
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
        let path_len = u16::from_le_bytes(len_buf) as usize;
        if path_len == 0 {
            break;
        }

        let mut path_bytes = vec![0u8; path_len];
        reader
            .read_exact(&mut path_bytes)
            .map_err(|e| e.to_string())?;
        let rel = String::from_utf8(path_bytes)
            .map_err(|e| format!("non-UTF-8 path in archive: {}", e))?;

        let mut size_buf = [0u8; 8];
        reader
            .read_exact(&mut size_buf)
            .map_err(|e| e.to_string())?;
        let file_size = u64::from_le_bytes(size_buf);

        let safe = sanitize_path(&rel)?;
        let full = format!("{}/{}", dst_dir, safe);

        if rel.ends_with('/') {
            fs::create_dir_all(&full).map_err(|e| format!("mkdir '{}': {}", full, e))?;
            skip_bytes(reader, file_size)?;
        } else {
            if let Some(parent) = Path::new(&full).parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir parent for '{}': {}", full, e))?;
            }
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&full)
                .map_err(|e| format!("create '{}': {}", full, e))?;
            copy_exact(reader, &mut out, file_size)?;
            total += file_size;
        }
    }

    Ok(total)
}

fn skip_bytes<R: Read>(r: &mut R, mut n: u64) -> Result<(), String> {
    let mut buf = [0u8; 4096];
    while n > 0 {
        let to_read = n.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..to_read])
            .map_err(|e| e.to_string())?;
        n -= to_read as u64;
    }
    Ok(())
}

fn copy_exact<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: u64) -> Result<(), String> {
    let mut buf = [0u8; 65536];
    while n > 0 {
        let to_read = n.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..to_read])
            .map_err(|e| e.to_string())?;
        w.write_all(&buf[..to_read]).map_err(|e| e.to_string())?;
        n -= to_read as u64;
    }
    Ok(())
}

/// Strip leading slashes, collapse dots, reject `..` traversal attempts.
fn sanitize_path(path: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.trim_end_matches('/').split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(format!("path traversal rejected: '{}'", path)),
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return Err(format!("empty path after sanitization: '{}'", path));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_normal_paths() {
        assert_eq!(sanitize_path("a.txt").unwrap(), "a.txt");
        assert_eq!(
            sanitize_path("sub/dir/file.bin").unwrap(),
            "sub/dir/file.bin"
        );
        assert_eq!(sanitize_path("dir/").unwrap(), "dir");
    }

    #[test]
    fn sanitize_strips_slashes_and_dots() {
        assert_eq!(sanitize_path("/etc/passwd").unwrap(), "etc/passwd");
        assert_eq!(sanitize_path("./a.txt").unwrap(), "a.txt");
        assert_eq!(sanitize_path("a/./b.txt").unwrap(), "a/b.txt");
        assert_eq!(sanitize_path("//double//slash").unwrap(), "double/slash");
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize_path("../evil").is_err());
        assert!(sanitize_path("a/../../evil").is_err());
        assert!(sanitize_path("..").is_err());
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_path("").is_err());
        assert!(sanitize_path("/").is_err());
        assert!(sanitize_path("./").is_err());
    }

    /// parse_inline_tar must reject archives containing traversal paths
    /// rather than writing outside the destination directory.
    #[test]
    fn extract_rejects_malicious_archive() {
        let mut archive: Vec<u8> = Vec::new();
        let path = b"../escape.txt";
        archive.extend_from_slice(&(path.len() as u16).to_le_bytes());
        archive.extend_from_slice(path);
        archive.extend_from_slice(&4u64.to_le_bytes());
        archive.extend_from_slice(b"EVIL");
        archive.extend_from_slice(&0u16.to_le_bytes()); // terminator

        let dir = std::env::temp_dir().join(format!(
            "satan2-test-extract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cursor = std::io::Cursor::new(archive);
        assert!(parse_inline_tar(&mut cursor, dir.to_str().unwrap()).is_err());
        assert!(!dir.parent().unwrap().join("escape.txt").exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
