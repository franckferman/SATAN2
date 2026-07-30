// Steganography honey injection — plant fake hidden data in media files.
//
// Goal: waste forensic analyst time. Files appear to contain steganographic
// payloads (tool signatures, LSB patterns, suspicious chunks) but the
// "hidden" content is generated noise or deliberate disinformation.
//
// Supported carriers:
//   JPEG — append fake data after EOI (FF D9) with OutGuess-style header
//   PNG  — inject tEXt / zTXt chunks with fake encoded payload
//   WAV  — flip LSBs of audio samples to encode a fake payload
//   ANY  — raw trailer append (generic fallback)

use std::fs;
use std::io::Write;

// ── Honey payload generator ───────────────────────────────────────────────────
// Generates content that looks like it might be interesting (fake credentials,
// fake private key header, random-looking base64) but is seeded noise.

pub fn generate_honey_payload(seed: u64, size: usize) -> Vec<u8> {
    // LCG PRNG seeded from the caller's seed
    let mut state = seed ^ 0x9e3779b97f4a7c15;
    let mut next = || -> u8 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };

    // Alternate between fake-credential-looking and random-looking content
    let mut out = Vec::with_capacity(size);
    // Prepend a fake PEM header to make it look like a certificate
    let header = b"-----BEGIN RSA PRIVATE KEY-----\n";
    out.extend_from_slice(&header[..header.len().min(size)]);

    let b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    while out.len() < size.saturating_sub(34) {
        let col = out.len() % 64;
        if col == 0 && !out.is_empty() {
            out.push(b'\n');
        }
        out.push(b64[(next() as usize) % 64]);
    }

    let footer = b"\n-----END RSA PRIVATE KEY-----\n";
    out.extend_from_slice(&footer[..footer.len().min(size.saturating_sub(out.len()))]);
    // Top up with base64 noise if the footer came up short, so the payload is
    // always exactly `size` bytes (the loop above can stop 1 byte early and
    // the footer reservation is approximate).
    while out.len() < size {
        out.push(b64[(next() as usize) % 64]);
    }
    out.truncate(size);
    out
}

// ── JPEG honey injection ──────────────────────────────────────────────────────
// Appends data after the EOI marker (FF D9).
// Steganography detection tools commonly scan after-EOI regions.
// We prepend a fake OutGuess 0.13b header to mislead tool identification.

pub fn inject_jpeg_honey(path: &str, payload: &[u8], verbose: bool) -> crate::Result<()> {
    let mut data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;

    // Verify JPEG signature
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(format!("{}: not a JPEG", path));
    }

    // Ensure file ends at EOI (FF D9); trim anything already after it
    if let Some(eoi_pos) = data.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
        data.truncate(eoi_pos + 2);
    }

    // Fake OutGuess trailer: magic + length + noise payload
    // Real OutGuess 0.13b appends: "OUTGUESS_PARITY_BLOCK" + random bytes
    // We use a variant that looks plausible to automated scanners
    let mut honey: Vec<u8> = Vec::new();
    honey.extend_from_slice(b"OUTGUESS13"); // fake tool magic
    honey.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    honey.extend_from_slice(payload);

    data.extend_from_slice(&honey);
    fs::write(path, &data).map_err(|e| format!("write {}: {}", path, e))?;
    if verbose {
        eprintln!(
            "[+] stego-honey: JPEG {} — {} B injected after EOI",
            path,
            honey.len()
        );
    }
    Ok(())
}

// ── PNG honey injection ───────────────────────────────────────────────────────
// Injects a tEXt chunk (keyword "steganography", value = base64-like payload)
// and a second chunk mimicking a zTXt compressed block.
// Both are valid per PNG spec — most viewers ignore unknown text chunks.

fn png_crc32(data: &[u8]) -> u32 {
    static mut TABLE: [u32; 256] = [0u32; 256];
    static mut INIT: bool = false;
    unsafe {
        if !INIT {
            for n in 0u32..256 {
                let mut c = n;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xEDB88320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
                TABLE[n as usize] = c;
            }
            INIT = true;
        }
        let mut c = !0u32;
        for &b in data {
            c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        !c
    }
}

fn png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes()); // length
    chunk.extend_from_slice(chunk_type); // type
    chunk.extend_from_slice(data); // data
                                   // CRC covers type + data
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    chunk.extend_from_slice(&png_crc32(&crc_input).to_be_bytes());
    chunk
}

pub fn inject_png_honey(path: &str, payload: &[u8], verbose: bool) -> crate::Result<()> {
    let data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;

    // Verify PNG signature: 8 bytes
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(format!("{}: not a PNG", path));
    }

    // Find IEND chunk to insert our chunks just before it
    let iend_pos = data
        .windows(8)
        .rposition(|w| &w[4..8] == b"IEND")
        .unwrap_or(data.len() - 12);

    // tEXt chunk: keyword\0value (both ISO 8859-1)
    let keyword = b"steganography";
    let mut text_data = Vec::new();
    text_data.extend_from_slice(keyword);
    text_data.push(0); // null separator
                       // Base64-encode payload for the value (fake "encoded hidden data")
    let b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i, &b) in payload.iter().take(512).enumerate() {
        text_data.push(b64[b as usize % 64]);
        if i % 64 == 63 {
            text_data.push(b'\n');
        }
    }
    let text_chunk = png_chunk(b"tEXt", &text_data);

    // Fake zTXt chunk: keyword\0\x00 (compression method 0) + "compressed" payload
    // We don't actually zlib-compress — we write raw bytes with a zlib-like header
    // (0x78 0x9C = zlib default compression header) to fool scanners.
    let mut ztxt_data = Vec::new();
    ztxt_data.extend_from_slice(b"comment\0");
    ztxt_data.push(0); // compression method: zlib
    ztxt_data.extend_from_slice(&[0x78, 0x9C]); // fake zlib header
    ztxt_data.extend_from_slice(&payload[..payload.len().min(128)]);
    let ztxt_chunk = png_chunk(b"zTXt", &ztxt_data);

    // Rebuild PNG: signature + chunks-before-IEND + our chunks + IEND
    let mut out = Vec::new();
    out.extend_from_slice(&data[..iend_pos]);
    out.extend_from_slice(&text_chunk);
    out.extend_from_slice(&ztxt_chunk);
    out.extend_from_slice(&data[iend_pos..]); // IEND + CRC

    fs::write(path, &out).map_err(|e| format!("write {}: {}", path, e))?;
    if verbose {
        eprintln!(
            "[+] stego-honey: PNG {} — tEXt+zTXt chunks injected ({} B payload)",
            path,
            payload.len()
        );
    }
    Ok(())
}

// ── WAV honey injection ───────────────────────────────────────────────────────
// Encodes payload bits into the LSBs of 16-bit PCM audio samples.
// Classic LSB steganography — most stego detectors scan for this pattern.
// The "hidden" content is our honey payload.

pub fn inject_wav_honey(path: &str, payload: &[u8], verbose: bool) -> crate::Result<()> {
    let mut data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;

    // RIFF WAV header check
    if data.len() < 44 || &data[..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return Err(format!("{}: not a WAV file", path));
    }

    // Find 'data' chunk offset
    let data_chunk = data
        .windows(4)
        .position(|w| w == b"data")
        .ok_or_else(|| format!("{}: no 'data' chunk", path))?;

    let samples_start = data_chunk + 8; // skip 'data' (4) + chunk_size (4)
    if samples_start >= data.len() {
        return Err(format!("{}: data chunk empty", path));
    }

    // Encode payload bits into LSBs of 16-bit samples (little-endian, so LSB at even offset)
    let payload_bits = payload.len() * 8;
    let available_samples = (data.len() - samples_start) / 2;

    if available_samples < payload_bits + 32 {
        return Err(format!(
            "{}: not enough samples to encode {} B payload",
            path,
            payload.len()
        ));
    }

    // Write payload length (32 bits) into first 32 sample LSBs
    let len_bits = (payload.len() as u32).to_le_bytes();
    for (i, &byte) in len_bits.iter().enumerate() {
        for bit in 0..8 {
            let sample_idx = samples_start + (i * 8 + bit) * 2;
            let bit_val = (byte >> bit) & 1;
            data[sample_idx] = (data[sample_idx] & 0xFE) | bit_val;
        }
    }

    // Write payload bits
    for (byte_idx, &byte) in payload.iter().enumerate() {
        for bit in 0..8u8 {
            let sample_idx = samples_start + (32 + byte_idx * 8 + bit as usize) * 2;
            if sample_idx + 1 >= data.len() {
                break;
            }
            let bit_val = (byte >> bit) & 1;
            data[sample_idx] = (data[sample_idx] & 0xFE) | bit_val;
        }
    }

    fs::write(path, &data).map_err(|e| format!("write {}: {}", path, e))?;
    if verbose {
        eprintln!(
            "[+] stego-honey: WAV {} — {} B encoded in sample LSBs ({} samples used)",
            path,
            payload.len(),
            payload_bits + 32
        );
    }
    Ok(())
}

// ── Generic trailer append ────────────────────────────────────────────────────
// Appends payload after the file's natural end with a fake tool signature header.
// Works as a fallback for any file type (Office, PDF, MP4, etc.).

pub fn inject_trailer_honey(
    path: &str,
    payload: &[u8],
    tool_sig: &[u8],
    verbose: bool,
) -> crate::Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    // Write: [sig][len:4 LE][payload]
    f.write_all(tool_sig).map_err(|e| e.to_string())?;
    f.write_all(&(payload.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    f.write_all(payload).map_err(|e| e.to_string())?;
    if verbose {
        eprintln!(
            "[+] stego-honey: trailer {} — sig={:?} {} B",
            path,
            String::from_utf8_lossy(tool_sig),
            payload.len()
        );
    }
    Ok(())
}

// ── Convenience: inject honey into all supported files in a directory ─────────

pub fn inject_directory_honey(dir: &str, seed: u64, payload_size: usize, verbose: bool) -> u32 {
    let mut count = 0u32;
    let walker = walkdir::WalkDir::new(dir).max_depth(3).into_iter();
    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_string_lossy().to_string();
        let payload = generate_honey_payload(seed ^ count as u64, payload_size);
        let ok = if path.ends_with(".jpg") || path.ends_with(".jpeg") {
            inject_jpeg_honey(&path, &payload, verbose).is_ok()
        } else if path.ends_with(".png") {
            inject_png_honey(&path, &payload, verbose).is_ok()
        } else if path.ends_with(".wav") {
            inject_wav_honey(&path, &payload, verbose).is_ok()
        } else {
            false
        };
        if ok {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "satan2-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn honey_payload_properties() {
        let p = generate_honey_payload(42, 512);
        assert_eq!(p.len(), 512, "payload must have exactly the requested size");
        assert!(
            p.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"),
            "missing PEM bait header"
        );

        // Deterministic per seed, different across seeds.
        assert_eq!(p, generate_honey_payload(42, 512));
        assert_ne!(p, generate_honey_payload(43, 512));

        // Degenerate sizes must not panic.
        assert_eq!(generate_honey_payload(1, 0).len(), 0);
        assert_eq!(generate_honey_payload(1, 10).len(), 10);
    }

    /// JPEG honey: payload must be recoverable byte-for-byte from after the EOI.
    #[test]
    fn jpeg_honey_roundtrip() {
        let dir = tmpdir("stego-jpeg");
        let path = dir.join("c.jpg");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, [0xFF, 0xD8, 0x01, 0x02, 0xFF, 0xD9]).unwrap();

        let payload = b"fake hidden secrets".to_vec();
        inject_jpeg_honey(ps, &payload, false).unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[0..2], &[0xFF, 0xD8], "SOI destroyed");
        let eoi = data.windows(2).rposition(|w| w == [0xFF, 0xD9]).unwrap();
        let trailer = &data[eoi + 2..];
        assert_eq!(&trailer[..10], b"OUTGUESS13", "fake tool magic missing");
        let len = u32::from_le_bytes(trailer[10..14].try_into().unwrap()) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(
            &trailer[14..14 + len],
            &payload[..],
            "payload not recoverable"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn jpeg_honey_rejects_non_jpeg() {
        let dir = tmpdir("stego-notjpeg");
        let path = dir.join("c.jpg");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, b"nope").unwrap();
        assert!(inject_jpeg_honey(ps, b"x", false).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// PNG honey: tEXt/zTXt chunks must land before IEND with consistent
    /// length fields and valid CRCs.
    #[test]
    fn png_honey_chunks_wellformed() {
        let dir = tmpdir("stego-png");
        let path = dir.join("c.png");
        let ps = path.to_str().unwrap();
        // Minimal PNG: signature + empty IEND (CRC of "IEND" is AE 42 60 82)
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
        std::fs::write(&path, &png).unwrap();

        let payload = generate_honey_payload(7, 256);
        inject_png_honey(ps, &payload, false).unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[..8], b"\x89PNG\r\n\x1a\n", "PNG signature destroyed");

        // Walk chunks: sig, then [len][type][data][crc]* — tEXt and zTXt before IEND.
        let mut pos = 8;
        let mut seen_text = false;
        let mut seen_ztxt = false;
        let mut last_type = [0u8; 4];
        while pos + 12 <= data.len() {
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let ctype: [u8; 4] = data[pos + 4..pos + 8].try_into().unwrap();
            let cdata = &data[pos + 8..pos + 8 + len];
            let crc = u32::from_be_bytes(data[pos + 8 + len..pos + 12 + len].try_into().unwrap());
            let mut crc_input = ctype.to_vec();
            crc_input.extend_from_slice(cdata);
            assert_eq!(png_crc32(&crc_input), crc, "bad CRC on {:?} chunk", ctype);
            match &ctype {
                b"tEXt" => {
                    seen_text = true;
                    assert!(cdata.starts_with(b"steganography\0"));
                }
                b"zTXt" => {
                    seen_ztxt = true;
                    assert!(cdata.starts_with(b"comment\0\0"));
                    assert_eq!(&cdata[9..11], &[0x78, 0x9C], "fake zlib header missing");
                }
                _ => {}
            }
            last_type = ctype;
            pos += 12 + len;
        }
        assert!(seen_text, "tEXt chunk missing");
        assert!(seen_ztxt, "zTXt chunk missing");
        assert_eq!(&last_type, b"IEND", "IEND must remain the last chunk");
        assert_eq!(pos, data.len(), "trailing garbage after IEND");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// WAV honey: bits must round-trip out of the sample LSBs exactly.
    #[test]
    fn wav_honey_lsb_roundtrip() {
        let dir = tmpdir("stego-wav");
        let path = dir.join("c.wav");
        let ps = path.to_str().unwrap();

        // 44-byte canonical WAV header + 16-bit PCM samples
        let n_samples = 4096usize;
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36u32 + (n_samples * 2) as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 1, 0]); // PCM, mono
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&16000u32.to_le_bytes());
        wav.extend_from_slice(&[2, 0, 16, 0]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&((n_samples * 2) as u32).to_le_bytes());
        // Non-trivial sample data (alternating pattern, LSBs will be overwritten)
        for i in 0..n_samples {
            wav.extend_from_slice(&((i as u16) * 3).to_le_bytes());
        }
        assert_eq!(wav.len(), 44 + n_samples * 2);
        std::fs::write(&path, &wav).unwrap();

        let payload = b"covert channel 123".to_vec();
        inject_wav_honey(ps, &payload, false).unwrap();

        // Decode: first 32 sample LSBs = length, then payload bits.
        let data = std::fs::read(&path).unwrap();
        let data_chunk = data.windows(4).position(|w| w == b"data").unwrap();
        let samples_start = data_chunk + 8;
        let get_bit = |i: usize| data[samples_start + i * 2] & 1;
        let mut len_bytes = [0u8; 4];
        for (i, b) in len_bytes.iter_mut().enumerate() {
            for bit in 0..8 {
                *b |= get_bit(i * 8 + bit) << bit;
            }
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        assert_eq!(len, payload.len());
        let mut decoded = vec![0u8; len];
        for (byte_idx, b) in decoded.iter_mut().enumerate() {
            for bit in 0..8 {
                *b |= get_bit(32 + byte_idx * 8 + bit) << bit;
            }
        }
        assert_eq!(decoded, payload, "LSB roundtrip mismatch");
        // High bytes of samples must be untouched
        assert_eq!(data[samples_start + 1], wav[samples_start + 1]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wav_honey_rejects_short_carrier() {
        let dir = tmpdir("stego-shortwav");
        let path = dir.join("c.wav");
        let ps = path.to_str().unwrap();
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&36u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&[0u8; 24]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[0u8; 4]);
        std::fs::write(&path, &wav).unwrap();
        assert!(inject_wav_honey(ps, b"way too much payload for this carrier", false).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trailer_honey_layout() {
        let dir = tmpdir("stego-trailer");
        let path = dir.join("doc.bin");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, b"ORIGINAL").unwrap();

        inject_trailer_honey(ps, b"PAYLOAD", b"SIG!", false).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(
            &data[..8],
            b"ORIGINAL",
            "original content must be untouched"
        );
        assert_eq!(&data[8..12], b"SIG!");
        assert_eq!(
            u32::from_le_bytes(data[12..16].try_into().unwrap()),
            7,
            "length field wrong"
        );
        assert_eq!(&data[16..], b"PAYLOAD");

        std::fs::remove_dir_all(&dir).ok();
    }
}
