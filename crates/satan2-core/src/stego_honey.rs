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
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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
        if col == 0 && out.len() > 0 { out.push(b'\n'); }
        out.push(b64[(next() as usize) % 64]);
    }

    let footer = b"\n-----END RSA PRIVATE KEY-----\n";
    out.extend_from_slice(&footer[..footer.len().min(size.saturating_sub(out.len()))]);
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
    if verbose { eprintln!("[+] stego-honey: JPEG {} — {} B injected after EOI", path, honey.len()); }
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
                for _ in 0..8 { c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 }; }
                TABLE[n as usize] = c;
            }
            INIT = true;
        }
        let mut c = !0u32;
        for &b in data { c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8); }
        !c
    }
}

fn png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes()); // length
    chunk.extend_from_slice(chunk_type);                          // type
    chunk.extend_from_slice(data);                                // data
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
    let iend_pos = data.windows(8)
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
        if i % 64 == 63 { text_data.push(b'\n'); }
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
        eprintln!("[+] stego-honey: PNG {} — tEXt+zTXt chunks injected ({} B payload)",
            path, payload.len());
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
    let data_chunk = data.windows(4)
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
        return Err(format!("{}: not enough samples to encode {} B payload", path, payload.len()));
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
            if sample_idx + 1 >= data.len() { break; }
            let bit_val = (byte >> bit) & 1;
            data[sample_idx] = (data[sample_idx] & 0xFE) | bit_val;
        }
    }

    fs::write(path, &data).map_err(|e| format!("write {}: {}", path, e))?;
    if verbose {
        eprintln!("[+] stego-honey: WAV {} — {} B encoded in sample LSBs ({} samples used)",
            path, payload.len(), payload_bits + 32);
    }
    Ok(())
}

// ── Generic trailer append ────────────────────────────────────────────────────
// Appends payload after the file's natural end with a fake tool signature header.
// Works as a fallback for any file type (Office, PDF, MP4, etc.).

pub fn inject_trailer_honey(path: &str, payload: &[u8], tool_sig: &[u8], verbose: bool) -> crate::Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    // Write: [sig][len:4 LE][payload]
    f.write_all(tool_sig).map_err(|e| e.to_string())?;
    f.write_all(&(payload.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(payload).map_err(|e| e.to_string())?;
    if verbose {
        eprintln!("[+] stego-honey: trailer {} — sig={:?} {} B", path,
            String::from_utf8_lossy(tool_sig), payload.len());
    }
    Ok(())
}

// ── Convenience: inject honey into all supported files in a directory ─────────

pub fn inject_directory_honey(dir: &str, seed: u64, payload_size: usize, verbose: bool) -> u32 {
    let mut count = 0u32;
    let walker = walkdir::WalkDir::new(dir).max_depth(3).into_iter();
    for entry in walker.flatten() {
        if !entry.file_type().is_file() { continue; }
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
        if ok { count += 1; }
    }
    count
}
