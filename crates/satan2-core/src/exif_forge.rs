// Forge embedded metadata in JPEG, PDF, and MP4 files.
//
// JPEG: rebuild APP1/EXIF segment (TIFF LE) with fake camera, GPS, timestamps.
//       Strips existing APP0/APP1 segments before injection.
// PDF:  inject /Info dictionary into trailer dict (text-level manipulation).
// MP4:  patch mvhd creation/modification timestamps + inject ©too encoder atom.
//
// All formats are written with pure Rust (no external image/codec crates).

use std::fs;

// ── Public options ────────────────────────────────────────────────────────────

pub struct ExifForgeOpts {
    pub make: String,         // camera manufacturer
    pub model: String,        // camera model
    pub software: String,     // editing software string
    pub artist: String,       // artist / copyright (empty = omit)
    pub datetime: String,     // "YYYY:MM:DD HH:MM:SS"
    pub gps_lat: Option<f64>, // decimal degrees, +N -S
    pub gps_lon: Option<f64>, // decimal degrees, +E -W
    pub iso: u16,
    pub focal_length_mm: u32,
    pub pixel_x: u32,
    pub pixel_y: u32,
    pub verbose: bool,
}

impl Default for ExifForgeOpts {
    fn default() -> Self {
        Self {
            make: "NIKON CORPORATION".into(),
            model: "NIKON D850".into(),
            software: "Adobe Photoshop 24.7.3 (Windows)".into(),
            artist: "".into(),
            datetime: "2023:11:07 09:42:18".into(),
            gps_lat: Some(48.8566), // Paris
            gps_lon: Some(2.3522),
            iso: 200,
            focal_length_mm: 50,
            pixel_x: 4720,
            pixel_y: 3152,
            verbose: false,
        }
    }
}

pub struct PdfMetaOpts {
    pub author: String,
    pub creator: String,
    pub producer: String,
    pub title: String,
    pub created: String, // D:YYYYMMDDHHmmSS
    pub modified: String,
    pub verbose: bool,
}

pub struct Mp4MetaOpts {
    pub encoder: String, // goes into ©too / ©enc atom
    pub ts_create: u32,  // seconds since 1904-01-01 (QuickTime/MP4 epoch)
    pub ts_modify: u32,
    pub verbose: bool,
}

// ── TIFF LE helpers ───────────────────────────────────────────────────────────

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

// Null-terminated ASCII padded to even byte count (TIFF alignment requirement)
fn tiff_ascii(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    if b.len() & 1 != 0 {
        b.push(0);
    }
    b
}

// RATIONAL: two u32 LE (numerator, denominator) = 8 bytes
fn rational(num: u32, den: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.extend(u32le(num));
    b.extend(u32le(den));
    b
}

// GPS decimal degrees → 3 RATIONALs (deg/min/sec), 24 bytes
fn dms_rationals(decimal: f64) -> Vec<u8> {
    let abs = decimal.abs();
    let deg = abs as u32;
    let min_f = (abs - deg as f64) * 60.0;
    let min = min_f as u32;
    let sec_n = ((min_f - min as f64) * 60_000.0) as u32;
    let mut b = Vec::with_capacity(24);
    b.extend(rational(deg, 1));
    b.extend(rational(min, 1));
    b.extend(rational(sec_n, 1000));
    b
}

// ── Build TIFF block (returned as Vec<u8> starting at offset 0) ───────────────
fn build_tiff(opts: &ExifForgeOpts) -> Vec<u8> {
    // Layout (all offsets from TIFF start = 0):
    //   [0..8]               TIFF header (II, 42, offset_to_IFD0=8)
    //   [8..8+IFD0_SZ]       IFD0
    //   [...]                IFD0 heap
    //   [...]                ExifIFD
    //   [...]                ExifIFD heap
    //   [...]                GPS IFD (if coords present)
    //   [...]                GPS IFD heap

    let has_gps = opts.gps_lat.is_some() && opts.gps_lon.is_some();

    // ── IFD0 entries and heap ─────────────────────────────────────────────────
    // We compute IFD0 size first to know where its heap starts.
    // IFD0 tags (must be ascending): 010F Make, 0110 Model, 0112 Orientation,
    //   011A XRes, 011B YRes, 0128 ResUnit, 0131 Software, 0132 DateTime,
    //   [013B Artist], 0213 YCbCrPos, 8769 ExifIFD, [8825 GPSIFD]
    let n_ifd0 = 10u16 + if !opts.artist.is_empty() { 1 } else { 0 } + if has_gps { 1 } else { 0 };
    let ifd0_offset: u32 = 8;
    let ifd0_sz = 2 + n_ifd0 as u32 * 12 + 4;
    let ifd0_heap_base = ifd0_offset + ifd0_sz;

    // We don't know ExifIFD/GPS offsets yet; build placeholder IFD0 heap first
    let make_bytes = tiff_ascii(&opts.make);
    let model_bytes = tiff_ascii(&opts.model);
    let sw_bytes = tiff_ascii(&opts.software);
    let dt_bytes = tiff_ascii(&opts.datetime);
    let art_bytes = if !opts.artist.is_empty() {
        tiff_ascii(&opts.artist)
    } else {
        vec![]
    };

    let mut ifd0_heap: Vec<u8> = Vec::new();
    let make_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(&make_bytes);
    let model_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(&model_bytes);
    let sw_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(&sw_bytes);
    let dt_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(&dt_bytes);
    let art_off = if !art_bytes.is_empty() {
        let o = ifd0_heap_base + ifd0_heap.len() as u32;
        ifd0_heap.extend(&art_bytes);
        o
    } else {
        0
    };
    let xres_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(rational(72, 1));
    let yres_off = ifd0_heap_base + ifd0_heap.len() as u32;
    ifd0_heap.extend(rational(72, 1));

    // ── ExifIFD (built to know its size) ─────────────────────────────────────
    // Tags: 8827 ISO, 829A ExpTime, 829D FNumber, 9000 ExifVer, 9003 DTOrig,
    //       9004 DTDig, 920A FocalLen, A001 ColorSpace, A002 PixX, A003 PixY,
    //       A401 CustomRend, A402 ExpMode, A403 WBal, A406 SceneCapType
    let n_exif: u16 = 14;
    let exif_ifd_offset = ifd0_heap_base + ifd0_heap.len() as u32;
    let exif_ifd_sz = 2 + n_exif as u32 * 12 + 4;
    let exif_heap_base = exif_ifd_offset + exif_ifd_sz;

    let dt_orig_bytes = tiff_ascii(&opts.datetime);
    let dt_dig_bytes = tiff_ascii(&opts.datetime);
    let mut exif_heap: Vec<u8> = Vec::new();
    let dt_orig_off = exif_heap_base + exif_heap.len() as u32;
    exif_heap.extend(&dt_orig_bytes);
    let dt_dig_off = exif_heap_base + exif_heap.len() as u32;
    exif_heap.extend(&dt_dig_bytes);
    let exp_off = exif_heap_base + exif_heap.len() as u32;
    exif_heap.extend(rational(1, 100));
    let fnum_off = exif_heap_base + exif_heap.len() as u32;
    exif_heap.extend(rational(28, 10));
    let focal_off = exif_heap_base + exif_heap.len() as u32;
    exif_heap.extend(rational(opts.focal_length_mm, 1));

    // ── GPS IFD ───────────────────────────────────────────────────────────────
    let gps_ifd_offset = exif_heap_base + exif_heap.len() as u32;
    let (gps_ifd_bytes, gps_heap_bytes) = if has_gps {
        let lat = opts.gps_lat.unwrap();
        let lon = opts.gps_lon.unwrap();
        let n_gps: u16 = 5;
        let gps_ifd_sz = 2 + n_gps as u32 * 12 + 4;
        let gps_heap_base = gps_ifd_offset + gps_ifd_sz;
        let mut gh: Vec<u8> = Vec::new();

        let lat_ref_bytes = [if lat >= 0.0 { b'N' } else { b'S' }, 0u8];
        let lat_ref_off = gps_heap_base + gh.len() as u32;
        gh.extend(&lat_ref_bytes);
        let lat_dms = dms_rationals(lat);
        let lat_off = gps_heap_base + gh.len() as u32;
        gh.extend(&lat_dms);
        let lon_ref_bytes = [if lon >= 0.0 { b'E' } else { b'W' }, 0u8];
        let lon_ref_off = gps_heap_base + gh.len() as u32;
        gh.extend(&lon_ref_bytes);
        let lon_dms = dms_rationals(lon);
        let lon_off = gps_heap_base + gh.len() as u32;
        gh.extend(&lon_dms);
        let datum = tiff_ascii("WGS-84");
        let datum_off = gps_heap_base + gh.len() as u32;
        gh.extend(&datum);

        let mut gi: Vec<u8> = Vec::new();
        gi.extend(u16le(n_gps));
        for &(tag, typ, count, off) in &[
            (0x0001u16, 2u16, 2u32, lat_ref_off),
            (0x0002, 5, 3, lat_off),
            (0x0003, 2, 2, lon_ref_off),
            (0x0004, 5, 3, lon_off),
            (0x0012, 2, datum.len() as u32, datum_off),
        ] {
            gi.extend(u16le(tag));
            gi.extend(u16le(typ));
            gi.extend(u32le(count));
            gi.extend(u32le(off));
        }
        gi.extend(u32le(0));
        (gi, gh)
    } else {
        (vec![], vec![])
    };

    // ── Assemble IFD0 ─────────────────────────────────────────────────────────
    // Helper: write inline SHORT (4-byte field, value in first 2 bytes LE, rest 0)
    fn short_inline(v: u16) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0..2].copy_from_slice(&v.to_le_bytes());
        b
    }

    let mut ifd0: Vec<u8> = Vec::new();
    ifd0.extend(u16le(n_ifd0));

    // Write entries in tag ascending order (TIFF requirement); heap offsets pre-computed above.
    ifd0.extend(u16le(0x010F));
    ifd0.extend(u16le(2));
    ifd0.extend(u32le(make_bytes.len() as u32));
    ifd0.extend(u32le(make_off));
    ifd0.extend(u16le(0x0110));
    ifd0.extend(u16le(2));
    ifd0.extend(u32le(model_bytes.len() as u32));
    ifd0.extend(u32le(model_off));
    ifd0.extend(u16le(0x0112));
    ifd0.extend(u16le(3));
    ifd0.extend(u32le(1));
    ifd0.extend(&short_inline(1)); // Orientation: top-left
    ifd0.extend(u16le(0x011A));
    ifd0.extend(u16le(5));
    ifd0.extend(u32le(1));
    ifd0.extend(u32le(xres_off));
    ifd0.extend(u16le(0x011B));
    ifd0.extend(u16le(5));
    ifd0.extend(u32le(1));
    ifd0.extend(u32le(yres_off));
    ifd0.extend(u16le(0x0128));
    ifd0.extend(u16le(3));
    ifd0.extend(u32le(1));
    ifd0.extend(&short_inline(2)); // ResolutionUnit: inch
    ifd0.extend(u16le(0x0131));
    ifd0.extend(u16le(2));
    ifd0.extend(u32le(sw_bytes.len() as u32));
    ifd0.extend(u32le(sw_off));
    ifd0.extend(u16le(0x0132));
    ifd0.extend(u16le(2));
    ifd0.extend(u32le(dt_bytes.len() as u32));
    ifd0.extend(u32le(dt_off));
    if !art_bytes.is_empty() {
        ifd0.extend(u16le(0x013B));
        ifd0.extend(u16le(2));
        ifd0.extend(u32le(art_bytes.len() as u32));
        ifd0.extend(u32le(art_off));
    }
    ifd0.extend(u16le(0x0213));
    ifd0.extend(u16le(3));
    ifd0.extend(u32le(1));
    ifd0.extend(&short_inline(1)); // YCbCrPositioning
    ifd0.extend(u16le(0x8769));
    ifd0.extend(u16le(4));
    ifd0.extend(u32le(1));
    ifd0.extend(u32le(exif_ifd_offset));
    if has_gps {
        ifd0.extend(u16le(0x8825));
        ifd0.extend(u16le(4));
        ifd0.extend(u32le(1));
        ifd0.extend(u32le(gps_ifd_offset));
    }
    ifd0.extend(u32le(0)); // next IFD = none

    // ── Assemble ExifIFD ─────────────────────────────────────────────────────
    let mut exif_ifd: Vec<u8> = Vec::new();
    exif_ifd.extend(u16le(n_exif));
    exif_ifd.extend(u16le(0x8827));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(opts.iso)); // ISO
    exif_ifd.extend(u16le(0x829A));
    exif_ifd.extend(u16le(5));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(u32le(exp_off)); // ExposureTime
    exif_ifd.extend(u16le(0x829D));
    exif_ifd.extend(u16le(5));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(u32le(fnum_off)); // FNumber
                                      // ExifVersion: 4-byte UNDEFINED "0232" (inline)
    exif_ifd.extend(u16le(0x9000));
    exif_ifd.extend(u16le(7));
    exif_ifd.extend(u32le(4));
    exif_ifd.extend(b"0232");
    exif_ifd.extend(u16le(0x9003));
    exif_ifd.extend(u16le(2));
    exif_ifd.extend(u32le(dt_orig_bytes.len() as u32));
    exif_ifd.extend(u32le(dt_orig_off));
    exif_ifd.extend(u16le(0x9004));
    exif_ifd.extend(u16le(2));
    exif_ifd.extend(u32le(dt_dig_bytes.len() as u32));
    exif_ifd.extend(u32le(dt_dig_off));
    exif_ifd.extend(u16le(0x920A));
    exif_ifd.extend(u16le(5));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(u32le(focal_off)); // FocalLength
    exif_ifd.extend(u16le(0xA001));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(1)); // ColorSpace: sRGB
    exif_ifd.extend(u16le(0xA002));
    exif_ifd.extend(u16le(4));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(u32le(opts.pixel_x)); // PixelXDimension
    exif_ifd.extend(u16le(0xA003));
    exif_ifd.extend(u16le(4));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(u32le(opts.pixel_y)); // PixelYDimension
    exif_ifd.extend(u16le(0xA401));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(0)); // CustomRendered: normal
    exif_ifd.extend(u16le(0xA402));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(0)); // ExposureMode: auto
    exif_ifd.extend(u16le(0xA403));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(0)); // WhiteBalance: auto
    exif_ifd.extend(u16le(0xA406));
    exif_ifd.extend(u16le(3));
    exif_ifd.extend(u32le(1));
    exif_ifd.extend(&short_inline(0)); // SceneCaptureType
    exif_ifd.extend(u32le(0));

    // ── Concatenate everything into TIFF blob ─────────────────────────────────
    let mut tiff: Vec<u8> = Vec::new();
    tiff.extend(b"II"); // little-endian marker
    tiff.extend(u16le(42)); // TIFF magic
    tiff.extend(u32le(8)); // IFD0 at offset 8
    tiff.extend(ifd0);
    tiff.extend(ifd0_heap);
    tiff.extend(exif_ifd);
    tiff.extend(exif_heap);
    tiff.extend(gps_ifd_bytes);
    tiff.extend(gps_heap_bytes);
    tiff
}

fn build_app1(opts: &ExifForgeOpts) -> Vec<u8> {
    let tiff = build_tiff(opts);
    // APP1 = FF E1 + length(2 BE, includes itself) + "Exif\0\0" + TIFF
    let payload_len = 2 + 6 + tiff.len(); // length field + "Exif\0\0" + tiff
    let mut app1 = Vec::new();
    app1.extend(&[0xFF, 0xE1]);
    app1.extend(&(payload_len as u16).to_be_bytes());
    app1.extend(b"Exif\0\0");
    app1.extend(tiff);
    app1
}

pub fn forge_jpeg_exif(path: &str, opts: &ExifForgeOpts) -> crate::Result<()> {
    let data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(format!("{}: not a JPEG (no SOI)", path));
    }
    // Skip existing APP0 (FFE0) and APP1 (FFE1) segments right after SOI
    let mut skip_end = 2usize;
    while skip_end + 3 < data.len() {
        let m = data[skip_end + 1];
        if data[skip_end] == 0xFF && (m == 0xE0 || m == 0xE1) {
            let seg_len = u16::from_be_bytes([data[skip_end + 2], data[skip_end + 3]]) as usize;
            skip_end += 2 + seg_len;
        } else {
            break;
        }
    }
    let mut out = Vec::new();
    out.extend(&[0xFF, 0xD8]); // SOI
    out.extend(build_app1(opts)); // new EXIF
    out.extend(&data[skip_end..]); // rest of JPEG
    fs::write(path, &out).map_err(|e| format!("write {}: {}", path, e))?;
    if opts.verbose {
        eprintln!("[+] exif-forge: JPEG {} — {} B", path, out.len());
    }
    Ok(())
}

// ── PDF metadata forge ────────────────────────────────────────────────────────
// Appends a new obj 1 0 /Info dictionary and patches the trailer to reference it.
// Works on linearized and non-linearized PDFs with a text-accessible trailer.

pub fn forge_pdf_metadata(path: &str, opts: &PdfMetaOpts) -> crate::Result<()> {
    let data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let src = String::from_utf8_lossy(&data);

    // Build the /Info object (object number 9999 to avoid collisions)
    let info_obj = format!(
        "\n9999 0 obj\n<< /Author ({author}) /Creator ({creator}) /Producer ({producer}) \
        /CreationDate (D:{created}) /ModDate (D:{modified}) >>\nendobj\n",
        author = opts.author,
        creator = opts.creator,
        producer = opts.producer,
        created = opts.created,
        modified = opts.modified,
    );

    // Find %%EOF and inject before it, patching trailer to add /Info ref
    let eof_pos = src.rfind("%%EOF").ok_or("PDF: %%EOF not found")?;
    let before_eof = &src[..eof_pos];

    let patched = if let Some(t) = before_eof.rfind("trailer") {
        // Inject /Info into existing trailer dict
        let trailer_src = &before_eof[t..];
        let fixed = if trailer_src.contains("/Info") {
            trailer_src.to_string()
        } else {
            trailer_src.replacen("<<", "<< /Info 9999 0 R ", 1)
        };
        format!("{}{}\n{}%%EOF\n", &before_eof[..t], fixed, info_obj)
    } else {
        // No trailer keyword — append object + comment
        format!("{}{}%%EOF\n", before_eof, info_obj)
    };

    fs::write(path, patched.as_bytes()).map_err(|e| format!("write {}: {}", path, e))?;
    if opts.verbose {
        eprintln!("[+] exif-forge: PDF {} — /Info injected", path);
    }
    Ok(())
}

// ── MP4 metadata forge ────────────────────────────────────────────────────────
// Patches mvhd creation/modification timestamps and injects a ©too encoder atom.

fn find_box_offset(data: &[u8], name: &[u8; 4]) -> Option<usize> {
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let sz = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        if sz < 8 || sz > data.len() - i {
            break;
        }
        if &data[i + 4..i + 8] == name.as_ref() {
            return Some(i);
        }
        i += sz;
    }
    None
}

pub fn forge_mp4_metadata(path: &str, opts: &Mp4MetaOpts) -> crate::Result<()> {
    let mut data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;

    let moov_off =
        find_box_offset(&data, b"moov").ok_or_else(|| format!("{}: no moov box", path))?;
    let moov_sz = u32::from_be_bytes([
        data[moov_off],
        data[moov_off + 1],
        data[moov_off + 2],
        data[moov_off + 3],
    ]) as usize;

    // ── Patch mvhd timestamps ─────────────────────────────────────────────────
    if let Some(mvhd_rel) = find_box_offset(&data[moov_off + 8..moov_off + moov_sz], b"mvhd") {
        let mvhd = moov_off + 8 + mvhd_rel;
        let version = data[mvhd + 8];
        if version == 0 {
            // creation_time @ +12, modification_time @ +16 (u32 BE)
            data[mvhd + 12..mvhd + 16].copy_from_slice(&opts.ts_create.to_be_bytes());
            data[mvhd + 16..mvhd + 20].copy_from_slice(&opts.ts_modify.to_be_bytes());
        } else {
            // version 1: times are u64 BE @ +12 and +20
            data[mvhd + 12..mvhd + 20].copy_from_slice(&(opts.ts_create as u64).to_be_bytes());
            data[mvhd + 20..mvhd + 28].copy_from_slice(&(opts.ts_modify as u64).to_be_bytes());
        }
        if opts.verbose {
            eprintln!("[+] exif-forge: MP4 mvhd timestamps patched (v{})", version);
        }
    }

    // ── Inject ©too encoder atom inside udta ─────────────────────────────────
    // ©too box layout: [size:4][name:4=©too][data-box: [size:4][data:4][type:4=1][locale:4=0][utf8]]
    let enc = opts.encoder.as_bytes();
    let data_box_sz = 4 + 4 + 4 + 4 + enc.len(); // "data" + type_flag + locale + string
    let too_sz = 8 + data_box_sz;
    let mut too_atom: Vec<u8> = Vec::with_capacity(too_sz);
    too_atom.extend(&(too_sz as u32).to_be_bytes());
    too_atom.extend(b"\xc2\xa9too"); // ©too (UTF-8, 4 bytes: C2 A9 74 6F 6F)

    // Wait — "©" in UTF-8 is 0xC2 0xA9, that's 2 bytes + "too" = 5 bytes. Box names must be 4 bytes.
    // The correct atom name is the literal 4 bytes: 0xA9 0x74 0x6F 0x6F (©too in Latin-1 / MacRoman)
    // Replace the last push:
    let too_sz_corrected = 8 + data_box_sz;
    too_atom.clear();
    too_atom.extend(&(too_sz_corrected as u32).to_be_bytes());
    too_atom.extend(&[0xA9, b't', b'o', b'o']); // ©too in MP4 atom name (Latin-1 ©)
    too_atom.extend(&(data_box_sz as u32).to_be_bytes());
    too_atom.extend(b"data");
    too_atom.extend(&1u32.to_be_bytes()); // type: UTF-8
    too_atom.extend(&0u32.to_be_bytes()); // locale: 0
    too_atom.extend(enc);

    // Find or create udta inside moov, then insert ©too
    let udta_rel = find_box_offset(&data[moov_off + 8..moov_off + moov_sz], b"udta");
    let delta = too_atom.len() as u32;

    if let Some(rel) = udta_rel {
        let udta_off = moov_off + 8 + rel;
        let udta_sz = u32::from_be_bytes([
            data[udta_off],
            data[udta_off + 1],
            data[udta_off + 2],
            data[udta_off + 3],
        ]) as usize;
        let insert = udta_off + udta_sz;
        data.splice(insert..insert, too_atom);
        // Fix udta size
        let new_udta = (udta_sz as u32 + delta).to_be_bytes();
        data[udta_off..udta_off + 4].copy_from_slice(&new_udta);
    } else {
        // Create udta wrapper around ©too
        let udta_sz = 8 + too_atom.len();
        let mut udta = Vec::with_capacity(udta_sz);
        udta.extend(&(udta_sz as u32).to_be_bytes());
        udta.extend(b"udta");
        udta.extend(&too_atom);
        let insert = moov_off + moov_sz;
        data.splice(insert..insert, udta);
    }

    // Fix moov size
    let new_moov = (moov_sz as u32 + delta + if udta_rel.is_none() { 8 } else { 0 }).to_be_bytes();
    data[moov_off..moov_off + 4].copy_from_slice(&new_moov);

    fs::write(path, &data).map_err(|e| format!("write {}: {}", path, e))?;
    if opts.verbose {
        eprintln!("[+] exif-forge: MP4 {} — ©too='{}'", path, opts.encoder);
    }
    Ok(())
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
    fn tiff_ascii_padding() {
        assert_eq!(tiff_ascii("ABC"), b"ABC\0".to_vec()); // 4 bytes: already even
        assert_eq!(tiff_ascii("AB"), b"AB\0\0".to_vec()); // padded to even
        assert_eq!(tiff_ascii("").len() % 2, 0);
    }

    #[test]
    fn dms_conversion() {
        let r = dms_rationals(48.8566);
        assert_eq!(r.len(), 24);
        let deg = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let min = u32::from_le_bytes(r[8..12].try_into().unwrap());
        assert_eq!(deg, 48);
        assert_eq!(min, 51); // 0.8566 * 60 = 51.396
                             // Negative latitude: DMS uses absolute value (hemisphere stored separately)
        let r2 = dms_rationals(-48.8566);
        assert_eq!(u32::from_le_bytes(r2[0..4].try_into().unwrap()), 48);
    }

    /// Forge EXIF into a minimal JPEG; the result must keep SOI/EOI framing and
    /// carry a well-formed APP1/Exif/TIFF segment with the forged fields.
    #[test]
    fn jpeg_forge_produces_valid_exif_segment() {
        let dir = tmpdir("exif-jpeg");
        let path = dir.join("img.jpg");
        let ps = path.to_str().unwrap();
        // Minimal JPEG: SOI + EOI
        std::fs::write(&path, [0xFF, 0xD8, 0xFF, 0xD9]).unwrap();

        let opts = ExifForgeOpts::default();
        forge_jpeg_exif(ps, &opts).unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[0..2], &[0xFF, 0xD8], "SOI destroyed");
        assert_eq!(&data[data.len() - 2..], &[0xFF, 0xD9], "EOI destroyed");
        assert_eq!(&data[2..4], &[0xFF, 0xE1], "APP1 marker must follow SOI");

        // APP1 length field (BE, includes itself) must bound the segment.
        let seg_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        assert_eq!(&data[6..12], b"Exif\0\0", "missing Exif preamble");
        assert!(2 + seg_len <= data.len(), "APP1 length overruns file");

        // TIFF header: II, magic 42, IFD0 at offset 8
        let tiff = &data[12..];
        assert_eq!(&tiff[0..2], b"II");
        assert_eq!(u16::from_le_bytes([tiff[2], tiff[3]]), 42);
        assert_eq!(u32::from_le_bytes(tiff[4..8].try_into().unwrap()), 8);

        // Forged strings must be present somewhere in the TIFF block
        let tiff_end = 12 + seg_len - 2 - 6;
        let tiff_block = &data[12..tiff_end];
        let contains = |needle: &[u8]| tiff_block.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b"NIKON CORPORATION"), "make missing");
        assert!(contains(b"NIKON D850"), "model missing");
        assert!(contains(b"2023:11:07 09:42:18"), "datetime missing");
        assert!(contains(b"WGS-84"), "GPS datum missing");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Re-forging must strip the previous APP1 rather than stacking segments.
    #[test]
    fn jpeg_reforge_strips_old_app1() {
        let dir = tmpdir("exif-reforge");
        let path = dir.join("img.jpg");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, [0xFF, 0xD8, 0xFF, 0xD9]).unwrap();

        let opts = ExifForgeOpts::default();
        forge_jpeg_exif(ps, &opts).unwrap();
        forge_jpeg_exif(ps, &opts).unwrap();

        let data = std::fs::read(&path).unwrap();
        let app1_count = data.windows(2).filter(|w| *w == [0xFF, 0xE1]).count();
        assert_eq!(app1_count, 1, "re-forge must not stack APP1 segments");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn jpeg_forge_rejects_non_jpeg() {
        let dir = tmpdir("exif-notjpeg");
        let path = dir.join("img.jpg");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, b"NOT A JPEG").unwrap();
        assert!(forge_jpeg_exif(ps, &ExifForgeOpts::default()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pdf_forge_injects_info_dict() {
        let dir = tmpdir("exif-pdf");
        let path = dir.join("doc.pdf");
        let ps = path.to_str().unwrap();
        let pdf =
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
        std::fs::write(&path, pdf).unwrap();

        let opts = PdfMetaOpts {
            author: "J. Random Author".into(),
            creator: "LaTeX".into(),
            producer: "pdfTeX 1.40".into(),
            title: "".into(),
            created: "20200101000000".into(),
            modified: "20200601000000".into(),
            verbose: false,
        };
        forge_pdf_metadata(ps, &opts).unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(
            out.contains("/Info 9999 0 R"),
            "trailer not patched: {}",
            out
        );
        assert!(
            out.contains("/Author (J. Random Author)"),
            "info object missing"
        );
        assert!(out.contains("/CreationDate (D:20200101000000)"));
        assert!(out.trim_end().ends_with("%%EOF"), "EOF marker lost");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pdf_forge_rejects_missing_eof() {
        let dir = tmpdir("exif-pdfbad");
        let path = dir.join("doc.pdf");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, b"%PDF-1.4\nno eof marker here\n").unwrap();
        let opts = PdfMetaOpts {
            author: String::new(),
            creator: String::new(),
            producer: String::new(),
            title: String::new(),
            created: String::new(),
            modified: String::new(),
            verbose: false,
        };
        assert!(forge_pdf_metadata(ps, &opts).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a minimal MP4: ftyp box + moov box containing a version-0 mvhd.
    fn minimal_mp4() -> Vec<u8> {
        let mut mvhd_body = vec![0u8; 100]; // version(1)+flags(3)+times+...
        mvhd_body[0] = 0; // version 0
        let mut mvhd = Vec::new();
        mvhd.extend(&(8u32 + mvhd_body.len() as u32).to_be_bytes());
        mvhd.extend(b"mvhd");
        mvhd.extend(&mvhd_body);

        let mut moov = Vec::new();
        moov.extend(&(8u32 + mvhd.len() as u32).to_be_bytes());
        moov.extend(b"moov");
        moov.extend(&mvhd);

        let mut ftyp = Vec::new();
        ftyp.extend(&24u32.to_be_bytes());
        ftyp.extend(b"ftyp");
        ftyp.extend(b"isom\0\0\x02\0isomiso2");

        let mut data = ftyp;
        data.extend(&moov);
        data
    }

    #[test]
    fn mp4_forge_patches_mvhd_and_injects_too() {
        let dir = tmpdir("exif-mp4");
        let path = dir.join("vid.mp4");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, minimal_mp4()).unwrap();

        let opts = Mp4MetaOpts {
            encoder: "Lavf60.3.100".into(),
            ts_create: 3_600_000_000,
            ts_modify: 3_600_000_001,
            verbose: false,
        };
        forge_mp4_metadata(ps, &opts).unwrap();

        let data = std::fs::read(&path).unwrap();
        let moov_off = find_box_offset(&data, b"moov").expect("moov lost");
        let mvhd_rel = find_box_offset(&data[moov_off + 8..], b"mvhd").expect("mvhd lost");
        let mvhd = moov_off + 8 + mvhd_rel;
        assert_eq!(
            u32::from_be_bytes(data[mvhd + 12..mvhd + 16].try_into().unwrap()),
            3_600_000_000,
            "creation time not patched"
        );
        assert_eq!(
            u32::from_be_bytes(data[mvhd + 16..mvhd + 20].try_into().unwrap()),
            3_600_000_001,
            "modification time not patched"
        );

        // ©too atom (0xA9 't' 'o' 'o') with the encoder string, inside udta
        let too_pos = data
            .windows(4)
            .position(|w| w == [0xA9, b't', b'o', b'o'])
            .expect("©too atom missing");
        let enc_pos = data
            .windows(12)
            .position(|w| w == b"Lavf60.3.100")
            .expect("encoder string missing");
        assert!(enc_pos > too_pos, "encoder string must follow ©too header");

        // moov size must account for the injected udta+©too
        let moov_sz = u32::from_be_bytes(data[moov_off..moov_off + 4].try_into().unwrap()) as usize;
        assert_eq!(
            moov_off + moov_sz,
            data.len(),
            "moov size inconsistent after injection"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mp4_forge_rejects_no_moov() {
        let dir = tmpdir("exif-mp4bad");
        let path = dir.join("vid.mp4");
        let ps = path.to_str().unwrap();
        std::fs::write(&path, b"garbage").unwrap();
        let opts = Mp4MetaOpts {
            encoder: "x".into(),
            ts_create: 0,
            ts_modify: 0,
            verbose: false,
        };
        assert!(forge_mp4_metadata(ps, &opts).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
