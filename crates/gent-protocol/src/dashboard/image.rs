//! Inline still images only. Check dimensions before allocating a pixel buffer.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::Cursor;

const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
fn dimensions(width: u32, height: u32) -> bool {
    (1..=2048).contains(&width) && (1..=2048).contains(&height) && width * height <= 1_048_576
}

pub(super) fn valid(uri: &str) -> bool {
    if uri.len() > super::MAX_BOARD_BYTES {
        return false;
    }
    if let Some(payload) = uri.strip_prefix("data:image/png;base64,") {
        return STANDARD.decode(payload).is_ok_and(|bytes| png(&bytes));
    }
    if let Some(payload) = uri.strip_prefix("data:image/jpeg;base64,") {
        return STANDARD.decode(payload).is_ok_and(|bytes| jpeg(&bytes));
    }
    false
}

fn png(bytes: &[u8]) -> bool {
    if !bytes.ends_with(b"\0\0\0\0IEND\xaeB\x60\x82") {
        return false;
    }
    let mut input = Cursor::new(bytes);
    let mut decoder = png::Decoder::new(&mut input);
    decoder.set_limits(png::Limits {
        bytes: MAX_DECODED_BYTES,
    });
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let Ok(mut reader) = decoder.read_info() else {
        return false;
    };
    let info = reader.info();
    if !dimensions(info.width, info.height) || info.animation_control.is_some() {
        return false;
    }
    let Some(size) = reader
        .output_buffer_size()
        .filter(|n| *n <= MAX_DECODED_BYTES)
    else {
        return false;
    };
    reader.next_frame(&mut vec![0; size]).is_ok()
        && reader.finish().is_ok()
        && input.position() == bytes.len() as u64
}

fn jpeg(bytes: &[u8]) -> bool {
    if !bytes.ends_with(&[0xff, 0xd9]) {
        return false;
    }
    let mut input = bytes;
    let mut decoder = jpeg_decoder::Decoder::new(&mut input);
    decoder.set_max_decoding_buffer_size(MAX_DECODED_BYTES);
    decoder.read_info().is_ok()
        && decoder
            .info()
            .is_some_and(|i| dimensions(i.width.into(), i.height.into()))
        && decoder.decode().is_ok()
        && input.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Complete single-pixel grayscale files.
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNoAAAAggCBd81ytgAAAABJRU5ErkJggg==";
    const JPEG: &str = "/9j/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAALCAABAAEBAREA/8QAJgABAAAAAAAAAAAAAAAAAAAAABABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAAPwA//9k=";

    #[test]
    fn images_require_a_complete_file_matching_the_declared_media_type() {
        for (mime, sample) in [("png", PNG), ("jpeg", JPEG)] {
            let uri = |bytes: &[u8]| format!("data:image/{mime};base64,{}", STANDARD.encode(bytes));
            let bytes = STANDARD.decode(sample).unwrap();
            assert!(valid(&uri(&bytes)), "{mime}");
            assert!(!valid(&uri(&bytes[..bytes.len() - 2])));
            assert!(!valid(&uri(&[bytes.as_slice(), bytes.as_slice()].concat())));
            assert!(!valid(&format!("data:image/{mime};base64,not base64!")));
        }
        assert!(!valid(&format!("data:image/png;base64,{JPEG}")));
        assert!(!valid(&format!("data:image/jpeg;base64,{PNG}")));
        assert!(!valid("https://example.org/image.png"));
        assert!(!valid("data:image/svg+xml;base64,PHN2Zy8+"));
        let mut damaged = STANDARD.decode(PNG).unwrap();
        let idat = damaged.windows(4).position(|w| w == b"IDAT").unwrap();
        damaged[idat + 5] ^= 0xff;
        assert!(!png(&damaged));
    }

    #[test]
    fn image_limits_apply_before_decoding_pixels() {
        for (w, h) in [(2048, 512), (2049, 1), (1025, 1024)] {
            let mut bytes = Vec::new();
            let mut encoder = png::Encoder::new(&mut bytes, w, h);
            encoder.set_color(png::ColorType::Grayscale);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&vec![0; (w * h) as usize])
                .unwrap();
            assert_eq!(png(&bytes), w == 2048);
        }
        let mut oversized = STANDARD.decode(JPEG).unwrap();
        let sof = oversized
            .windows(2)
            .position(|v| v == [0xff, 0xc0])
            .unwrap();
        oversized[sof + 5..sof + 9].copy_from_slice(&[0x08, 0, 0x08, 0]);
        assert!(!jpeg(&oversized));
    }
}
