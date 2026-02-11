use std::io::{self, Write};

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = bytes[i + 2];
        i += 3;

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0b0000_0011) << 4 | (b1 >> 4)) as usize] as char);
        out.push(TABLE[((b1 & 0b0000_1111) << 2 | (b2 >> 6)) as usize] as char);
        out.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
    }

    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i];
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0b0000_0011) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0b0000_0011) << 4 | (b1 >> 4)) as usize] as char);
        out.push(TABLE[((b1 & 0b0000_1111) << 2) as usize] as char);
        out.push('=');
    }

    out
}

// Copies text through OSC52 so it works in remote terminal sessions.
pub fn copy_text_via_osc52(text: &str) -> io::Result<()> {
    // Keep payload reasonably bounded for terminals/tmux that cap OSC52 length.
    const MAX_BYTES: usize = 100_000;
    let bytes = text.as_bytes();
    let slice = if bytes.len() > MAX_BYTES {
        &bytes[..MAX_BYTES]
    } else {
        bytes
    };
    let encoded = base64_encode(slice);
    let sequence = format!("\x1b]52;c;{}\x07", encoded);
    let mut stdout = io::stdout();
    stdout.write_all(sequence.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
