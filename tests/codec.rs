use mpc_relay::codec::{unescape, CodecError, Decoder, Frame, MAX_HEADERS};

const MAX: usize = 4096;

fn decode_all(bytes: &[u8], max: usize) -> Result<Vec<Frame>, CodecError> {
    let mut d = Decoder::new(max);
    d.extend(bytes);
    let mut out = Vec::new();
    while let Some(f) = d.decode()? {
        out.push(f);
    }
    Ok(out)
}

fn one(bytes: &[u8]) -> Frame {
    let mut frames = decode_all(bytes, MAX).expect("decodes");
    assert_eq!(frames.len(), 1, "exactly one frame");
    frames.remove(0)
}

#[test]
fn parses_a_frame() {
    let f = one(b"SEND\ndestination:/exchange/ex/k\ncontent-type:text/plain\n\nhello\0");
    assert_eq!(f.command, "SEND");
    assert_eq!(f.header("destination"), Some("/exchange/ex/k"));
    assert_eq!(f.header("content-type"), Some("text/plain"));
    assert_eq!(&f.body[..], b"hello");
}

#[test]
fn frame_split_across_every_byte_boundary() {
    let wire = b"SEND\ndestination:/exchange/ex/k\nreceipt:r1\n\nsplit body\0";
    let expected = one(wire);
    let mut d = Decoder::new(MAX);
    let mut got = Vec::new();
    for b in wire.iter() {
        d.extend(std::slice::from_ref(b));
        while let Some(f) = d.decode().unwrap() {
            got.push(f);
        }
    }
    assert_eq!(got, vec![expected]);
    assert_eq!(d.buffered(), 0);
}

#[test]
fn frame_split_at_every_position_into_two_messages() {
    let wire = b"SEND\ndestination:/x\ncontent-length:3\n\na\0b\0\n";
    let expected = one(wire);
    for cut in 0..wire.len() {
        let mut d = Decoder::new(MAX);
        d.extend(&wire[..cut]);
        let mut got = Vec::new();
        while let Some(f) = d.decode().unwrap() {
            got.push(f);
        }
        d.extend(&wire[cut..]);
        while let Some(f) = d.decode().unwrap() {
            got.push(f);
        }
        assert_eq!(got, vec![expected.clone()], "cut at {cut}");
    }
}

#[test]
fn several_frames_and_heartbeats_in_one_message() {
    let wire = b"\n\r\nSEND\ndestination:/a\n\none\0\n\nSEND\ndestination:/b\n\ntwo\0\r\n\nDISCONNECT\nreceipt:z\n\n\0\n";
    let frames = decode_all(wire, MAX).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].header("destination"), Some("/a"));
    assert_eq!(&frames[0].body[..], b"one");
    assert_eq!(&frames[1].body[..], b"two");
    assert_eq!(frames[2].command, "DISCONNECT");
    assert_eq!(frames[2].header("receipt"), Some("z"));
}

#[test]
fn heartbeats_alone_yield_nothing_and_are_consumed() {
    let mut d = Decoder::new(MAX);
    d.extend(b"\n\n\r\n\n");
    assert_eq!(d.decode().unwrap(), None);
    assert_eq!(d.buffered(), 0);
}

#[test]
fn crlf_line_endings() {
    let f = one(b"SEND\r\ndestination:/x\r\nfoo:bar\r\n\r\nbody\0");
    assert_eq!(f.header("destination"), Some("/x"));
    assert_eq!(f.header("foo"), Some("bar"));
    assert_eq!(&f.body[..], b"body");
}

#[test]
fn content_length_allows_nul_in_body() {
    let mut wire = b"SEND\ndestination:/x\ncontent-length:5\n\n".to_vec();
    wire.extend_from_slice(&[1, 0, 2, 0, 3]);
    wire.push(0);
    let f = one(&wire);
    assert_eq!(&f.body[..], &[1, 0, 2, 0, 3]);
}

#[test]
fn content_length_zero() {
    let f = one(b"SEND\ndestination:/x\ncontent-length:0\n\n\0");
    assert!(f.body.is_empty());
}

#[test]
fn content_length_waits_for_the_whole_body() {
    let mut d = Decoder::new(MAX);
    d.extend(b"SEND\ncontent-length:4\n\nab\0");
    assert_eq!(
        d.decode().unwrap(),
        None,
        "a NUL inside a sized body is not the end"
    );
    d.extend(b"c\0");
    let f = d.decode().unwrap().unwrap();
    assert_eq!(&f.body[..], b"ab\0c");
}

#[test]
fn content_length_shorter_than_body_is_an_error() {
    assert_eq!(
        decode_all(b"SEND\ncontent-length:2\n\nabc\0", MAX),
        Err(CodecError::Malformed("body longer than content-length"))
    );
}

#[test]
fn invalid_content_length() {
    for v in ["abc", "-1", "1.5", ""] {
        let wire = format!("SEND\ncontent-length:{v}\n\n\0");
        assert_eq!(
            decode_all(wire.as_bytes(), MAX),
            Err(CodecError::BadContentLength),
            "content-length:{v}"
        );
    }
}

#[test]
fn header_unescaping() {
    let f = one(b"SEND\nkey\\cwith\\ccolons:line\\nbreak\\r\\\\slash\n\n\0");
    assert_eq!(f.header("key:with:colons"), Some("line\nbreak\r\\slash"));
}

#[test]
fn connect_headers_are_not_unescaped() {
    let f = one(b"CONNECT\naccept-version:1.2\npasscode:a\\cb\\x\n\n\0");
    assert_eq!(f.header("passcode"), Some("a\\cb\\x"));
}

#[test]
fn invalid_escape_is_an_error() {
    assert_eq!(
        decode_all(b"SEND\nk:a\\tb\n\n\0", MAX),
        Err(CodecError::InvalidEscape)
    );
    assert_eq!(
        decode_all(b"SEND\nk:trailing\\\n\n\0", MAX),
        Err(CodecError::InvalidEscape)
    );
    assert_eq!(unescape(b"ok\\c"), Ok("ok:".into()));
}

#[test]
fn encode_escapes_and_roundtrips() {
    let f = Frame::new("MESSAGE")
        .with_header("subscription", "a:b\nc\\d\re")
        .with_header("content-length", "3")
        .with_body(&b"x\0y"[..]);
    let wire = f.encode();
    assert!(wire.starts_with(b"MESSAGE\nsubscription:a\\cb\\nc\\\\d\\re\n"));
    assert_eq!(one(&wire), f);
}

#[test]
fn connected_is_not_escaped() {
    let wire = Frame::new("CONNECTED")
        .with_header("server", "mpc-relay/1:2")
        .encode();
    assert_eq!(wire, b"CONNECTED\nserver:mpc-relay/1:2\n\n\0".to_vec());
}

#[test]
fn repeated_header_first_wins() {
    let f = one(b"SEND\nfoo:first\nfoo:second\n\n\0");
    assert_eq!(f.header("foo"), Some("first"));
    assert_eq!(f.headers.len(), 2);
}

#[test]
fn raw_colon_in_value_is_kept() {
    let f = one(b"SEND\nk:a:b:c\n\n\0");
    assert_eq!(f.header("k"), Some("a:b:c"));
}

#[test]
fn malformed_frames() {
    assert_eq!(
        decode_all(b"send\n\n\0", MAX),
        Err(CodecError::Malformed("invalid command"))
    );
    assert_eq!(
        decode_all(b"SE ND\n\n\0", MAX),
        Err(CodecError::Malformed("invalid command"))
    );
    assert_eq!(
        decode_all(b"SEND\nnocolon\n\n\0", MAX),
        Err(CodecError::Malformed("header line without ':'"))
    );
    assert_eq!(
        decode_all(b"SEND\n:value\n\n\0", MAX),
        Err(CodecError::Malformed("empty header name"))
    );
    assert_eq!(
        decode_all(b"SEND\nk:\xff\n\n\0", MAX),
        Err(CodecError::InvalidUtf8)
    );
}

#[test]
fn too_many_headers() {
    let mut wire = b"SEND\n".to_vec();
    for i in 0..=MAX_HEADERS {
        wire.extend_from_slice(format!("h{i}:v\n").as_bytes());
    }
    wire.extend_from_slice(b"\n\0");
    assert_eq!(decode_all(&wire, 1 << 20), Err(CodecError::TooManyHeaders));
}

#[test]
fn oversize_header_block_detected_before_it_ends() {
    let mut d = Decoder::new(1024);
    d.extend(b"SEND\nx:");
    d.extend(&vec![b'a'; 2000]);
    assert_eq!(d.decode(), Err(CodecError::FrameTooLarge { limit: 1024 }));
}

#[test]
fn oversize_body_without_content_length() {
    let mut d = Decoder::new(1024);
    d.extend(b"SEND\n\n");
    d.extend(&vec![b'a'; 1100]);
    assert_eq!(d.decode(), Err(CodecError::FrameTooLarge { limit: 1024 }));
}

#[test]
fn oversize_content_length_rejected_before_the_body_arrives() {
    let mut d = Decoder::new(1024);
    d.extend(b"SEND\ncontent-length:5000\n\n");
    assert_eq!(d.decode(), Err(CodecError::FrameTooLarge { limit: 1024 }));
    let mut d = Decoder::new(1024);
    d.extend(b"SEND\ncontent-length:99999999999999999999999999\n\n");
    assert_eq!(d.decode(), Err(CodecError::FrameTooLarge { limit: 1024 }));
}

#[test]
fn frame_exactly_at_the_limit_is_accepted() {
    let head = b"SEND\n\n";
    let body_len = 1024 - head.len() - 1;
    let mut wire = head.to_vec();
    wire.extend(std::iter::repeat_n(b'a', body_len));
    wire.push(0);
    assert_eq!(wire.len(), 1024);
    assert_eq!(decode_all(&wire, 1024).unwrap()[0].body.len(), body_len);
    wire.insert(head.len(), b'a');
    assert_eq!(
        decode_all(&wire, 1024),
        Err(CodecError::FrameTooLarge { limit: 1024 })
    );
}

#[test]
fn limit_applies_per_frame_not_per_buffer() {
    // Three 600-byte frames in one message, limit 1024: each fits.
    let mut wire = Vec::new();
    for _ in 0..3 {
        wire.extend_from_slice(b"SEND\n\n");
        wire.extend(std::iter::repeat_n(b'z', 593));
        wire.push(0);
    }
    assert_eq!(decode_all(&wire, 1024).unwrap().len(), 3);
}
