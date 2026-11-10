//! STOMP 1.2 frame codec (also accepts STOMP 1.1 framing).
//!
//! A WebSocket message may carry several frames or part of one, so the
//! decoder buffers bytes and yields complete frames. Bare EOLs between frames
//! are heart-beats and are skipped. `content-length`, when present, decides
//! where the body ends, so a body may then contain NUL bytes. Header values
//! are unescaped (`\r` `\n` `\c` `\\`) on every frame except CONNECT and
//! CONNECTED, as STOMP 1.2 specifies.
//!
//! Every frame is bounded by `max_frame` bytes, counted from the first byte
//! of the command to the terminating NUL. The decoder reports
//! [`CodecError::FrameTooLarge`] as soon as a frame is known to exceed it,
//! without waiting for the rest of it to arrive.

use bytes::{Buf, Bytes, BytesMut};

/// Upper bound on headers in one frame. The frame size limit already bounds
/// memory; this bounds the cost of header lookups.
pub const MAX_HEADERS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub command: String,
    /// In wire order. Lookups return the first occurrence, as STOMP 1.2
    /// requires for repeated headers.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl Frame {
    pub fn new(command: impl Into<String>) -> Self {
        Frame {
            command: command.into(),
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// First value of `name`, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Serialise. Header names and values are escaped except on CONNECT and
    /// CONNECTED. The caller decides whether to include `content-length`.
    pub fn encode(&self) -> Vec<u8> {
        let escape = !is_unescaped_command(&self.command);
        let mut out = Vec::with_capacity(self.command.len() + 64 + self.body.len());
        out.extend_from_slice(self.command.as_bytes());
        out.push(b'\n');
        for (k, v) in &self.headers {
            if escape {
                escape_into(k, &mut out);
                out.push(b':');
                escape_into(v, &mut out);
            } else {
                out.extend_from_slice(k.as_bytes());
                out.push(b':');
                out.extend_from_slice(v.as_bytes());
            }
            out.push(b'\n');
        }
        out.push(b'\n');
        out.extend_from_slice(&self.body);
        out.push(0);
        out
    }
}

fn is_unescaped_command(command: &str) -> bool {
    command == "CONNECT" || command == "CONNECTED"
}

fn escape_into(s: &str, out: &mut Vec<u8>) {
    for b in s.bytes() {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b':' => out.extend_from_slice(b"\\c"),
            _ => out.push(b),
        }
    }
}

/// Undo STOMP 1.2 header escaping. Any other escape sequence is a protocol
/// error, as the specification requires.
pub fn unescape(raw: &[u8]) -> Result<String, CodecError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter();
    while let Some(&b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b'c') => out.push(b':'),
            Some(b'\\') => out.push(b'\\'),
            _ => return Err(CodecError::InvalidEscape),
        }
    }
    String::from_utf8(out).map_err(|_| CodecError::InvalidUtf8)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("frame exceeds the {limit}-byte limit")]
    FrameTooLarge { limit: usize },
    #[error("malformed frame: {0}")]
    Malformed(&'static str),
    #[error("malformed frame: invalid header escape sequence")]
    InvalidEscape,
    #[error("malformed frame: header is not valid UTF-8")]
    InvalidUtf8,
    #[error("malformed frame: invalid content-length")]
    BadContentLength,
    #[error("malformed frame: more than {MAX_HEADERS} headers")]
    TooManyHeaders,
}

#[derive(Debug)]
enum State {
    /// Between frames: skipping heart-beat EOLs.
    Idle,
    /// Reading the command and header lines. `pos` is the start of the next
    /// unparsed line, relative to the start of the buffer (which is always
    /// the start of the current frame).
    Head {
        command: Option<String>,
        headers: Vec<(String, String)>,
        pos: usize,
    },
    /// Reading the body. `scanned` is how far the NUL search has got.
    Body {
        command: String,
        headers: Vec<(String, String)>,
        body_start: usize,
        content_length: Option<usize>,
        scanned: usize,
    },
}

pub struct Decoder {
    buf: BytesMut,
    max_frame: usize,
    state: State,
}

impl Decoder {
    pub fn new(max_frame: usize) -> Self {
        Decoder {
            buf: BytesMut::new(),
            max_frame,
            state: State::Idle,
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Bytes buffered and not yet returned as a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Next complete frame, `Ok(None)` if more bytes are needed. After an
    /// error the decoder is unusable and the connection should be closed.
    pub fn decode(&mut self) -> Result<Option<Frame>, CodecError> {
        loop {
            match &mut self.state {
                State::Idle => {
                    let skip = self
                        .buf
                        .iter()
                        .take_while(|b| **b == b'\n' || **b == b'\r')
                        .count();
                    self.buf.advance(skip);
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    self.state = State::Head {
                        command: None,
                        headers: Vec::new(),
                        pos: 0,
                    };
                }
                State::Head {
                    command,
                    headers,
                    pos,
                } => {
                    let Some(rel) = self.buf[*pos..].iter().position(|b| *b == b'\n') else {
                        if self.buf.len() > self.max_frame {
                            return Err(CodecError::FrameTooLarge {
                                limit: self.max_frame,
                            });
                        }
                        return Ok(None);
                    };
                    let end = *pos + rel;
                    let mut line = &self.buf[*pos..end];
                    if line.last() == Some(&b'\r') {
                        line = &line[..line.len() - 1];
                    }
                    let next = end + 1;
                    if next > self.max_frame {
                        return Err(CodecError::FrameTooLarge {
                            limit: self.max_frame,
                        });
                    }
                    match command {
                        None => {
                            if line.is_empty()
                                || line.len() > 32
                                || !line.iter().all(|b| b.is_ascii_uppercase())
                            {
                                return Err(CodecError::Malformed("invalid command"));
                            }
                            // ASCII uppercase checked above.
                            *command = Some(String::from_utf8_lossy(line).into_owned());
                            *pos = next;
                        }
                        Some(cmd) if line.is_empty() => {
                            let cmd = std::mem::take(cmd);
                            let headers = std::mem::take(headers);
                            let content_length = content_length(&headers, self.max_frame)?;
                            self.state = State::Body {
                                command: cmd,
                                headers,
                                body_start: next,
                                content_length,
                                scanned: next,
                            };
                        }
                        Some(cmd) => {
                            if headers.len() >= MAX_HEADERS {
                                return Err(CodecError::TooManyHeaders);
                            }
                            let colon = line
                                .iter()
                                .position(|b| *b == b':')
                                .ok_or(CodecError::Malformed("header line without ':'"))?;
                            let (raw_k, raw_v) = (&line[..colon], &line[colon + 1..]);
                            if raw_k.is_empty() {
                                return Err(CodecError::Malformed("empty header name"));
                            }
                            let (k, v) = if is_unescaped_command(cmd) {
                                (
                                    String::from_utf8(raw_k.to_vec())
                                        .map_err(|_| CodecError::InvalidUtf8)?,
                                    String::from_utf8(raw_v.to_vec())
                                        .map_err(|_| CodecError::InvalidUtf8)?,
                                )
                            } else {
                                (unescape(raw_k)?, unescape(raw_v)?)
                            };
                            headers.push((k, v));
                            *pos = next;
                        }
                    }
                }
                State::Body {
                    command,
                    headers,
                    body_start,
                    content_length,
                    scanned,
                } => {
                    let (body_end, frame_end) = match *content_length {
                        Some(n) => {
                            let body_end = *body_start + n;
                            if body_end + 1 > self.max_frame {
                                return Err(CodecError::FrameTooLarge {
                                    limit: self.max_frame,
                                });
                            }
                            if self.buf.len() <= body_end {
                                return Ok(None);
                            }
                            if self.buf[body_end] != 0 {
                                return Err(CodecError::Malformed(
                                    "body longer than content-length",
                                ));
                            }
                            (body_end, body_end + 1)
                        }
                        None => match self.buf[*scanned..].iter().position(|b| *b == 0) {
                            Some(rel) => {
                                let nul = *scanned + rel;
                                if nul + 1 > self.max_frame {
                                    return Err(CodecError::FrameTooLarge {
                                        limit: self.max_frame,
                                    });
                                }
                                (nul, nul + 1)
                            }
                            None => {
                                *scanned = self.buf.len();
                                if self.buf.len() > self.max_frame {
                                    return Err(CodecError::FrameTooLarge {
                                        limit: self.max_frame,
                                    });
                                }
                                return Ok(None);
                            }
                        },
                    };
                    let frame_bytes = self.buf.split_to(frame_end).freeze();
                    let frame = Frame {
                        command: std::mem::take(command),
                        headers: std::mem::take(headers),
                        body: frame_bytes.slice(*body_start..body_end),
                    };
                    self.state = State::Idle;
                    return Ok(Some(frame));
                }
            }
        }
    }
}

fn content_length(
    headers: &[(String, String)],
    max_frame: usize,
) -> Result<Option<usize>, CodecError> {
    let Some((_, v)) = headers.iter().find(|(k, _)| k == "content-length") else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CodecError::BadContentLength);
    }
    // Anything that does not fit in usize is certainly too large.
    match v.parse::<usize>() {
        Ok(n) if n < max_frame => Ok(Some(n)),
        _ => Err(CodecError::FrameTooLarge { limit: max_frame }),
    }
}
