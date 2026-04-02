use qlog::Token;
use qlog::events::RawInfo;
use qlog::events::quic::{AckedRanges, PacketNumberSpace, PacketType, QuicFrame, StreamType};

use crate::util::extract_u64;

// ---------------------------------------------------------------------------
// Packet number space
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PnSpace {
    Initial,
    Handshake,
    ApplicationData,
}

pub(crate) fn packet_type_to_number_space(packet_type: PacketType) -> Option<PnSpace> {
    match packet_type {
        PacketType::Initial => Some(PnSpace::Initial),
        PacketType::Handshake => Some(PnSpace::Handshake),
        PacketType::OneRtt => Some(PnSpace::ApplicationData),
        _ => None,
    }
}

pub(crate) fn qlog_packet_number_space(space: PnSpace) -> PacketNumberSpace {
    match space {
        PnSpace::Initial => PacketNumberSpace::Initial,
        PnSpace::Handshake => PacketNumberSpace::Handshake,
        PnSpace::ApplicationData => PacketNumberSpace::ApplicationData,
    }
}

// ---------------------------------------------------------------------------
// Packet type helpers
// ---------------------------------------------------------------------------

pub(crate) fn level_to_packet_type(level: &str) -> PacketType {
    match level {
        "init" => PacketType::Initial,
        "hs" => PacketType::Handshake,
        "app" => PacketType::OneRtt,
        _ => PacketType::Unknown,
    }
}

pub(crate) fn flags_to_packet_type(flags: u8) -> PacketType {
    match (flags & 0x30) >> 4 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        3 => PacketType::Retry,
        _ => PacketType::Unknown,
    }
}

pub(crate) fn level_num_to_packet_type(n: u64) -> PacketType {
    match n {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::OneRtt,
    }
}

// ---------------------------------------------------------------------------
// Token helper
// ---------------------------------------------------------------------------

pub(crate) fn token_from_length(length: u32) -> Token {
    Token {
        ty: None,
        details: None,
        raw: Some(RawInfo {
            length: Some(length as u64),
            payload_length: None,
            data: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_frame(s: &str, ack_delay_exponent: u64) -> QuicFrame {
    let s = s.trim();

    if s == "PADDING" {
        return QuicFrame::Padding {
            length: None,
            payload_length: 0,
        };
    }
    if s == "PING" {
        return QuicFrame::Ping {
            length: None,
            payload_length: None,
        };
    }
    if s == "HANDSHAKE DONE" {
        return QuicFrame::HandshakeDone;
    }
    if let Some(r) = s.strip_prefix("ACK ") {
        return parse_ack(r, ack_delay_exponent);
    }
    if let Some(r) = s.strip_prefix("CRYPTO ") {
        return QuicFrame::Crypto {
            offset: extract_u64(r, "off:"),
            length: extract_u64(r, "len:"),
        };
    }
    if let Some(r) = s.strip_prefix("STREAM ") {
        let fin = r.contains("fin:1");
        return QuicFrame::Stream {
            stream_id: parse_stream_id(r),
            offset: extract_u64(r, "off:"),
            length: extract_u64(r, "len:"),
            fin: fin.then_some(true),
            raw: None,
        };
    }
    if let Some(r) = s.strip_prefix("NEW_CONNECTION_ID ") {
        return QuicFrame::NewConnectionId {
            sequence_number: extract_u64(r, "seq:") as u32,
            retire_prior_to: extract_u64(r, "retire:") as u32,
            connection_id_length: Some(extract_u64(r, "len:") as u8),
            connection_id: String::new(),
            stateless_reset_token: None,
        };
    }
    if let Some(r) = s.strip_prefix("RETIRE_CONNECTION_ID ") {
        return QuicFrame::RetireConnectionId {
            sequence_number: extract_u64(r, "seq:") as u32,
        };
    }
    if let Some(r) = s.strip_prefix("MAX_STREAM_DATA ") {
        return QuicFrame::MaxStreamData {
            stream_id: parse_stream_id(r),
            maximum: extract_u64(r, "limit:"),
        };
    }
    if let Some(r) = s.strip_prefix("MAX_DATA ") {
        return QuicFrame::MaxData {
            maximum: extract_u64(r, "max_data:"),
        };
    }
    if let Some(r) = s.strip_prefix("MAX_STREAMS ") {
        return QuicFrame::MaxStreams {
            stream_type: if r.contains("uni") {
                StreamType::Unidirectional
            } else {
                StreamType::Bidirectional
            },
            maximum: extract_u64(r, "limit:"),
        };
    }
    if let Some(r) = s.strip_prefix("RESET_STREAM ") {
        return QuicFrame::ResetStream {
            stream_id: parse_stream_id(r),
            error_code: extract_u64(r, "error:"),
            final_size: extract_u64(r, "final:"),
            length: None,
            payload_length: None,
        };
    }
    if let Some(r) = s.strip_prefix("STOP_SENDING ") {
        return QuicFrame::StopSending {
            stream_id: parse_stream_id(r),
            error_code: extract_u64(r, "error:"),
            length: None,
            payload_length: None,
        };
    }
    if let Some(r) = s.strip_prefix("CONNECTION_CLOSE ") {
        return QuicFrame::ConnectionClose {
            error_space: None,
            error_code: Some(extract_u64(r, "error:")),
            error_code_value: None,
            reason: None,
            trigger_frame_type: None,
        };
    }
    if s.starts_with("PATH_CHALLENGE") {
        return QuicFrame::PathChallenge { data: None };
    }
    if s.starts_with("PATH_RESPONSE") {
        return QuicFrame::PathResponse { data: None };
    }
    if s.starts_with("NEW_TOKEN") {
        return QuicFrame::NewToken {
            token: Token {
                ty: None,
                details: None,
                raw: None,
            },
        };
    }
    if let Some(r) = s.strip_prefix("STREAMS_BLOCKED ") {
        return QuicFrame::StreamsBlocked {
            stream_type: if r.contains("uni") {
                StreamType::Unidirectional
            } else {
                StreamType::Bidirectional
            },
            limit: extract_u64(r, "limit:"),
        };
    }
    if let Some(r) = s.strip_prefix("DATA_BLOCKED ") {
        return QuicFrame::DataBlocked {
            limit: extract_u64(r, "limit:"),
        };
    }
    if let Some(r) = s.strip_prefix("STREAM_DATA_BLOCKED ") {
        return QuicFrame::StreamDataBlocked {
            stream_id: parse_stream_id(r),
            limit: extract_u64(r, "limit:"),
        };
    }

    QuicFrame::Unknown {
        raw_frame_type: 0,
        frame_type_value: None,
        raw: None,
    }
}

fn parse_ack(r: &str, ack_delay_exponent: u64) -> QuicFrame {
    // "n:N delay:N RANGE RANGE ..."  — delay in units of 2^exp µs, converted to ms.
    let after_delay = r.split_once("delay:").map(|(_, s)| s).unwrap_or("");
    let (delay_str, ranges_str) = after_delay.split_once(' ').unwrap_or((after_delay, ""));
    let delay =
        delay_str.parse::<u64>().unwrap_or(0) as f32 * (1u64 << ack_delay_exponent) as f32 / 1000.0;

    let ranges: Vec<(u64, u64)> = ranges_str
        .split_whitespace()
        .filter_map(|tok| {
            if let Some((hi_str, lo_str)) = tok.rsplit_once('-') {
                let hi: u64 = hi_str.parse().unwrap_or(0);
                let lo: u64 = lo_str.parse().unwrap_or(0);
                Some((lo, hi))
            } else {
                tok.parse::<u64>().ok().map(|n| (n, n))
            }
        })
        .collect();

    QuicFrame::Ack {
        ack_delay: Some(delay),
        acked_ranges: Some(AckedRanges::Double(ranges)),
        ect1: None,
        ect0: None,
        ce: None,
        length: None,
        payload_length: None,
    }
}

/// Parse stream id which may be hex ("id:0xN") or decimal ("id:N").
fn parse_stream_id(s: &str) -> u64 {
    if let Some(p) = s.find("id:0x") {
        let r = &s[p + 5..];
        let end = r.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(r.len());
        u64::from_str_radix(&r[..end], 16).unwrap_or(0)
    } else {
        extract_u64(s, "id:")
    }
}
