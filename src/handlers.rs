use qlog::events::connectivity::{
    ConnectionClosedTrigger, ConnectionStarted, ConnectionState, MtuUpdated, TransportOwner,
};
use qlog::events::quic::{
    AckedRanges, AlpnInformation, DatagramsReceived, LossTimerEventType, LossTimerUpdated,
    MarkedForRetransmit, PacketHeader, PacketLost, PacketLostTrigger, PacketReceived, PacketSent,
    PacketType, PacketsAcked, QuicFrame, RecoveryParametersSet, TimerType, VersionInformation,
};
use qlog::events::security::{KeyType, KeyUpdateOrRetiredTrigger, KeyUpdated};
use qlog::events::{EventData, RawInfo};

use crate::constants::{
    INITIAL_RTT_MS, LOSS_REDUCTION_FACTOR, PERSISTENT_CONGESTION_THRESHOLD,
    QUIC_HANDSHAKE_HEADER_OVERHEAD, QUIC_INITIAL_HEADER_OVERHEAD, REORDERING_THRESHOLD,
    TIME_THRESHOLD, TIMER_GRANULARITY_MS,
};
use crate::frames::{
    flags_to_packet_type, level_num_to_packet_type, level_to_packet_type,
    packet_type_to_number_space, parse_frame, qlog_packet_number_space, token_from_length,
};
use crate::state::{CidInfo, ConnState, PendingRx, SentPacketRecord};
use crate::util::{extract_field, extract_i64, extract_u64, ip_version_str, non_empty, parse_addr};

// ---------------------------------------------------------------------------
// Log line parser
// ---------------------------------------------------------------------------

pub(crate) struct LogLine<'a> {
    pub(crate) timestamp: &'a str,
    pub(crate) conn_id: Option<u32>,
    pub(crate) message: &'a str,
}

pub(crate) fn parse_line(line: &str) -> Option<LogLine<'_>> {
    // "2026/03/27 08:37:07 [debug] 2816782#0: *2 MESSAGE"
    let timestamp = line.get(..19)?;
    let rest = line.get(21..)?;
    let rest = rest.split_once(": ").map(|(_, after)| after)?;

    let (conn_id, message) = if let Some(stripped) = rest.strip_prefix('*')
        && let Some((id, msg)) = stripped.split_once(' ')
    {
        (Some(id.parse().ok()?), msg)
    } else {
        (None, rest)
    };

    Some(LogLine {
        timestamp,
        conn_id,
        message,
    })
}

// ---------------------------------------------------------------------------
// Connection ID frame filler
// ---------------------------------------------------------------------------

pub(crate) fn fill_new_connection_id_frame(frame: &mut QuicFrame, info: &CidInfo) {
    if let QuicFrame::NewConnectionId {
        connection_id,
        stateless_reset_token,
        ..
    } = frame
    {
        *connection_id = info.cid.clone();
        *stateless_reset_token = info.stateless_reset_token.clone();
    }
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

pub(crate) fn handle_recvmsg(state: &mut ConnState, t: f64, r: &str) {
    // quic recvmsg: 80.250.18.198:64165 fd:7 n:1200
    // quic recvmsg: fd:7 n:44
    if state.client_addr.is_none()
        && let Some(addr) = r.split_whitespace().next()
        && !addr.starts_with("fd:")
    {
        state.client_addr = Some(addr.to_string());
    }
    let n = extract_u64(r, "n:");
    if n > 0 {
        state.recvmsg_size = Some(n as u32);
        state.packets_since_recvmsg = 0;
        let datagram_id = state.next_datagram_id();
        state.current_recv_datagram_id = Some(datagram_id);
        state.current_recv_packet_event_indices.clear();
        state.push(
            t,
            EventData::DatagramsReceived(DatagramsReceived {
                count: Some(1),
                raw: Some(vec![RawInfo {
                    length: Some(n),
                    payload_length: None,
                    data: None,
                }]),
                datagram_ids: Some(vec![datagram_id]),
            }),
        );
    }
}

pub(crate) fn handle_connection_created(state: &mut ConnState, t: f64) {
    let (src_ip, src_port) = parse_addr(state.client_addr.as_deref());
    let (dst_ip, dst_port) = parse_addr(state.server_addr.as_deref());
    let ip_version = src_ip.as_deref().map(ip_version_str).map(str::to_string);
    let src_cid = state
        .scid
        .clone()
        .or_else(|| state.pending_rx.as_ref().and_then(|p| p.scid.clone()));
    let dst_cid = state
        .dcid
        .clone()
        .or_else(|| state.pending_rx.as_ref().and_then(|p| p.dcid.clone()));
    state.push(
        t,
        EventData::ConnectionStarted(ConnectionStarted {
            ip_version,
            src_ip: src_ip.unwrap_or_default(),
            dst_ip: dst_ip.unwrap_or_default(),
            protocol: Some("QUIC".to_string()),
            src_port,
            dst_port,
            src_cid,
            dst_cid,
        }),
    );
    state.transition_connection_state(t, ConnectionState::Attempted);
}

pub(crate) fn handle_rx_long(state: &mut ConnState, r: &str, time_ms: f64) {
    // quic packet rx long flags:c1 version:1
    let flags = u8::from_str_radix(r.split_whitespace().next().unwrap_or(""), 16).unwrap_or(0);
    let version = extract_u64(r, "version:");
    state.pending_rx = Some(PendingRx {
        time_ms,
        flags: Some(flags),
        version: (version != 0).then_some(version as u32),
        ..Default::default()
    });
}

pub(crate) fn handle_rx_short(state: &mut ConnState, r: &str, time_ms: f64) {
    // quic packet rx short flags:4a
    let flags = u8::from_str_radix(r.split_whitespace().next().unwrap_or(""), 16).unwrap_or(0);
    // For 1RTT packets, raw.length = full UDP payload when this is the only packet in the datagram.
    let raw_length = (state.packets_since_recvmsg == 0)
        .then_some(state.recvmsg_size)
        .flatten();
    state.pending_rx = Some(PendingRx {
        time_ms,
        packet_type: Some(PacketType::OneRtt),
        flags: Some(flags),
        raw_length,
        ..Default::default()
    });
}

pub(crate) fn handle_frame_rx(state: &mut ConnState, r: &str) {
    // quic frame rx init:0 CRYPTO len:35 off:71
    // quic frame rx app:5310 ACK n:0 delay:19 92557-92289
    let Some((level, after)) = r.split_once(':') else {
        return;
    };
    let (pn_str, frame_str) = after.split_once(' ').unwrap_or((after, ""));
    let pn: u64 = pn_str.parse().unwrap_or(0);
    let mut frame = parse_frame(frame_str, state.ack_delay_exponent);

    if let QuicFrame::NewConnectionId {
        sequence_number,
        connection_id,
        ..
    } = &frame
        && connection_id.is_empty()
        && let Some(info) = state.remote_cids.get(sequence_number)
    {
        fill_new_connection_id_frame(&mut frame, info);
    }

    let Some(p) = &mut state.pending_rx else {
        return;
    };
    p.packet_type
        .get_or_insert_with(|| level_to_packet_type(level));
    if p.packet_number.is_none_or(|n| n == pn) {
        p.frames.push(frame);
    }
}

pub(crate) fn handle_socket_seq(state: &mut ConnState, t: f64, r: &str) {
    let seq = r
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<i64>().ok())
        .unwrap_or(0);
    let cid = extract_field(r, "sid:");
    if cid.is_empty() {
        return;
    }

    state.local_cids.entry(seq).or_default().cid = cid.to_string();
    state.last_socket_seq = Some(seq);

    if seq == 0 && state.current_local_cid.is_none() && state.dcid.is_some() {
        state.update_connection_id(t, TransportOwner::Local, cid);
    }
}

pub(crate) fn handle_cid_received(state: &mut ConnState, t: f64, r: &str) {
    let seq = r
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    let Some((_, payload)) = r.split_once("id:") else {
        return;
    };

    let mut parts = payload.split(':');
    let _len = parts.next();
    let Some(cid) = parts.next() else {
        return;
    };
    let token = parts.next().map(str::to_string);

    state.remote_cids.insert(
        seq,
        CidInfo {
            cid: cid.to_string(),
            stateless_reset_token: token,
        },
    );

    if let Some(pending) = &mut state.pending_rx {
        for frame in pending.frames.iter_mut().rev() {
            if let QuicFrame::NewConnectionId {
                sequence_number,
                connection_id,
                ..
            } = frame
                && *sequence_number == seq
                && connection_id.is_empty()
            {
                if let Some(info) = state.remote_cids.get(&seq) {
                    fill_new_connection_id_frame(frame, info);
                }
                break;
            }
        }
    }

    state.update_connection_id(t, TransportOwner::Remote, cid);
}

pub(crate) fn handle_stateless_reset_token(state: &mut ConnState, r: &str) {
    let Some(seq) = state.last_socket_seq else {
        return;
    };

    let token = r.trim();
    if token.is_empty() {
        return;
    }

    state
        .local_cids
        .entry(seq)
        .or_default()
        .stateless_reset_token = Some(token.to_string());
}

pub(crate) fn handle_packet_done(state: &mut ConnState, t: f64, r: &str) {
    let level = extract_field(r, "level:");
    let pn = extract_u64(r, "pn:");

    if let Some(pending) = state.pending_rx.take() {
        let ptype = pending.packet_type.unwrap_or_else(|| {
            if !level.is_empty() {
                level_to_packet_type(level)
            } else if let Some(f) = pending.flags {
                flags_to_packet_type(f)
            } else {
                PacketType::Unknown
            }
        });
        let packet_number = pending.packet_number.unwrap_or(pn);
        let packet_number_space = packet_type_to_number_space(ptype.clone());
        let mut frames = pending.frames;

        for frame in &mut frames {
            if let QuicFrame::NewConnectionId {
                sequence_number,
                connection_id,
                ..
            } = frame
                && connection_id.is_empty()
                && let Some(info) = state.remote_cids.get(sequence_number)
            {
                fill_new_connection_id_frame(frame, info);
            }
        }

        let acked_packets = packet_number_space.as_ref().map(|space| {
            let mut result = Vec::new();
            for frame in &frames {
                if let QuicFrame::Ack {
                    acked_ranges: Some(AckedRanges::Double(ranges)),
                    ..
                } = frame
                {
                    for &(lo, hi) in ranges {
                        for pn in lo..=hi {
                            if state.sent_packets.remove(&(*space, pn)).is_some() {
                                result.push(pn);
                            }
                        }
                    }
                }
            }
            result
        });

        if state.dcid.is_none()
            && let Some(ref d) = pending.dcid
        {
            if let Some(v) = pending.version {
                let ver_str = format!("{:08x}", v);
                state.push(
                    t,
                    EventData::VersionInformation(VersionInformation {
                        server_versions: Some(vec![ver_str.clone()]),
                        client_versions: Some(vec![ver_str.clone()]),
                        chosen_version: Some(ver_str),
                    }),
                );
            }
            state.dcid = Some(d.clone());
            state.current_local_cid.get_or_insert(d.clone());
            if state.scid.is_none()
                && let Some(ref s) = pending.scid
            {
                state.scid = Some(s.clone());
                state.current_remote_cid.get_or_insert(s.clone());
            }

            if let Some(info) = state.local_cids.get(&0)
                && info.cid != *d
            {
                let local_cid = info.cid.clone();
                state.update_connection_id(t, TransportOwner::Local, &local_cid);
            }
        }

        let header = PacketHeader {
            packet_type: ptype,
            packet_number: Some(packet_number),
            flags: pending.flags,
            token: pending.token_length.map(token_from_length),
            length: pending.header_length,
            version: pending.version.map(|v| format!("{:08x}", v)),
            scil: pending.scil,
            dcil: pending.dcil,
            dcid: pending.dcid,
            scid: pending.scid,
        };
        let rx_t = state.best_rel(pending.time_ms);
        let event_idx = state.push(
            rx_t,
            EventData::PacketReceived(PacketReceived {
                header,
                raw: pending.raw_length.map(|l| RawInfo {
                    length: Some(l as u64),
                    payload_length: None,
                    data: None,
                }),
                frames: non_empty(frames),
                ..Default::default()
            }),
        );
        state.attach_recv_datagram(event_idx);

        if let (Some(space), Some(packet_numbers)) = (packet_number_space, acked_packets)
            && !packet_numbers.is_empty()
        {
            state.push(
                rx_t,
                EventData::PacketsAcked(PacketsAcked {
                    packet_number_space: Some(qlog_packet_number_space(space)),
                    packet_numbers: Some(packet_numbers),
                }),
            );
        }
    }
    state.packets_since_recvmsg += 1;
}

pub(crate) fn handle_packet_tx(state: &mut ConnState, t: f64, r: &str) {
    // "init bytes:5 need_ack:0 number:0 encoded nl:1 trunc:0x0"
    let sp = r.find(' ').unwrap_or(r.len());
    let level = r[..sp].to_string();
    let rest = r.get(sp + 1..).unwrap_or("");
    let pn = extract_u64(rest, "number:");
    let bytes = extract_u64(rest, "bytes:");

    let mut frames = state
        .pending_tx
        .remove(&(level.clone(), pn))
        .unwrap_or_default();
    let ptype = level_to_packet_type(&level);

    for frame in &mut frames {
        if let QuicFrame::NewConnectionId {
            sequence_number,
            connection_id,
            ..
        } = frame
            && connection_id.is_empty()
            && let Some(info) = state.local_cids.get(&(*sequence_number as i64))
        {
            fill_new_connection_id_frame(&mut *frame, info);
        }
    }

    // bytes: is frame payload only; add QUIC header + AEAD overhead.
    let overhead: u64 = if ptype == PacketType::OneRtt { 38 } else { 66 };
    let header = PacketHeader {
        packet_type: ptype.clone(),
        packet_number: Some(pn),
        ..Default::default()
    };

    let event_idx = state.push(
        t,
        EventData::PacketSent(PacketSent {
            header: header.clone(),
            raw: Some(RawInfo {
                length: Some(bytes + overhead),
                payload_length: None,
                data: None,
            }),
            frames: non_empty(frames.clone()).map(Into::into),
            ..Default::default()
        }),
    );
    state.pending_send_packet_event_indices.push(event_idx);

    if let Some(space) = packet_type_to_number_space(ptype.clone()) {
        state.sent_packets.insert(
            (space, pn),
            SentPacketRecord {
                header,
                frames: frames.clone(),
            },
        );
    }

    if ptype == PacketType::Handshake
        && matches!(
            state.connection_state,
            None | Some(ConnectionState::Attempted)
        )
    {
        state.transition_connection_state(t, ConnectionState::HandshakeStarted);
    }

    if frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::HandshakeDone))
    {
        state.transition_connection_state(t, ConnectionState::HandshakeConfirmed);
    }

    for frame in &frames {
        if let QuicFrame::NewConnectionId { connection_id, .. } = frame {
            state.update_connection_id(t, TransportOwner::Local, connection_id);
        }
    }
}

pub(crate) fn handle_tp(state: &mut ConnState, t: f64, r: &str) {
    if r.starts_with("disable active migration:") {
        state.pending_tp.disable_active_migration = Some(r.contains(": 1"));
    } else if let Some(v) = r.strip_prefix("idle_timeout:") {
        state.pending_tp.idle_timeout = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("max_udp_payload_size:") {
        state.pending_tp.max_udp_payload_size = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("max_data:") {
        state.pending_tp.max_data = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("max_stream_data_bidi_local:") {
        state.pending_tp.max_stream_data_bidi_local = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("max_stream_data_bidi_remote:") {
        state.pending_tp.max_stream_data_bidi_remote = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("max_stream_data_uni:") {
        state.pending_tp.max_stream_data_uni = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("initial_max_streams_bidi:") {
        state.pending_tp.initial_max_streams_bidi = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("initial_max_streams_uni:") {
        state.pending_tp.initial_max_streams_uni = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("ack_delay_exponent:") {
        // Also updates the live exponent used when parsing ACK frames.
        if let Ok(exp) = v.trim().parse::<u16>() {
            state.ack_delay_exponent = exp as u64;
            state.pending_tp.ack_delay_exponent = Some(exp);
        }
    } else if let Some(v) = r.strip_prefix("max_ack_delay:") {
        state.pending_tp.max_ack_delay = v.trim().parse().ok();
    } else if let Some(v) = r.strip_prefix("active_connection_id_limit:") {
        state.pending_tp.active_connection_id_limit = v.trim().parse().ok();
    } else if r.starts_with("initial source_connection_id") {
        state.pending_tp.initial_scid = r.split_whitespace().last().map(str::to_string);
        state.flush_tp_params(t);
    }
}

pub(crate) fn handle_rtt_sample(state: &mut ConnState, t: f64, r: &str) {
    state.last_latest_rtt = Some(extract_u64(r, "latest:"));
    state.last_min_rtt = Some(extract_u64(r, "min:"));
    state.last_smoothed_rtt = Some(extract_u64(r, "avg:"));
    state.last_rtt_variance = Some(extract_u64(r, "var:"));
    state.push_metrics(t);
}

pub(crate) fn handle_compat_secret(state: &mut ConnState, t: f64, r: &str) {
    let key_type = match r.trim() {
        "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(KeyType::ServerHandshakeSecret),
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(KeyType::ClientHandshakeSecret),
        "SERVER_TRAFFIC_SECRET_0" => Some(KeyType::Server1RttSecret),
        "CLIENT_TRAFFIC_SECRET_0" => Some(KeyType::Client1RttSecret),
        _ => None,
    };
    let Some(kt) = key_type else { return };
    state.push(
        t,
        EventData::KeyUpdated(KeyUpdated {
            key_type: kt,
            old: None,
            new: String::new(),
            generation: None,
            trigger: Some(KeyUpdateOrRetiredTrigger::Tls),
        }),
    );

    match r.trim() {
        "SERVER_TRAFFIC_SECRET_0" => {
            if matches!(
                state.connection_state,
                None | Some(ConnectionState::Attempted)
            ) {
                state.transition_connection_state(t, ConnectionState::HandshakeStarted);
            }
            state.transition_connection_state(t, ConnectionState::EarlyWrite);
        }
        "CLIENT_TRAFFIC_SECRET_0" => {
            state.transition_connection_state(t, ConnectionState::HandshakeCompleted);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Event processing dispatcher
// ---------------------------------------------------------------------------

pub(crate) fn process(state: &mut ConnState, time_ms: f64, msg: &str) {
    // Internal-timestamp extraction — fires on non-quic lines too.
    if let Some(r) = msg.strip_prefix("event timer add: ") {
        if let Some((before, expiry_str)) = r.rsplit_once(':')
            && let Ok(expiry) = expiry_str.trim().parse::<u64>()
            && let Some(delay_str) = before.split_whitespace().last()
            && let Ok(delay) = delay_str.parse::<u64>()
        {
            state.start_time_ms.get_or_insert(time_ms);
            state.apply_internal_ts(time_ms, expiry.saturating_sub(delay));
        }
        return;
    }

    if let Some(r) = msg.strip_prefix("sendmsg: ") {
        state.start_time_ms.get_or_insert(time_ms);
        let t = state.best_rel(time_ms);
        let bytes = r
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        state.finalize_sent_datagram(t, bytes);
        return;
    }

    if let Some(r) = msg.strip_prefix("SSL ALPN selected: ") {
        state.start_time_ms.get_or_insert(time_ms);
        let t = state.best_rel(time_ms);
        state.push(
            t,
            EventData::AlpnInformation(AlpnInformation {
                server_alpns: None,
                client_alpns: None,
                chosen_alpn: Some(r.to_string()),
            }),
        );
        return;
    }

    // Ignore non-quic lines after timestamp extraction and ALPN information
    let Some(msg) = msg.strip_prefix("quic ") else {
        return;
    };

    state.start_time_ms.get_or_insert(time_ms);
    let t = state.best_rel(time_ms);

    // ── Address discovery ─────────────────────────────────────────────────────
    if let Some(r) = msg.strip_prefix("recvmsg: ") {
        handle_recvmsg(state, t, r);
    } else if let Some(r) = msg.strip_prefix("path seq:0 created addr:") {
        state.client_addr = Some(r.to_string());
    } else if let Some(r) = msg.strip_prefix("socket seq:") {
        handle_socket_seq(state, t, r);
    } else if let Some(r) = msg.strip_prefix("cid seq:") {
        handle_cid_received(state, t, r);
    } else if let Some(r) = msg.strip_prefix("stateless reset token ") {
        handle_stateless_reset_token(state, r);

    // ── Connection lifecycle ──────────────────────────────────────────────────
    } else if msg == "connection created" {
        handle_connection_created(state, t);
    } else if let Some(r) = msg.strip_prefix("close initiated ") {
        let trigger = if extract_i64(r, "rc:") == 0 {
            ConnectionClosedTrigger::Clean
        } else {
            ConnectionClosedTrigger::Error
        };
        state.transition_connection_state(t, ConnectionState::Closing);
        state.push_closed(t, TransportOwner::Local, trigger);
    } else if let Some(r) = msg.strip_prefix("close silent ") {
        let trigger = if r.contains("timedout:1") {
            ConnectionClosedTrigger::IdleTimeout
        } else {
            ConnectionClosedTrigger::Clean
        };
        state.transition_connection_state(t, ConnectionState::Closing);
        state.push_closed(t, TransportOwner::Local, trigger);
    } else if msg == "close completed" {
        state.transition_connection_state(t, ConnectionState::Closed);
        state.push_closed(t, TransportOwner::Local, ConnectionClosedTrigger::Clean);
    } else if msg.starts_with("client timed out") {
        state.transition_connection_state(t, ConnectionState::Closed);
        state.push_closed(
            t,
            TransportOwner::Local,
            ConnectionClosedTrigger::IdleTimeout,
        );

    // ── RX packet header ─────────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("packet rx long flags:") {
        handle_rx_long(state, r, time_ms);
    } else if let Some(r) = msg.strip_prefix("packet rx short flags:") {
        handle_rx_short(state, r, time_ms);
    } else if let Some(r) = msg.strip_prefix("packet rx init len:") {
        // quic packet rx init len:22
        if let Some(p) = &mut state.pending_rx {
            p.packet_type = Some(PacketType::Initial);
            let header_length = r.trim().parse::<u16>().unwrap_or(0);
            p.header_length = Some(header_length);
            p.raw_length = Some(header_length as u32 + QUIC_INITIAL_HEADER_OVERHEAD);
        }
    } else if let Some(r) = msg.strip_prefix("packet rx hs len:") {
        // quic packet rx hs len:77
        if let Some(p) = &mut state.pending_rx {
            p.packet_type = Some(PacketType::Handshake);
            let header_length = r.trim().parse::<u16>().unwrap_or(0);
            p.header_length = Some(header_length);
            p.raw_length = Some(header_length as u32 + QUIC_HANDSHAKE_HEADER_OVERHEAD);
        }
    } else if let Some(r) = msg.strip_prefix("address validation token len:") {
        if let Some(p) = &mut state.pending_rx {
            p.token_length = r.trim().parse().ok();
        }
    } else if let Some(r) = msg.strip_prefix("packet rx dcid len:") {
        // quic packet rx dcid len:20 0000000012bdbb1622662880db5c7ec95181fdef
        if let Some(p) = &mut state.pending_rx {
            let (len_str, hex) = r.split_once(' ').unwrap_or((r, ""));
            p.dcil = len_str.trim().parse().ok();
            if !hex.trim().is_empty() {
                p.dcid = Some(hex.trim().to_string());
            }
        }
    } else if let Some(r) = msg.strip_prefix("packet rx scid len:") {
        // quic packet rx scid len:20 4020cd821db3380191f5045285f90d5082363d08
        if let Some(p) = &mut state.pending_rx {
            let (len_str, hex) = r.split_once(' ').unwrap_or((r, ""));
            p.scil = len_str.trim().parse().ok();
            if !hex.trim().is_empty() {
                p.scid = Some(hex.trim().to_string());
            }
        }
    } else if let Some(r) = msg.strip_prefix("packet rx number:") {
        // quic packet rx number:2 len:1
        let pn: u64 = r
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        if let Some(p) = &mut state.pending_rx {
            p.packet_number = Some(pn);
        }
    } else if let Some(r) = msg.strip_prefix("packet len:") {
        if let Some(p) = &mut state.pending_rx
            && p.raw_length.is_none()
        {
            p.raw_length = r
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok());
        }

    // ── RX frames & done ─────────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("frame rx ") {
        handle_frame_rx(state, r);
    } else if let Some(r) = msg.strip_prefix("packet done ") {
        handle_packet_done(state, t, r);

    // ── TX frames & done ─────────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("frame tx ") {
        if let Some(cp) = r.find(':') {
            let level = r[..cp].to_string();
            let after = &r[cp + 1..];
            let sp = after.find(' ').unwrap_or(after.len());
            let pn: u64 = after[..sp].parse().unwrap_or(0);
            let mut frame =
                parse_frame(after.get(sp + 1..).unwrap_or(""), state.ack_delay_exponent);
            if let QuicFrame::NewConnectionId {
                sequence_number,
                connection_id,
                ..
            } = &frame
                && connection_id.is_empty()
                && let Some(info) = state.local_cids.get(&(*sequence_number as i64))
            {
                fill_new_connection_id_frame(&mut frame, info);
            }
            state.pending_tx.entry((level, pn)).or_default().push(frame);
        }
    } else if let Some(r) = msg.strip_prefix("packet tx ") {
        handle_packet_tx(state, t, r);

    // ── Transport parameters ──────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("tp ") {
        handle_tp(state, t, r);

    // ── Recovery ─────────────────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("rtt sample ") {
        handle_rtt_sample(state, t, r);
    } else if let Some(r) = msg.strip_prefix("congestion ack ") {
        let t_internal = extract_u64(r, "t:");
        state.last_cwnd = Some(extract_u64(r, "win:"));
        state.last_bytes_in_flight = Some(extract_u64(r, "if:"));
        let ct = state.apply_internal_ts(time_ms, t_internal);
        if r.starts_with("ss ") {
            state.transition_congestion_state(ct, "slow_start");
        } else if r.starts_with("cubic ") {
            state.transition_congestion_state(ct, "congestion_avoidance");
        }
        state.push_metrics(ct);
    } else if let Some(r) = msg.strip_prefix("congestion lost") {
        let is_new_loss = !r.trim_start().starts_with("rec");
        let t_internal = extract_u64(r, "t:");
        state.last_cwnd = Some(extract_u64(r, "win:"));
        state.last_bytes_in_flight = Some(extract_u64(r, "if:"));
        if is_new_loss {
            state.last_ssthresh = state.last_cwnd;
        }
        let ct = state.apply_internal_ts(time_ms, t_internal);
        if is_new_loss {
            state.transition_congestion_state(ct, "recovery");
        }
        state.push_metrics(ct);
    } else if let Some(r) = msg.strip_prefix("lost timer pto:") {
        let delta = r.trim().parse::<f32>().ok();
        state.push(
            t,
            EventData::LossTimerUpdated(LossTimerUpdated {
                timer_type: Some(TimerType::Pto),
                packet_number_space: None,
                event_type: LossTimerEventType::Set,
                delta,
            }),
        );
    } else if msg == "lost timer unset" {
        state.push(
            t,
            EventData::LossTimerUpdated(LossTimerUpdated {
                timer_type: Some(TimerType::Pto),
                packet_number_space: None,
                event_type: LossTimerEventType::Cancelled,
                delta: None,
            }),
        );
    } else if msg == "pto timer" {
        state.push(
            t,
            EventData::LossTimerUpdated(LossTimerUpdated {
                timer_type: Some(TimerType::Pto),
                packet_number_space: None,
                event_type: LossTimerEventType::Expired,
                delta: None,
            }),
        );
    } else if let Some(r) = msg.strip_prefix("pto ") {
        // "pto app pto_count:N" / "pto init pto_count:N" / "pto hs pto_count:N"
        let count = extract_u64(r, "pto_count:") as u16;
        state.pto_count = count;
        state.push_metrics(t);
    } else if let Some(r) = msg.strip_prefix("detect_lost ") {
        let wait = extract_i64(r, "wait:");
        if wait <= 0 {
            let pnum = extract_u64(r, "pnum:");
            let lvl = extract_u64(r, "level:");
            let packet_type = level_num_to_packet_type(lvl);
            if let Some(space) = packet_type_to_number_space(packet_type.clone()) {
                state.lost_packet_spaces.insert(pnum, space);
                if state.reported_lost.insert((space, pnum)) {
                    let sent = state.sent_packets.get(&(space, pnum)).cloned();
                    state.push(
                        t,
                        EventData::PacketLost(PacketLost {
                            header: Some(sent.as_ref().map(|p| p.header.clone()).unwrap_or(
                                PacketHeader {
                                    packet_type,
                                    packet_number: Some(pnum),
                                    ..Default::default()
                                },
                            )),
                            frames: sent.map(|p| p.frames),
                            trigger: Some(PacketLostTrigger::TimeThreshold),
                        }),
                    );
                }
            }
        }
    } else if let Some(r) = msg.strip_prefix("resend packet ") {
        let pnum = extract_u64(r, "pnum:");
        if let Some(space) = state.lost_packet_spaces.get(&pnum).copied()
            && state.marked_for_retransmit.insert((space, pnum))
            && let Some(sent) = state.sent_packets.get(&(space, pnum))
        {
            state.push(
                t,
                EventData::MarkedForRetransmit(MarkedForRetransmit {
                    frames: sent.frames.clone(),
                }),
            );
        }

    // ── Security ─────────────────────────────────────────────────────────────
    } else if msg == "key update" {
        // Key phase update — emit an event for both 1-RTT secrets.
        for key_type in [KeyType::Server1RttSecret, KeyType::Client1RttSecret] {
            state.push(
                t,
                EventData::KeyUpdated(KeyUpdated {
                    key_type,
                    old: None,
                    new: String::new(),
                    generation: None,
                    trigger: Some(KeyUpdateOrRetiredTrigger::RemoteUpdate),
                }),
            );
        }
    } else if let Some(r) = msg.strip_prefix("compat secret ") {
        handle_compat_secret(state, t, r);

    // ── Path MTU discovery ────────────────────────────────────────────────────
    } else if let Some(r) = msg.strip_prefix("path seq:0 ack mtu:") {
        let old_mtu = state.current_mtu as u16;
        let new_mtu: u64 = r.trim().parse().unwrap_or(state.current_mtu);
        state.current_mtu = new_mtu;
        state.push(
            t,
            EventData::MtuUpdated(MtuUpdated {
                old: Some(old_mtu),
                new: new_mtu as u16,
                done: None,
            }),
        );
        let cwnd = state.last_cwnd.unwrap_or(new_mtu * 10);
        state.push(
            t,
            EventData::RecoveryParametersSet(RecoveryParametersSet {
                reordering_threshold: Some(REORDERING_THRESHOLD),
                time_threshold: Some(TIME_THRESHOLD),
                timer_granularity: Some(TIMER_GRANULARITY_MS),
                initial_rtt: Some(INITIAL_RTT_MS as f32),
                max_datagram_size: Some(new_mtu as u32),
                initial_congestion_window: Some(cwnd),
                minimum_congestion_window: Some((new_mtu * 2) as u32),
                loss_reduction_factor: Some(LOSS_REDUCTION_FACTOR),
                persistent_congestion_threshold: Some(PERSISTENT_CONGESTION_THRESHOLD),
            }),
        );
    }
}
