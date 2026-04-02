use rustc_hash::{FxHashMap, FxHashSet};

use qlog::events::connectivity::{
    ConnectionClosed, ConnectionClosedTrigger, ConnectionIdUpdated, ConnectionState,
    ConnectionStateUpdated, TransportOwner,
};
use qlog::events::quic::{
    CongestionStateUpdated, DatagramsSent, MetricsUpdated, PacketHeader, PacketType, QuicFrame,
    TransportParametersSet,
};
use qlog::events::{Event, EventData, RawInfo};

use crate::constants::INITIAL_RTT_MS;
use crate::frames::PnSpace;

// ---------------------------------------------------------------------------
// Pending receive buffer
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct PendingRx {
    pub(crate) time_ms: f64,
    pub(crate) packet_type: Option<PacketType>,
    pub(crate) packet_number: Option<u64>,
    pub(crate) dcid: Option<String>,
    pub(crate) scid: Option<String>,
    pub(crate) dcil: Option<u8>,
    pub(crate) scil: Option<u8>,
    pub(crate) flags: Option<u8>,
    pub(crate) version: Option<u32>,
    pub(crate) token_length: Option<u32>,
    pub(crate) header_length: Option<u16>,
    pub(crate) raw_length: Option<u32>,
    pub(crate) frames: Vec<QuicFrame>,
}

// ---------------------------------------------------------------------------
// Transport parameters (accumulated before the final flush)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct TransportParams {
    pub(crate) max_udp_payload_size: Option<u32>,
    pub(crate) max_data: Option<u64>,
    pub(crate) max_stream_data_bidi_local: Option<u64>,
    pub(crate) max_stream_data_bidi_remote: Option<u64>,
    pub(crate) max_stream_data_uni: Option<u64>,
    pub(crate) initial_max_streams_bidi: Option<u64>,
    pub(crate) initial_max_streams_uni: Option<u64>,
    pub(crate) ack_delay_exponent: Option<u16>,
    pub(crate) max_ack_delay: Option<u16>,
    pub(crate) active_connection_id_limit: Option<u32>,
    pub(crate) idle_timeout: Option<u64>,
    pub(crate) disable_active_migration: Option<bool>,
    pub(crate) initial_scid: Option<String>,
}

// ---------------------------------------------------------------------------
// Connection ID record
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub(crate) struct CidInfo {
    pub(crate) cid: String,
    pub(crate) stateless_reset_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Sent packet record (kept for loss/ACK attribution)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct SentPacketRecord {
    pub(crate) header: PacketHeader,
    pub(crate) frames: Vec<QuicFrame>,
}

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

pub(crate) struct ConnState {
    pub(crate) events: Vec<Event>,
    pub(crate) start_time_ms: Option<f64>,
    pub(crate) client_addr: Option<String>,
    pub(crate) pending_rx: Option<PendingRx>,
    /// (level_name, packet_number) → frames
    pub(crate) pending_tx: FxHashMap<(String, u64), Vec<QuicFrame>>,
    pub(crate) pending_tp: TransportParams,
    pub(crate) closed: bool,
    pub(crate) last_latest_rtt: Option<u64>,
    pub(crate) last_min_rtt: Option<u64>,
    pub(crate) last_smoothed_rtt: Option<u64>,
    pub(crate) last_rtt_variance: Option<u64>,
    pub(crate) last_cwnd: Option<u64>,
    pub(crate) last_bytes_in_flight: Option<u64>,
    /// Offset to convert nginx's internal monotonic clock (ms) to wall-clock ms.
    pub(crate) clock_offset: Option<f64>,
    /// Most recently observed internal monotonic timestamp (ms).
    pub(crate) last_t_internal: Option<u64>,
    /// Original destination connection ID — used as group_id.
    pub(crate) dcid: Option<String>,
    /// Source connection ID from the client's first Initial packet.
    pub(crate) scid: Option<String>,
    /// UDP payload bytes from the last `recvmsg n:N` log line.
    pub(crate) recvmsg_size: Option<u32>,
    /// Number of `packet done` events processed since the last `recvmsg`.
    pub(crate) packets_since_recvmsg: u32,
    /// Monotonic datagram id within the trace.
    pub(crate) next_datagram_id: u32,
    /// Datagram id currently being parsed from `recvmsg`.
    pub(crate) current_recv_datagram_id: Option<u32>,
    /// Packet event indices belonging to the current received datagram.
    pub(crate) current_recv_packet_event_indices: Vec<usize>,
    /// Packet event indices waiting for the next `sendmsg`.
    pub(crate) pending_send_packet_event_indices: Vec<usize>,
    /// ACK delay exponent negotiated with the remote peer (default 3).
    pub(crate) ack_delay_exponent: u64,
    /// Slow-start threshold set by the most recent loss event.
    pub(crate) last_ssthresh: Option<u64>,
    /// Current path MTU (updated on `ack mtu:N`).
    pub(crate) current_mtu: u64,
    /// Server's listen address, for connection_started.
    pub(crate) server_addr: Option<String>,
    /// Packet numbers already reported as lost, to avoid duplicates.
    pub(crate) reported_lost: FxHashSet<(PnSpace, u64)>,
    /// Packets already marked for retransmission.
    pub(crate) marked_for_retransmit: FxHashSet<(PnSpace, u64)>,
    /// Sent packets kept around so loss/ACK handling can reference their frames.
    /// Entries are removed when the peer acknowledges the packet.
    pub(crate) sent_packets: FxHashMap<(PnSpace, u64), SentPacketRecord>,
    /// Most recent packet number space observed for a lost packet number.
    pub(crate) lost_packet_spaces: FxHashMap<u64, PnSpace>,
    /// Locally-issued connection IDs keyed by their nginx sequence number.
    pub(crate) local_cids: FxHashMap<i64, CidInfo>,
    /// Remotely-advertised connection IDs keyed by sequence number.
    pub(crate) remote_cids: FxHashMap<u32, CidInfo>,
    /// Last local socket sequence seen, used to pair the subsequent reset token.
    pub(crate) last_socket_seq: Option<i64>,
    /// Currently known local CID value.
    pub(crate) current_local_cid: Option<String>,
    /// Currently known remote CID value.
    pub(crate) current_remote_cid: Option<String>,
    /// Best-effort connection state progression.
    pub(crate) connection_state: Option<ConnectionState>,
    /// Current congestion state ("slow_start", "congestion_avoidance", "recovery").
    pub(crate) congestion_state: Option<String>,
    /// Current PTO count (incremented by `pto app/init/hs pto_count:N`).
    pub(crate) pto_count: u16,
    /// Last values emitted in a MetricsUpdated event, used to suppress unchanged fields.
    pub(crate) last_emitted_metrics: EmittedMetrics,
}

#[derive(Default, Clone, PartialEq)]
pub(crate) struct EmittedMetrics {
    pub(crate) min_rtt: Option<u64>,
    pub(crate) smoothed_rtt: Option<u64>,
    pub(crate) latest_rtt: Option<u64>,
    pub(crate) rtt_variance: Option<u64>,
    pub(crate) pto_count: Option<u16>,
    pub(crate) congestion_window: Option<u64>,
    pub(crate) bytes_in_flight: Option<u64>,
    pub(crate) ssthresh: Option<u64>,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            events: Vec::new(),
            start_time_ms: None,
            client_addr: None,
            pending_rx: None,
            pending_tx: FxHashMap::default(),
            pending_tp: TransportParams::default(),
            closed: false,
            last_latest_rtt: Some(0),
            last_min_rtt: None,
            last_smoothed_rtt: Some(INITIAL_RTT_MS),
            last_rtt_variance: Some(INITIAL_RTT_MS / 2),
            last_cwnd: None,
            last_bytes_in_flight: None,
            clock_offset: None,
            last_t_internal: None,
            dcid: None,
            scid: None,
            recvmsg_size: None,
            packets_since_recvmsg: 0,
            next_datagram_id: 0,
            current_recv_datagram_id: None,
            current_recv_packet_event_indices: Vec::new(),
            pending_send_packet_event_indices: Vec::new(),
            ack_delay_exponent: 3,
            last_ssthresh: None,
            current_mtu: 1200,
            reported_lost: FxHashSet::default(),
            marked_for_retransmit: FxHashSet::default(),
            sent_packets: FxHashMap::default(),
            lost_packet_spaces: FxHashMap::default(),
            local_cids: FxHashMap::default(),
            remote_cids: FxHashMap::default(),
            last_socket_seq: None,
            current_local_cid: None,
            current_remote_cid: None,
            connection_state: None,
            congestion_state: None,
            pto_count: 0,
            server_addr: None,
            last_emitted_metrics: EmittedMetrics::default(),
        }
    }
}

impl ConnState {
    pub(crate) fn rel(&self, time_ms: f64) -> f64 {
        time_ms - self.start_time_ms.unwrap_or(time_ms)
    }

    /// Record an internal monotonic timestamp and return its relative qlog time.
    pub(crate) fn apply_internal_ts(&mut self, wall_ms: f64, t_internal: u64) -> f64 {
        let offset = *self.clock_offset.get_or_insert(wall_ms - t_internal as f64);
        self.last_t_internal = Some(t_internal);
        (t_internal as f64 + offset) - self.start_time_ms.unwrap_or(wall_ms)
    }

    /// Best available relative time: precise internal clock when calibrated, wall-clock otherwise.
    pub(crate) fn best_rel(&self, wall_ms: f64) -> f64 {
        match (self.clock_offset, self.last_t_internal) {
            (Some(offset), Some(t)) => (t as f64 + offset) - self.start_time_ms.unwrap_or(wall_ms),
            _ => self.rel(wall_ms),
        }
    }

    pub(crate) fn push(&mut self, t: f64, data: EventData) -> usize {
        self.events.push(Event::with_time(t as f32, data));
        self.events.len() - 1
    }

    pub(crate) fn push_metrics(&mut self, t: f64) {
        let p = &self.last_emitted_metrics;
        let diff = |cur: Option<u64>, prev: Option<u64>| if cur != prev { cur } else { None };

        let min_rtt = diff(self.last_min_rtt, p.min_rtt);
        let smoothed_rtt = diff(self.last_smoothed_rtt, p.smoothed_rtt);
        let latest_rtt = diff(self.last_latest_rtt, p.latest_rtt);
        let rtt_variance = diff(self.last_rtt_variance, p.rtt_variance);
        let congestion_window = diff(self.last_cwnd, p.congestion_window);
        let bytes_in_flight = diff(self.last_bytes_in_flight, p.bytes_in_flight);
        let ssthresh = diff(self.last_ssthresh, p.ssthresh);
        let pto_count = (p.pto_count != Some(self.pto_count)).then_some(self.pto_count);

        if [
            min_rtt,
            smoothed_rtt,
            latest_rtt,
            rtt_variance,
            congestion_window,
            bytes_in_flight,
            ssthresh,
        ]
        .iter()
        .all(Option::is_none)
            && pto_count.is_none()
        {
            return;
        }

        self.last_emitted_metrics = EmittedMetrics {
            min_rtt: self.last_min_rtt,
            smoothed_rtt: self.last_smoothed_rtt,
            latest_rtt: self.last_latest_rtt,
            rtt_variance: self.last_rtt_variance,
            pto_count: Some(self.pto_count),
            congestion_window: self.last_cwnd,
            bytes_in_flight: self.last_bytes_in_flight,
            ssthresh: self.last_ssthresh,
        };

        self.push(
            t,
            EventData::MetricsUpdated(MetricsUpdated {
                min_rtt: min_rtt.map(|v| v as f32),
                smoothed_rtt: smoothed_rtt.map(|v| v as f32),
                latest_rtt: latest_rtt.map(|v| v as f32),
                rtt_variance: rtt_variance.map(|v| v as f32),
                pto_count,
                congestion_window,
                bytes_in_flight,
                ssthresh,
                ..Default::default()
            }),
        );
    }

    pub(crate) fn next_datagram_id(&mut self) -> u32 {
        let id = self.next_datagram_id;
        self.next_datagram_id += 1;
        id
    }

    pub(crate) fn transition_congestion_state(&mut self, t: f64, new: &str) {
        if self.congestion_state.as_deref() == Some(new) {
            return;
        }
        let old = self.congestion_state.clone();
        self.congestion_state = Some(new.to_string());
        self.push(
            t,
            EventData::CongestionStateUpdated(CongestionStateUpdated {
                old,
                new: new.to_string(),
                trigger: None,
            }),
        );
    }

    pub(crate) fn transition_connection_state(&mut self, t: f64, new: ConnectionState) {
        if self.connection_state.as_ref() == Some(&new) {
            return;
        }

        let old = self.connection_state.clone();
        self.connection_state = Some(new.clone());
        self.push(
            t,
            EventData::ConnectionStateUpdated(ConnectionStateUpdated { old, new }),
        );
    }

    pub(crate) fn update_connection_id(&mut self, t: f64, owner: TransportOwner, new_cid: &str) {
        if new_cid.is_empty() {
            return;
        }

        let current = match owner {
            TransportOwner::Local => &mut self.current_local_cid,
            TransportOwner::Remote => &mut self.current_remote_cid,
        };

        if current.as_deref() == Some(new_cid) {
            return;
        }

        let old = current.clone();
        *current = Some(new_cid.to_string());

        self.push(
            t,
            EventData::ConnectionIdUpdated(ConnectionIdUpdated {
                owner: Some(owner),
                old,
                new: Some(new_cid.to_string()),
            }),
        );
    }

    pub(crate) fn attach_recv_datagram(&mut self, event_idx: usize) {
        let Some(datagram_id) = self.current_recv_datagram_id else {
            return;
        };

        if let EventData::PacketReceived(packet) = &mut self.events[event_idx].data {
            packet.datagram_id = Some(datagram_id);
        }

        if !self.current_recv_packet_event_indices.is_empty() {
            for idx in self
                .current_recv_packet_event_indices
                .iter()
                .copied()
                .chain(std::iter::once(event_idx))
            {
                if let EventData::PacketReceived(packet) = &mut self.events[idx].data {
                    packet.is_coalesced = Some(true);
                }
            }
        }

        self.current_recv_packet_event_indices.push(event_idx);
    }

    pub(crate) fn finalize_sent_datagram(&mut self, t: f64, bytes: u64) {
        if self.pending_send_packet_event_indices.is_empty() {
            return;
        }

        let event_indices = self.pending_send_packet_event_indices.clone();
        let raw_lengths: Vec<u64> = event_indices
            .iter()
            .map(|idx| match &self.events[*idx].data {
                EventData::PacketSent(packet) => {
                    packet.raw.as_ref().and_then(|raw| raw.length).unwrap_or(0)
                }
                _ => 0,
            })
            .collect();
        let sum_raw: u64 = raw_lengths.iter().sum();

        if event_indices.len() > 1 && sum_raw == bytes {
            let mut datagram_ids = Vec::with_capacity(event_indices.len());
            let raw = raw_lengths
                .iter()
                .map(|len| RawInfo {
                    length: Some(*len),
                    payload_length: None,
                    data: None,
                })
                .collect();

            for _ in 0..event_indices.len() {
                datagram_ids.push(self.next_datagram_id());
            }

            self.push(
                t,
                EventData::DatagramsSent(DatagramsSent {
                    count: Some(event_indices.len() as u16),
                    raw: Some(raw),
                    datagram_ids: Some(datagram_ids.clone()),
                }),
            );

            for (idx, datagram_id) in event_indices.iter().zip(datagram_ids) {
                if let EventData::PacketSent(packet) = &mut self.events[*idx].data {
                    packet.datagram_id = Some(datagram_id);
                }
            }
        } else {
            let datagram_id = self.next_datagram_id();

            self.push(
                t,
                EventData::DatagramsSent(DatagramsSent {
                    count: Some(1),
                    raw: Some(vec![RawInfo {
                        length: Some(bytes),
                        payload_length: None,
                        data: None,
                    }]),
                    datagram_ids: Some(vec![datagram_id]),
                }),
            );

            for idx in &event_indices {
                if let EventData::PacketSent(packet) = &mut self.events[*idx].data {
                    packet.datagram_id = Some(datagram_id);
                    if event_indices.len() > 1 {
                        packet.is_coalesced = Some(true);
                    }
                }
            }
        }

        self.pending_send_packet_event_indices.clear();
    }

    pub(crate) fn push_closed(
        &mut self,
        t: f64,
        owner: TransportOwner,
        trigger: ConnectionClosedTrigger,
    ) {
        if !self.closed {
            self.push(
                t,
                EventData::ConnectionClosed(ConnectionClosed {
                    owner: Some(owner),
                    connection_code: None,
                    application_code: None,
                    internal_code: None,
                    reason: None,
                    trigger: Some(trigger),
                }),
            );
            self.closed = true;
        }
    }

    pub(crate) fn flush_tp_params(&mut self, t: f64) {
        let tp = &self.pending_tp;
        let event_data = EventData::TransportParametersSet(TransportParametersSet {
            owner: Some(TransportOwner::Remote),
            max_udp_payload_size: tp.max_udp_payload_size,
            initial_max_data: tp.max_data,
            initial_max_stream_data_bidi_local: tp.max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: tp.max_stream_data_bidi_remote,
            initial_max_stream_data_uni: tp.max_stream_data_uni,
            initial_max_streams_bidi: tp.initial_max_streams_bidi,
            initial_max_streams_uni: tp.initial_max_streams_uni,
            ack_delay_exponent: tp.ack_delay_exponent,
            max_ack_delay: tp.max_ack_delay,
            active_connection_id_limit: tp.active_connection_id_limit,
            max_idle_timeout: tp.idle_timeout,
            disable_active_migration: tp.disable_active_migration,
            initial_source_connection_id: tp.initial_scid.clone(),
            ..Default::default()
        });
        self.push(t, event_data);
    }
}
