use std::io::{self, Write};

use qlog::events::{EventImportance, Eventable};
use qlog::{CommonFields, QLOG_VERSION, QlogSeq, TraceSeq, VantagePoint, VantagePointType};
use serde::Serialize;

use crate::state::ConnState;

pub(crate) fn write_record(w: &mut impl Write, val: &impl Serialize) -> io::Result<()> {
    w.write_all(&[0x1E])?;
    serde_json::to_writer(&mut *w, val).map_err(io::Error::other)?;
    w.write_all(b"\n")
}

pub(crate) fn write_jsonseq(
    state: &ConnState,
    w: &mut impl Write,
    importance: EventImportance,
) -> io::Result<()> {
    let qlog_seq = QlogSeq {
        qlog_version: QLOG_VERSION.to_string(),
        qlog_format: "JSON-SEQ".to_string(),
        title: None,
        description: None,
        summary: None,
        trace: TraceSeq::new(
            VantagePoint {
                name: Some("nginx".to_string()),
                ty: VantagePointType::Server,
                flow: None,
            },
            None,
            None,
            None,
            Some(CommonFields {
                group_id: state.dcid.clone(),
                protocol_type: Some(vec!["quic".to_string()]),
                reference_time: state.start_time_ms,
                time_format: Some("relative".to_string()),
            }),
        ),
    };

    write_record(w, &qlog_seq)?;
    for event in &state.events {
        if event.importance().is_contained_in(&importance) {
            write_record(w, event)?;
        }
    }

    Ok(())
}
