mod constants;
mod frames;
mod handlers;
mod output;
mod state;
mod util;

use clap::Parser;
use handlers::{parse_line, process};
use output::write_jsonseq;
use qlog::events::EventData;
use state::ConnState;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;
use util::parse_timestamp_ms;

/// Convert nginx QUIC debug logs to qlog (.sqlog) format.
///
/// Reads an nginx debug log file and produces one .sqlog file per QUIC
/// connection found in the log. Each output file is named after the
/// source connection ID (SCID) of the connection.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the nginx debug log file to process
    input: PathBuf,

    /// Directory where .sqlog output files will be written
    #[arg(short, long, default_value = ".")]
    output_dir: PathBuf,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(&args.input)?;
    let mut reader = io::BufReader::new(file);

    std::fs::create_dir_all(&args.output_dir)?;

    let mut connections: HashMap<u32, ConnState> = HashMap::new();
    let mut server_addr: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        let Some(parsed) = parse_line(line) else {
            continue;
        };

        let Some(conn_id) = parsed.conn_id else {
            if let Some(r) = parsed.message.strip_prefix("quic recvmsg on ")
                && let Some((addr, _)) = r.split_once(',')
            {
                server_addr = Some(addr.to_string());
            }
            continue;
        };
        let time_ms = parse_timestamp_ms(parsed.timestamp);

        let state = connections.entry(conn_id).or_insert_with(|| ConnState {
            server_addr: server_addr.clone(),
            ..Default::default()
        });
        process(state, time_ms, parsed.message);
    }

    for (id, state) in &connections {
        let has_packets = state.events.iter().any(|e| {
            matches!(
                &e.data,
                EventData::PacketReceived(_) | EventData::PacketSent(_)
            )
        });
        if !has_packets {
            continue;
        }
        let cid = state.scid.clone().unwrap_or_else(|| id.to_string());
        let filename = args.output_dir.join(format!("{}.sqlog", cid));
        let mut f = io::BufWriter::new(std::fs::File::create(&filename)?);
        write_jsonseq(state, &mut f)?;
        eprintln!("wrote {}", filename.display());
    }
    Ok(())
}
