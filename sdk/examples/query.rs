//! Query recent records with verified TLS. Read the query key from stdin.
use positron_sdk::log_query::*;
use std::{
    error::Error,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let endpoint = arguments
        .next()
        .ok_or("usage: query ENDPOINT SERVER_NAME TRUST_PEM < QUERY_KEY_FILE")?
        .parse()?;
    let server_name = arguments.next().ok_or("missing server name")?;
    let trust_file = PathBuf::from(arguments.next().ok_or("missing trust file")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut bearer = Zeroizing::new(String::new());
    std::io::stdin().take(4097).read_to_string(&mut bearer)?;
    if bearer.is_empty() || bearer.len() > 4096 {
        return Err("invalid credential input".into());
    }
    let client = LogQueryServiceClient::new(LogQueryTransport::Tls {
        endpoint,
        server_name,
        trust_file,
    })?;
    let end = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let start = end
        .checked_sub(60_000_000_000)
        .ok_or("time range overflow")?;
    let response = client.execute(bearer.trim(), &LogQueryRequest {
        pipeline: format!("pipeline:v1 logs | range ingest_time {start} {end} | project commit_position | limit 1"),
        budget: Some(LogQueryBudget { scanned_bytes: 1_048_576, decoded_records: 16, output_rows: 1,
            output_bytes: 16_384, memory_bytes: 1_048_576, cpu_work_units: 15, wall_seconds: 5,
            maximum_time_range_nanoseconds: 60_000_000_000 }),
    })?;
    let mut tracker = BatchTracker::query();
    let records = tracker
        .filter(&response)?
        .iter()
        .map(|batch| batch.rows.len())
        .sum::<usize>();
    let terminal = response
        .events
        .last()
        .and_then(|event| match event.event.as_ref() {
            Some(log_query_event::Event::Terminal(terminal)) => Some(terminal),
            _ => None,
        })
        .ok_or("missing terminal")?;
    writeln!(
        std::io::stdout().lock(),
        "records={records} status={:?}",
        terminal.status()?
    )?;
    Ok(())
}
