use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Injected monotonic observation seam for deterministic query budget enforcement.
pub trait QueryClock: Send + Sync {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryWorkStage {
    Parse,
    ScanDecode,
    Operators,
    Output,
}

pub trait QueryWorkMeter: Send + Sync {
    fn units(&self, stage: QueryWorkStage) -> Result<u64, QueryWorkFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryWorkFailure;

impl Display for QueryWorkFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query work meter unavailable")
    }
}

impl std::error::Error for QueryWorkFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryClockFailure;

impl Display for QueryClockFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query clock unavailable")
    }
}

impl std::error::Error for QueryClockFailure {}

#[derive(Default)]
pub(crate) struct SystemQueryClock {
    probe_callbacks: AtomicU8,
}
pub(crate) struct FixedQueryWorkMeter;

impl QueryWorkMeter for FixedQueryWorkMeter {
    fn units(&self, _stage: QueryWorkStage) -> Result<u64, QueryWorkFailure> {
        Ok(1)
    }
}

impl QueryClock for SystemQueryClock {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure> {
        static ORIGIN: OnceLock<Result<(Instant, u64), QueryClockFailure>> = OnceLock::new();
        let (instant, unix_seconds) = ORIGIN
            .get_or_init(|| {
                let unix_seconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .map_err(|_| QueryClockFailure)?;
                Ok::<_, QueryClockFailure>((Instant::now(), unix_seconds))
            })
            .as_ref()
            .map_err(|_| QueryClockFailure)?;
        let now = unix_seconds
            .checked_add(instant.elapsed().as_secs())
            .ok_or(QueryClockFailure);
        // Temporary ARM diagnosis: preserve the clock observation and bound
        // numeric-only output to the first four callbacks of this instance.
        if let Ok(previous) =
            self.probe_callbacks
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1).filter(|next| *next <= 4)
                })
            && writeln!(
                std::io::stderr().lock(),
                "TEMP_QUERY_CLOCK callback={} elapsed_us={}",
                previous + 1,
                instant.elapsed().as_micros()
            )
            .is_err()
        {
            self.probe_callbacks.store(4, Ordering::Relaxed);
        }
        now
    }
}
