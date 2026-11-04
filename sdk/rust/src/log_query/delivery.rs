//! Bounded client delivery receipts over canonical wire messages.
use super::*;
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct Receipt {
    sequence: u64,
    digest: [u8; 32],
    fingerprint: [u8; 32],
    prior: [u8; 32],
    rows: u64,
}

/// Retains one last-batch receipt, never an unbounded result cache.
#[derive(Clone, Default)]
pub struct BatchTracker {
    snapshot: Option<[u8; 32]>,
    schema: Option<[u8; 32]>,
    next_sequence: u64,
    digest: [u8; 32],
    last: Option<Receipt>,
    rows: u64,
    finished: bool,
    tail: bool,
    tail_live: bool,
}
impl BatchTracker {
    #[must_use]
    pub fn query() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn tail() -> Self {
        Self {
            tail: true,
            ..Self::default()
        }
    }

    /// Returns only new batches. A refusal leaves the delivery receipt unchanged.
    pub fn filter<'a>(
        &mut self,
        response: &'a LogQueryResponse,
    ) -> Result<Vec<&'a LogQueryBatch>, LogQueryWireFailure> {
        if self.tail {
            response.validate_tail()?;
        } else {
            response.validate_session()?;
        }
        let mut next = self.clone();
        let Some(log_query_event::Event::Header(header)) = response
            .events
            .first()
            .and_then(|event| event.event.as_ref())
        else {
            return Err(LogQueryWireFailure);
        };
        let snapshot: [u8; 32] = header
            .snapshot
            .as_ref()
            .ok_or(LogQueryWireFailure)?
            .identity
            .as_slice()
            .try_into()
            .map_err(|_| LogQueryWireFailure)?;
        if !next.tail && next.snapshot.is_some_and(|previous| previous != snapshot) {
            return Err(LogQueryWireFailure);
        }
        next.snapshot = Some(snapshot);
        if header.encoded_len() > MAX_RESPONSE_BYTES {
            return Err(LogQueryWireFailure);
        }
        if next.tail {
            let live = header.tail_phase.as_deref() == Some("live_commit_vector");
            if next.tail_live && !live {
                return Err(LogQueryWireFailure);
            }
            next.tail_live |= live;
        }
        let mut schema = header.clone();
        schema.snapshot = None;
        schema.lease = None;
        schema.effective_budget = None;
        schema.initial_cursor = None;
        schema.tail_phase = None;
        let schema: [u8; 32] = Sha256::digest(schema.encode_to_vec()).into();
        if next.schema.is_some_and(|previous| previous != schema) {
            return Err(LogQueryWireFailure);
        }
        next.schema = Some(schema);
        let mut batches = Vec::with_capacity(response.events.len().saturating_sub(2));
        for event in &response.events {
            let Some(log_query_event::Event::Batch(batch)) = event.event.as_ref() else {
                continue;
            };
            if batch.encoded_len() > MAX_RESPONSE_BYTES {
                return Err(LogQueryWireFailure);
            }
            let mut canonical = batch.clone();
            for row in &mut canonical.rows {
                row.replayed = false;
            }
            let fingerprint: [u8; 32] = Sha256::digest(canonical.encode_to_vec()).into();
            let digest: [u8; 32] = batch
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| LogQueryWireFailure)?;
            if let Some(last) = next.last.as_ref()
                && batch.sequence == last.sequence
            {
                if digest != last.digest || fingerprint != last.fingerprint {
                    return Err(LogQueryWireFailure);
                }
                continue;
            }
            if next.finished
                || batch.sequence != next.next_sequence
                || batch.prior_digest.as_slice() != next.digest
            {
                return Err(LogQueryWireFailure);
            }
            next.next_sequence = next
                .next_sequence
                .checked_add(1)
                .ok_or(LogQueryWireFailure)?;
            next.rows = next
                .rows
                .checked_add(u64::try_from(batch.rows.len()).map_err(|_| LogQueryWireFailure)?)
                .ok_or(LogQueryWireFailure)?;
            if next.rows
                > header
                    .effective_budget
                    .as_ref()
                    .ok_or(LogQueryWireFailure)?
                    .output_rows
            {
                return Err(LogQueryWireFailure);
            }
            next.digest = digest;
            next.last = Some(Receipt {
                sequence: batch.sequence,
                digest,
                fingerprint,
                prior: batch
                    .prior_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| LogQueryWireFailure)?,
                rows: u64::try_from(batch.rows.len()).map_err(|_| LogQueryWireFailure)?,
            });
            batches.push(batch);
        }
        let Some(log_query_event::Event::Terminal(terminal)) = response
            .events
            .last()
            .and_then(|event| event.event.as_ref())
        else {
            return Err(LogQueryWireFailure);
        };
        if terminal.state != "continued" {
            let stats = terminal.stats.as_ref().ok_or(LogQueryWireFailure)?;
            let acknowledged = stats.records == next.rows
                && stats.last_sequence == next.next_sequence.checked_sub(1)
                && stats.result_digest.as_slice() == next.digest;
            let pending = next.tail
                && next.last.as_ref().is_some_and(|last| {
                    next.rows.checked_sub(last.rows) == Some(stats.records)
                        && stats.last_sequence == last.sequence.checked_sub(1)
                        && stats.result_digest.as_slice() == last.prior
                });
            if !acknowledged && !pending {
                return Err(LogQueryWireFailure);
            }
            next.finished = !next.tail;
        }
        *self = next;
        Ok(batches)
    }
    /// A receipt is explicit caller input; the SDK never sends it implicitly.
    #[must_use]
    pub fn acknowledgement(&self) -> Option<LogQueryAcknowledgement> {
        self.last.as_ref().map(|last| LogQueryAcknowledgement {
            sequence: last.sequence,
            digest: last.digest.to_vec(),
        })
    }
}
