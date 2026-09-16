//! Second-order SQLi workflow tracing (brief §5, §24).
//!
//! A second-order finding requires more than "unusual input was stored".
//! This module models the full chain — origin → storage → trigger → sink →
//! observation — and only yields a trace when every link is present and
//! correlated by a shared trace ID.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A unique ID linking every request in one second-order workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub Uuid);

impl TraceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Where the input first entered the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Origin {
    pub endpoint: String,
    pub parameter: String,
    pub input_location: String,
    pub stored_value: String,
    pub trace: TraceId,
}

/// Where the stored value is believed to live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageContext {
    Database,
    File,
    Cache,
    Session,
    Unknown,
}

/// The request that causes the stored value to be used again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    pub endpoint: String,
    pub method: String,
    pub trace: TraceId,
}

/// The query sink the stored value is hypothesised to reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sink {
    /// The parameter or field name at the sink.
    pub name: String,
    /// Whether the sink is actually derived from the stored value (as
    /// opposed to a coincidence of naming).
    pub linked_to_stored: bool,
}

/// An observation made during a later request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkObservation {
    pub endpoint: String,
    /// A short description of what was observed (e.g. "error signature
    /// appeared only after the stored value was triggered").
    pub observation: String,
    pub repeatable: bool,
    pub trace: TraceId,
}

/// The complete second-order chain for one workflow.
///
/// A trace is only `complete()` when origin, trigger, a linked sink, and at
/// least one repeatable observation all exist and share the same trace ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondOrderTrace {
    pub trace: TraceId,
    pub origin: Origin,
    pub storage_context: StorageContext,
    pub trigger: Option<Trigger>,
    pub sink: Option<Sink>,
    pub observations: Vec<SinkObservation>,
}

impl SecondOrderTrace {
    pub fn new(origin: Origin) -> Self {
        let trace = origin.trace;
        Self {
            trace,
            origin,
            storage_context: StorageContext::Unknown,
            trigger: None,
            sink: None,
            observations: Vec::new(),
        }
    }

    pub fn with_storage(mut self, context: StorageContext) -> Self {
        self.storage_context = context;
        self
    }

    pub fn with_trigger(mut self, trigger: Trigger) -> Self {
        self.trigger = Some(trigger);
        self
    }

    pub fn with_sink(mut self, sink: Sink) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn record_observation(&mut self, observation: SinkObservation) {
        self.observations.push(observation);
    }

    /// Whether every link in the chain is present AND the observations are
    /// repeatable. This is the gate that prevents reporting a stored input
    /// as a vulnerability.
    pub fn is_complete(&self) -> bool {
        self.trigger.is_some()
            && self
                .sink
                .as_ref()
                .map(|s| s.linked_to_stored)
                .unwrap_or(false)
            && self.observations.iter().any(|o| o.repeatable)
            && self
                .observations
                .iter()
                .all(|o| o.trace == self.trace)
    }

    /// Explain why the trace is incomplete, for the UI limitations field.
    pub fn incompleteness_reason(&self) -> Option<String> {
        if self.trigger.is_none() {
            return Some("no trigger request identified; the stored value was never re-used".into());
        }
        match &self.sink {
            None => Some("no sink identified for the stored value".into()),
            Some(s) if !s.linked_to_stored => {
                Some("sink exists but is not linked to the stored value".into())
            }
            Some(_) if !self.observations.iter().any(|o| o.repeatable) => {
                Some("observations were not repeatable across runs".into())
            }
            Some(_) if self.observations.iter().any(|o| o.trace != self.trace) => {
                Some("an observation carried a mismatched trace ID".into())
            }
            _ => None,
        }
    }
}

/// A registry of second-order traces, keyed by trace ID.
#[derive(Debug, Clone, Default)]
pub struct TraceRegistry {
    traces: Vec<SecondOrderTrace>,
}

impl TraceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, trace: SecondOrderTrace) {
        self.traces.push(trace);
    }

    pub fn complete(&self) -> Vec<&SecondOrderTrace> {
        self.traces.iter().filter(|t| t.is_complete()).collect()
    }

    pub fn incomplete(&self) -> Vec<&SecondOrderTrace> {
        self.traces.iter().filter(|t| !t.is_complete()).collect()
    }

    pub fn len(&self) -> usize {
        self.traces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.traces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(trace: TraceId) -> Origin {
        Origin {
            endpoint: "/profile/update".into(),
            parameter: "display_name".into(),
            input_location: "form".into(),
            stored_value: "test'value".into(),
            trace,
        }
    }

    #[test]
    fn storing_input_alone_is_not_complete() {
        let trace = TraceId::new();
        let t = SecondOrderTrace::new(origin(trace)).with_storage(StorageContext::Database);
        assert!(!t.is_complete());
        assert!(t.incompleteness_reason().unwrap().contains("no trigger"));
    }

    #[test]
    fn missing_sink_is_incomplete() {
        let trace = TraceId::new();
        let t = SecondOrderTrace::new(origin(trace))
            .with_trigger(Trigger {
                endpoint: "/reports".into(),
                method: "GET".into(),
                trace,
            });
        assert!(!t.is_complete());
        assert!(t.incompleteness_reason().unwrap().contains("no sink"));
    }

    #[test]
    fn unlinked_sink_is_incomplete() {
        let trace = TraceId::new();
        let t = SecondOrderTrace::new(origin(trace))
            .with_trigger(Trigger {
                endpoint: "/reports".into(),
                method: "GET".into(),
                trace,
            })
            .with_sink(Sink {
                name: "display_name".into(),
                linked_to_stored: false,
            });
        assert!(!t.is_complete());
        assert!(t.incompleteness_reason().unwrap().contains("not linked"));
    }

    #[test]
    fn non_repeatable_observation_is_incomplete() {
        let trace = TraceId::new();
        let mut t = SecondOrderTrace::new(origin(trace))
            .with_trigger(Trigger {
                endpoint: "/reports".into(),
                method: "GET".into(),
                trace,
            })
            .with_sink(Sink {
                name: "display_name".into(),
                linked_to_stored: true,
            });
        t.record_observation(SinkObservation {
            endpoint: "/reports".into(),
            observation: "error appeared once".into(),
            repeatable: false,
            trace,
        });
        assert!(!t.is_complete());
        assert!(t.incompleteness_reason().unwrap().contains("not repeatable"));
    }

    #[test]
    fn full_chain_is_complete() {
        let trace = TraceId::new();
        let mut t = SecondOrderTrace::new(origin(trace))
            .with_storage(StorageContext::Database)
            .with_trigger(Trigger {
                endpoint: "/reports".into(),
                method: "GET".into(),
                trace,
            })
            .with_sink(Sink {
                name: "display_name".into(),
                linked_to_stored: true,
            });
        t.record_observation(SinkObservation {
            endpoint: "/reports".into(),
            observation: "error signature appears only after trigger".into(),
            repeatable: true,
            trace,
        });
        assert!(t.is_complete());
        assert!(t.incompleteness_reason().is_none());
    }

    #[test]
    fn mismatched_trace_id_breaks_chain() {
        let trace = TraceId::new();
        let mut t = SecondOrderTrace::new(origin(trace))
            .with_trigger(Trigger {
                endpoint: "/reports".into(),
                method: "GET".into(),
                trace,
            })
            .with_sink(Sink {
                name: "x".into(),
                linked_to_stored: true,
            });
        t.record_observation(SinkObservation {
            endpoint: "/reports".into(),
            observation: "unrelated".into(),
            repeatable: true,
            trace: TraceId::new(),
        });
        assert!(!t.is_complete());
        assert!(t.incompleteness_reason().unwrap().contains("mismatched trace"));
    }

    #[test]
    fn registry_separates_complete_from_incomplete() {
        let trace = TraceId::new();
        let mut good = SecondOrderTrace::new(origin(trace))
            .with_trigger(Trigger {
                endpoint: "/r".into(),
                method: "GET".into(),
                trace,
            })
            .with_sink(Sink {
                name: "x".into(),
                linked_to_stored: true,
            });
        good.record_observation(SinkObservation {
            endpoint: "/r".into(),
            observation: "repeatable".into(),
            repeatable: true,
            trace,
        });
        let bad = SecondOrderTrace::new(origin(TraceId::new()));

        let mut reg = TraceRegistry::new();
        reg.add(good);
        reg.add(bad);
        assert_eq!(reg.complete().len(), 1);
        assert_eq!(reg.incomplete().len(), 1);
    }
}
