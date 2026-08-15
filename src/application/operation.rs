use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(test)]
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::error::ApplicationError;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Onboard,
    Status,
    Sync,
    Clean,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OperationStage {
    InputValidation,
    SourceConnectivity,
    SourceAuthentication,
    SourceApproval,
    TargetValidation,
    SourceResources,
    BaseServices,
    DownstreamInitialization,
    PricingImport,
    ChannelSynchronization,
    KumaSynchronization,
    FinalVerification,
    Cleanup,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Draft,
    Running,
    Cancelling,
    Cancelled,
    Failed,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OperationEventKind {
    OperationStarted,
    StageStarted,
    Message,
    ProgressChanged { completed: u64, total: u64 },
    CredentialGenerated { credential_kind: String },
    StageCompleted,
    RecoverableFailure { code: String },
    FatalFailure { code: String },
    OperationCompleted,
    OperationCancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationEvent {
    pub operation_id: String,
    pub sequence: u64,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<OperationStage>,
    pub severity: EventSeverity,
    pub kind: OperationEventKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: OperationEvent);
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct CollectedEventSink {
    events: Arc<Mutex<Vec<OperationEvent>>>,
}

#[cfg(test)]
impl CollectedEventSink {
    pub fn events(&self) -> Vec<OperationEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[cfg(test)]
impl EventSink for CollectedEventSink {
    fn emit(&self, event: OperationEvent) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    }
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Clone, Default)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::SeqCst) {
            self.state.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> Result<(), OperationTransitionError> {
        if self.is_cancelled() {
            Err(OperationTransitionError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationFailure {
    pub stage: OperationStage,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationCheckpoint {
    pub operation_id: String,
    pub kind: OperationKind,
    pub status: OperationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<OperationStage>,
    #[serde(default)]
    pub completed_stages: BTreeSet<OperationStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<OperationFailure>,
    pub started_at: i64,
    pub updated_at: i64,
}

impl OperationCheckpoint {
    pub fn new(operation_id: impl Into<String>, kind: OperationKind) -> Self {
        Self {
            operation_id: operation_id.into(),
            kind,
            status: OperationStatus::Draft,
            current_stage: None,
            completed_stages: BTreeSet::new(),
            failure: None,
            started_at: 0,
            updated_at: unix_timestamp(),
        }
    }

    pub fn start(&mut self) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Draft)?;
        let now = unix_timestamp();
        self.status = OperationStatus::Running;
        self.started_at = now;
        self.updated_at = now;
        Ok(())
    }

    pub fn start_stage(&mut self, stage: OperationStage) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Running)?;
        if self.completed_stages.contains(&stage) {
            return Err(OperationTransitionError::StageAlreadyCompleted(stage));
        }
        self.current_stage = Some(stage);
        self.failure = None;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    pub fn complete_stage(
        &mut self,
        stage: OperationStage,
    ) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Running)?;
        if self.current_stage != Some(stage) {
            return Err(OperationTransitionError::UnexpectedStage {
                expected: self.current_stage,
                actual: stage,
            });
        }
        self.completed_stages.insert(stage);
        self.current_stage = None;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    pub fn fail(
        &mut self,
        stage: OperationStage,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Running)?;
        self.status = OperationStatus::Failed;
        self.current_stage = Some(stage);
        self.failure = Some(OperationFailure {
            stage,
            code: code.into(),
            message: message.into(),
            retryable,
        });
        self.updated_at = unix_timestamp();
        Ok(())
    }

    #[allow(dead_code)]
    pub fn resume(&mut self) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Failed)?;
        if self
            .failure
            .as_ref()
            .is_none_or(|failure| !failure.retryable)
        {
            return Err(OperationTransitionError::FailureNotRetryable);
        }
        self.status = OperationStatus::Running;
        self.failure = None;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    #[allow(dead_code)]
    pub fn request_cancel(&mut self) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Running)?;
        self.status = OperationStatus::Cancelling;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    #[allow(dead_code)]
    pub fn mark_cancelled(&mut self) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Cancelling)?;
        self.status = OperationStatus::Cancelled;
        self.current_stage = None;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    pub fn complete(&mut self) -> Result<(), OperationTransitionError> {
        self.require_status(OperationStatus::Running)?;
        if self.current_stage.is_some() {
            return Err(OperationTransitionError::StageStillRunning);
        }
        self.status = OperationStatus::Completed;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    fn require_status(&self, expected: OperationStatus) -> Result<(), OperationTransitionError> {
        if self.status == expected {
            Ok(())
        } else {
            Err(OperationTransitionError::InvalidStatus {
                expected,
                actual: self.status,
            })
        }
    }
}

pub struct OperationTracker<S> {
    checkpoint: OperationCheckpoint,
    sink: S,
    cancellation: CancellationToken,
    sequence: u64,
}

impl<S: EventSink> OperationTracker<S> {
    pub fn new(operation_id: impl Into<String>, kind: OperationKind, sink: S) -> Self {
        Self::with_cancellation(operation_id, kind, sink, CancellationToken::default())
    }

    pub fn with_cancellation(
        operation_id: impl Into<String>,
        kind: OperationKind,
        sink: S,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            checkpoint: OperationCheckpoint::new(operation_id, kind),
            sink,
            cancellation,
            sequence: 0,
        }
    }

    pub fn from_checkpoint(checkpoint: OperationCheckpoint, sink: S) -> Self {
        Self::from_checkpoint_with_cancellation(checkpoint, sink, CancellationToken::default())
    }

    pub fn from_checkpoint_with_cancellation(
        checkpoint: OperationCheckpoint,
        sink: S,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            checkpoint,
            sink,
            cancellation,
            sequence: 0,
        }
    }

    pub fn resume(&mut self) -> Result<(), OperationTransitionError> {
        self.checkpoint.resume()
    }

    pub fn start(&mut self, message: impl Into<String>) -> Result<(), OperationTransitionError> {
        self.checkpoint.start()?;
        self.emit(
            None,
            EventSeverity::Info,
            OperationEventKind::OperationStarted,
            message,
            None,
        );
        Ok(())
    }

    pub fn start_stage(
        &mut self,
        stage: OperationStage,
        message: impl Into<String>,
    ) -> Result<(), OperationTransitionError> {
        self.cancellation.check()?;
        self.checkpoint.start_stage(stage)?;
        self.emit(
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::StageStarted,
            message,
            None,
        );
        Ok(())
    }

    pub fn progress(&mut self, stage: OperationStage, completed: u64, total: u64) {
        self.emit(
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::ProgressChanged { completed, total },
            format!("已完成 {completed}/{total}"),
            None,
        );
    }

    pub fn credential_generated(&mut self, stage: OperationStage, credential_kind: String) {
        self.emit(
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::CredentialGenerated { credential_kind },
            "管理员凭证已生成；凭证只会通过安全结果返回".to_owned(),
            None,
        );
    }

    pub fn complete_stage(
        &mut self,
        stage: OperationStage,
        message: impl Into<String>,
    ) -> Result<(), OperationTransitionError> {
        self.checkpoint.complete_stage(stage)?;
        self.emit(
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::StageCompleted,
            message,
            None,
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub fn fail_current(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<(), OperationTransitionError> {
        let stage = self
            .checkpoint
            .current_stage
            .ok_or(OperationTransitionError::NoCurrentStage)?;
        let code = code.into();
        let message = message.into();
        self.checkpoint
            .fail(stage, code.clone(), message.clone(), retryable)?;
        self.emit(
            Some(stage),
            EventSeverity::Error,
            if retryable {
                OperationEventKind::RecoverableFailure { code }
            } else {
                OperationEventKind::FatalFailure { code }
            },
            message,
            None,
        );
        Ok(())
    }

    pub fn fail_current_error(
        &mut self,
        error: &ApplicationError,
    ) -> Result<(), OperationTransitionError> {
        let stage = self
            .checkpoint
            .current_stage
            .ok_or(OperationTransitionError::NoCurrentStage)?;
        self.checkpoint.fail(
            stage,
            error.code.clone(),
            error.message.clone(),
            error.retryable,
        )?;
        self.emit(
            Some(stage),
            EventSeverity::Error,
            if error.retryable {
                OperationEventKind::RecoverableFailure {
                    code: error.code.clone(),
                }
            } else {
                OperationEventKind::FatalFailure {
                    code: error.code.clone(),
                }
            },
            error.message.clone(),
            error.diagnostic.clone(),
        );
        Ok(())
    }

    pub fn complete(&mut self, message: impl Into<String>) -> Result<(), OperationTransitionError> {
        self.checkpoint.complete()?;
        self.emit(
            None,
            EventSeverity::Info,
            OperationEventKind::OperationCompleted,
            message,
            None,
        );
        Ok(())
    }

    pub fn cancel(&mut self, message: impl Into<String>) -> Result<(), OperationTransitionError> {
        self.cancellation.cancel();
        self.checkpoint.request_cancel()?;
        self.emit(
            self.checkpoint.current_stage,
            EventSeverity::Warning,
            OperationEventKind::OperationCancelled,
            message,
            None,
        );
        self.checkpoint.mark_cancelled()?;
        Ok(())
    }

    pub fn checkpoint_owned(&self) -> OperationCheckpoint {
        self.checkpoint.clone()
    }

    pub fn checkpoint(&self) -> &OperationCheckpoint {
        &self.checkpoint
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn emit(
        &mut self,
        stage: Option<OperationStage>,
        severity: EventSeverity,
        kind: OperationEventKind,
        message: impl Into<String>,
        diagnostic: Option<String>,
    ) {
        self.sequence += 1;
        self.sink.emit(OperationEvent {
            operation_id: self.checkpoint.operation_id.clone(),
            sequence: self.sequence,
            timestamp: unix_timestamp(),
            stage,
            severity,
            kind,
            message: message.into(),
            diagnostic,
        });
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationTransitionError {
    #[error("operation was cancelled")]
    Cancelled,
    #[error("invalid operation status: expected {expected:?}, got {actual:?}")]
    InvalidStatus {
        expected: OperationStatus,
        actual: OperationStatus,
    },
    #[error("operation stage {0:?} has already completed")]
    StageAlreadyCompleted(OperationStage),
    #[error("unexpected operation stage {actual:?}; current stage is {expected:?}")]
    UnexpectedStage {
        expected: Option<OperationStage>,
        actual: OperationStage,
    },
    #[error("the current failure is not retryable")]
    #[allow(dead_code)]
    FailureNotRetryable,
    #[error("an operation stage is still running")]
    StageStillRunning,
    #[error("the operation has no current stage")]
    NoCurrentStage,
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_tracks_retry_without_losing_completed_stages() {
        let mut checkpoint = OperationCheckpoint::new("operation-1", OperationKind::Onboard);
        checkpoint.start().expect("start operation");
        checkpoint
            .start_stage(OperationStage::SourceConnectivity)
            .expect("start source stage");
        checkpoint
            .complete_stage(OperationStage::SourceConnectivity)
            .expect("complete source stage");
        checkpoint
            .start_stage(OperationStage::TargetValidation)
            .expect("start target stage");
        checkpoint
            .fail(
                OperationStage::TargetValidation,
                "SSH_AUTH_UNAVAILABLE",
                "SSH authentication failed",
                true,
            )
            .expect("record failure");
        checkpoint.resume().expect("resume retryable failure");
        assert!(
            checkpoint
                .completed_stages
                .contains(&OperationStage::SourceConnectivity)
        );
        assert_eq!(
            checkpoint.current_stage,
            Some(OperationStage::TargetValidation)
        );
    }

    #[test]
    fn cancellation_token_is_shared_across_adapters() {
        let first = CancellationToken::default();
        let second = first.clone();
        first.cancel();
        assert!(second.is_cancelled());
        assert_eq!(second.check(), Err(OperationTransitionError::Cancelled));
    }

    #[test]
    fn tracker_emits_ordered_events_and_exposes_checkpoint() {
        let sink = CollectedEventSink::default();
        let mut tracker =
            OperationTracker::new("operation-1", OperationKind::Onboard, sink.clone());
        tracker.start("start").expect("start operation");
        tracker
            .start_stage(OperationStage::InputValidation, "validate")
            .expect("start stage");
        tracker
            .complete_stage(OperationStage::InputValidation, "validated")
            .expect("complete stage");
        tracker.complete("done").expect("complete operation");
        let events = sink.events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[3].sequence, 4);
        assert_eq!(tracker.checkpoint().status, OperationStatus::Completed);
    }
}
