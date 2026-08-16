use serde::{Deserialize, Serialize};

use super::{
    input::{DeploymentInput, ValidationResult},
    operation::{OperationKind, OperationStage},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CancellationPolicy {
    Immediate,
    SafePoint,
    NotInterruptible,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentPlanStage {
    pub stage: OperationStage,
    pub cancellation: CancellationPolicy,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub kind: OperationKind,
    pub deployment_id: String,
    pub target: String,
    pub resumable: bool,
    pub stages: Vec<DeploymentPlanStage>,
}

pub fn build_onboard_plan(
    input: &DeploymentInput,
    deployment_id: impl Into<String>,
) -> ValidationResult<DeploymentPlan> {
    input.validate()?;
    let target = match &input.target {
        super::input::DeploymentTargetInput::Local => "local".to_owned(),
        super::input::DeploymentTargetInput::Ssh { destination } => {
            format!("ssh:{destination}")
        }
    };
    Ok(DeploymentPlan {
        kind: OperationKind::Onboard,
        deployment_id: deployment_id.into(),
        target,
        resumable: true,
        stages: vec![
            stage(
                OperationStage::InputValidation,
                CancellationPolicy::Immediate,
                true,
            ),
            stage(
                OperationStage::SourceConnectivity,
                CancellationPolicy::Immediate,
                true,
            ),
            stage(
                OperationStage::SourceAuthentication,
                CancellationPolicy::Immediate,
                true,
            ),
            stage(
                OperationStage::SourceApproval,
                CancellationPolicy::Immediate,
                true,
            ),
            stage(
                OperationStage::TargetValidation,
                CancellationPolicy::Immediate,
                true,
            ),
            stage(
                OperationStage::SourceResources,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::BaseServices,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::DownstreamInitialization,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::PricingImport,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::ChannelSynchronization,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::KumaSynchronization,
                CancellationPolicy::SafePoint,
                true,
            ),
            stage(
                OperationStage::FinalVerification,
                CancellationPolicy::NotInterruptible,
                true,
            ),
        ],
    })
}

fn stage(
    stage: OperationStage,
    cancellation: CancellationPolicy,
    retryable: bool,
) -> DeploymentPlanStage {
    DeploymentPlanStage {
        stage,
        cancellation,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::input::DeploymentInput;

    #[test]
    fn onboard_plan_is_structured_and_resumable() {
        let mut input = DeploymentInput {
            image_ref: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            ..DeploymentInput::default()
        };
        if cfg!(windows) {
            input.target = super::super::input::DeploymentTargetInput::Ssh {
                destination: "deploy@example.test".to_owned(),
            };
        }
        let plan = build_onboard_plan(&input, "deployment-1").expect("build plan");
        assert!(plan.resumable);
        assert_eq!(plan.kind, OperationKind::Onboard);
        assert_eq!(
            plan.stages.first().map(|stage| stage.stage),
            Some(OperationStage::InputValidation)
        );
        assert_eq!(
            plan.stages.last().map(|stage| stage.stage),
            Some(OperationStage::FinalVerification)
        );
    }
}
