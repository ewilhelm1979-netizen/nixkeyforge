use crate::command::{CommandOutput, CommandSpec, ExecutionError, Executor};
use std::fmt;

/// Applying is a dry-run unless the caller explicitly supplies confirmed state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ApplyMode {
    #[default]
    DryRun,
    Confirmed(ApplyConfirmation),
}

/// Evidence collected by the orchestration layer immediately before apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyConfirmation {
    pub plan_fingerprint: String,
    pub interactive_phrase_matched: bool,
    pub preconditions_revalidated: bool,
}

impl ApplyConfirmation {
    pub fn is_valid_for(&self, expected_fingerprint: &str) -> bool {
        self.interactive_phrase_matched
            && self.preconditions_revalidated
            && self.plan_fingerprint == expected_fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyResult {
    DryRun { command: CommandSpec },
    Executed(CommandOutput),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyError {
    ConfirmationRequired,
    LiveApplyDisabled,
    Execution(ExecutionError),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("apply authorization or execution failed")
    }
}

impl std::error::Error for ApplyError {}

pub fn apply_command(
    _executor: &dyn Executor,
    command: &CommandSpec,
    plan_fingerprint: &str,
    mode: &ApplyMode,
) -> Result<ApplyResult, ApplyError> {
    match mode {
        ApplyMode::DryRun => Ok(ApplyResult::DryRun {
            command: command.clone(),
        }),
        ApplyMode::Confirmed(confirmation) if confirmation.is_valid_for(plan_fingerprint) => {
            Err(ApplyError::LiveApplyDisabled)
        }
        ApplyMode::Confirmed(_) => Err(ApplyError::ConfirmationRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{MockExecutor, Program};

    #[test]
    fn apply_is_dry_run_by_default() -> Result<(), ApplyError> {
        let executor = MockExecutor::default();
        let command = CommandSpec::for_test(Program::Nix, ["--version"]);
        let result = apply_command(&executor, &command, "plan-1", &ApplyMode::default())?;
        assert!(matches!(result, ApplyResult::DryRun { .. }));
        assert!(executor.seen().is_empty());
        Ok(())
    }

    #[test]
    fn stale_fingerprint_is_rejected() {
        let executor = MockExecutor::default();
        let command = CommandSpec::for_test(Program::Nix, ["--version"]);
        let confirmation = ApplyConfirmation {
            plan_fingerprint: "old-plan".into(),
            interactive_phrase_matched: true,
            preconditions_revalidated: true,
        };
        assert_eq!(
            apply_command(
                &executor,
                &command,
                "new-plan",
                &ApplyMode::Confirmed(confirmation)
            ),
            Err(ApplyError::ConfirmationRequired)
        );
    }

    #[test]
    fn even_valid_confirmation_cannot_enable_live_apply() {
        let executor = MockExecutor::default();
        let command = CommandSpec::for_test(Program::Nix, ["--version"]);
        let confirmation = ApplyConfirmation {
            plan_fingerprint: "plan-1".into(),
            interactive_phrase_matched: true,
            preconditions_revalidated: true,
        };
        assert_eq!(
            apply_command(
                &executor,
                &command,
                "plan-1",
                &ApplyMode::Confirmed(confirmation)
            ),
            Err(ApplyError::LiveApplyDisabled)
        );
        assert!(executor.seen().is_empty());
    }
}
