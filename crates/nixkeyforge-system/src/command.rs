use std::collections::VecDeque;
use std::fmt;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

/// Closed executable allowlist. No user-selected executable can be represented.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Program {
    Nix,
    NixosVersion,
    Fido2Token,
    SystemdCryptenroll,
    Cryptsetup,
    Lsblk,
    Ssh,
    SshKeygen,
    Pamu2fcfg,
    Age,
}

impl Program {
    /// Immutable NixOS system-profile path. Resolution never consults `PATH`.
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Nix => "/run/current-system/sw/bin/nix",
            Self::NixosVersion => "/run/current-system/sw/bin/nixos-version",
            Self::Fido2Token => "/run/current-system/sw/bin/fido2-token",
            Self::SystemdCryptenroll => "/run/current-system/sw/bin/systemd-cryptenroll",
            Self::Cryptsetup => "/run/current-system/sw/bin/cryptsetup",
            Self::Lsblk => "/run/current-system/sw/bin/lsblk",
            Self::Ssh => "/run/current-system/sw/bin/ssh",
            Self::SshKeygen => "/run/current-system/sw/bin/ssh-keygen",
            Self::Pamu2fcfg => "/run/current-system/sw/bin/pamu2fcfg",
            Self::Age => "/run/current-system/sw/bin/age",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InputPolicy {
    #[default]
    Null,
    /// Used only where the called tool performs its own protected TTY prompt.
    ProtectedTty,
}

/// A typed command with a fixed executable, separated arguments and an empty environment.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandSpec {
    program: Program,
    arguments: Vec<String>,
    input: InputPolicy,
}

impl CommandSpec {
    pub(crate) fn new(
        program: Program,
        arguments: impl IntoIterator<Item = impl Into<String>>,
        input: InputPolicy,
    ) -> Self {
        let arguments = arguments.into_iter().map(Into::into).collect();
        Self {
            program,
            arguments,
            input,
        }
    }

    pub fn program(&self) -> Program {
        self.program
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn input_policy(&self) -> InputPolicy {
        self.input
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        program: Program,
        arguments: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(program, arguments, InputPolicy::Null)
    }
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("arguments", &"<redacted typed arguments>")
            .field("argument_count", &self.arguments.len())
            .field("input", &self.input)
            .finish()
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    /// Callers must redact this before presenting it.
    pub stderr: Vec<u8>,
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("status", &self.status)
            .field("stdout", &"<redacted>")
            .field("stderr", &"<redacted>")
            .finish()
    }
}

impl Drop for CommandOutput {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    SpawnFailed { program: Program },
    Failed { program: Program, status: i32 },
    NoMockResponse { program: Program },
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("typed command execution failed")
    }
}

impl std::error::Error for ExecutionError {}

pub trait Executor: Send + Sync {
    fn execute(&self, command: &CommandSpec) -> Result<CommandOutput, ExecutionError>;
}

/// Production executor. It never invokes a shell, clears the environment and never
/// accepts an executable outside [`Program`].
#[derive(Clone, Copy, Debug)]
pub struct ProcessExecutor {
    _private: (),
}

impl ProcessExecutor {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

impl Executor for ProcessExecutor {
    fn execute(&self, spec: &CommandSpec) -> Result<CommandOutput, ExecutionError> {
        let mut command = Command::new(spec.program.executable());
        command
            .args(&spec.arguments)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match spec.input {
            InputPolicy::Null => {
                command.stdin(Stdio::null());
            }
            InputPolicy::ProtectedTty => {
                command.stdin(Stdio::inherit());
            }
        }
        let mut output = command.output().map_err(|_| ExecutionError::SpawnFailed {
            program: spec.program,
        })?;
        let status = output.status.code().unwrap_or(-1);
        if output.status.success() {
            Ok(CommandOutput {
                status,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        } else {
            output.stdout.zeroize();
            output.stderr.zeroize();
            Err(ExecutionError::Failed {
                program: spec.program,
                status,
            })
        }
    }
}

/// Deterministic executor used by parser, planner and integration tests.
#[derive(Debug, Default)]
pub struct MockExecutor {
    responses: Mutex<VecDeque<Result<CommandOutput, ExecutionError>>>,
    seen: Mutex<Vec<CommandSpec>>,
}

impl MockExecutor {
    pub fn push(&self, response: Result<CommandOutput, ExecutionError>) {
        lock_unpoison(&self.responses).push_back(response);
    }

    pub fn seen(&self) -> Vec<CommandSpec> {
        lock_unpoison(&self.seen).clone()
    }
}

impl Executor for MockExecutor {
    fn execute(&self, command: &CommandSpec) -> Result<CommandOutput, ExecutionError> {
        lock_unpoison(&self.seen).push(command.clone());
        lock_unpoison(&self.responses)
            .pop_front()
            .unwrap_or(Err(ExecutionError::NoMockResponse {
                program: command.program,
            }))
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_has_no_shell_program() {
        let executables = [
            Program::Nix,
            Program::NixosVersion,
            Program::Fido2Token,
            Program::SystemdCryptenroll,
            Program::Cryptsetup,
            Program::Lsblk,
            Program::Ssh,
            Program::SshKeygen,
            Program::Pamu2fcfg,
            Program::Age,
        ]
        .map(Program::executable);
        assert!(
            executables
                .iter()
                .all(|executable| executable.starts_with("/run/current-system/sw/bin/"))
        );
        assert!(
            !executables
                .iter()
                .any(|executable| { executable.ends_with("/sh") || executable.ends_with("/bash") })
        );
    }

    #[test]
    fn mock_captures_arguments_without_interpretation() -> Result<(), ExecutionError> {
        let mock = MockExecutor::default();
        mock.push(Ok(CommandOutput::default()));
        let spec = CommandSpec::for_test(Program::Nix, ["--", "$(touch /tmp/nope)"]);
        mock.execute(&spec)?;
        assert_eq!(mock.seen()[0].arguments()[1], "$(touch /tmp/nope)");
        Ok(())
    }
}
