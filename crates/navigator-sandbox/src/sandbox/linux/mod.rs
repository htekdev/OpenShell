//! Linux sandbox implementation using Landlock and seccomp.

mod landlock;
pub mod netns;
mod seccomp;

use crate::policy::SandboxPolicy;
use miette::Result;

pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    landlock::apply(policy, workdir)?;
    seccomp::apply(policy)?;
    Ok(())
}
