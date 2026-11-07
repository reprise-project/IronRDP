use ironrdp_connector::{ConnectorResult, Sequence as _, reason_err};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::rdp::client_info::Credentials;

use crate::{Acceptor, CredentialOrigin, ReceivedCredentials};

/// One step of a recorded accept, replayed into a fresh [`Acceptor`] by [`Acceptor::replay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStep {
    /// A PDU the acceptor read (empty for a send-only step) and the bytes it wrote in reply.
    Pdu { input: Vec<u8>, output: Vec<u8> },
    /// The security upgrade finished; see [`Acceptor::mark_security_upgrade_as_done`].
    SecurityUpgradeDone,
    /// CredSSP authenticated `username`; see [`Acceptor::mark_credssp_as_done_with`].
    CredsspDone { username: String, domain: Option<String> },
}

pub(crate) fn replay(acceptor: &mut Acceptor, steps: &[ReplayStep]) -> ConnectorResult<()> {
    let mut buf = WriteBuf::new();
    for (i, step) in steps.iter().enumerate() {
        match step {
            ReplayStep::Pdu { input, output } => {
                buf.clear();
                let written = acceptor.step(input, None, &mut buf)?;
                if buf.filled()[..written.size().unwrap_or(0)] != output[..] {
                    return Err(reason_err!("replay", "diverged at step {i}"));
                }
            }
            ReplayStep::SecurityUpgradeDone => {
                if acceptor.reached_security_upgrade().is_none() {
                    return Err(reason_err!("replay", "step {i} is not at the security upgrade"));
                }
                acceptor.mark_security_upgrade_as_done();
            }
            ReplayStep::CredsspDone { username, domain } => {
                if !acceptor.should_perform_credssp() {
                    return Err(reason_err!("replay", "step {i} is not at CredSSP"));
                }
                acceptor.mark_credssp_as_done_with(ReceivedCredentials {
                    credentials: Credentials {
                        username: username.clone(),
                        password: String::new(),
                        domain: domain.clone(),
                    },
                    origin: CredentialOrigin::CredSspDelegated,
                });
            }
        }
    }
    Ok(())
}
