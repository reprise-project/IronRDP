use core::fmt;

use ironrdp_connector::{ConnectorResult, Sequence as _, reason_err};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::rdp::client_info::Credentials;

use crate::{Acceptor, CredentialOrigin, ReceivedCredentials};

/// One step of a recorded accept, replayed into a fresh [`Acceptor`] by [`Acceptor::replay`].
#[derive(Clone, PartialEq, Eq)]
pub enum ReplayStep {
    /// A PDU the acceptor read (empty for a send-only step) and the bytes it wrote in reply.
    Pdu { input: Vec<u8>, output: Vec<u8> },
    /// The security upgrade finished; see [`Acceptor::mark_security_upgrade_as_done`].
    SecurityUpgradeDone,
    /// CredSSP authenticated `username`; see [`Acceptor::mark_credssp_as_done_with`].
    CredsspDone { username: String, domain: Option<String> },
}

// A Client Info PDU carries the plaintext password, so a `Pdu` shows only its lengths.
impl fmt::Debug for ReplayStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pdu { input, output } => f
                .debug_struct("Pdu")
                .field("input_len", &input.len())
                .field("output_len", &output.len())
                .finish(),
            Self::SecurityUpgradeDone => f.write_str("SecurityUpgradeDone"),
            Self::CredsspDone { username, domain } => f
                .debug_struct("CredsspDone")
                .field("username", username)
                .field("domain", domain)
                .finish(),
        }
    }
}

pub(crate) fn replay(acceptor: &mut Acceptor, steps: &[ReplayStep]) -> ConnectorResult<()> {
    let mut buf = WriteBuf::new();
    for (i, step) in steps.iter().enumerate() {
        match step {
            ReplayStep::Pdu { input, output } => {
                // The marker states and the send-only states step without reading their input.
                if acceptor.reached_security_upgrade().is_some() || acceptor.should_perform_credssp() {
                    return Err(reason_err!("replay", "step {i} is a PDU where a marker is due"));
                }
                if acceptor.next_pdu_hint().is_none() && !input.is_empty() {
                    return Err(reason_err!("replay", "step {i} reads a PDU at a send-only state"));
                }
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
