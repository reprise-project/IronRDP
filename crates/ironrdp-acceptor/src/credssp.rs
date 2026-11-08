use std::borrow::Cow;

use ironrdp_async::NetworkClient;
use ironrdp_connector::sspi::credssp::{
    CredSspServer, CredentialsProxy, NStatusCode, ServerError, ServerMode, ServerState, TsRequest,
};
use ironrdp_connector::sspi::generator::{Generator, GeneratorState};
use ironrdp_connector::sspi::{
    self, AuthIdentity, KerberosServerConfig, NegotiateConfig, NetworkRequest, Username, UsernameParts,
};
use ironrdp_connector::{
    ConnectorError, ConnectorErrorKind, ConnectorResult, ServerName, Written, custom_err, general_err,
};
use ironrdp_core::{WriteBuf, other_err};
use ironrdp_pdu::PduHint;
use picky_krb::gss_api::NegTokenTarg1;
use tracing::debug;

/// Selects the authentication provider used inside CredSSP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CredsspBackend {
    /// Authenticates against the credentials supplied to the acceptor.
    #[default]
    Rust,
    /// Uses Windows Negotiate to authenticate local and domain accounts.
    ///
    /// Delegated credentials still require application-specific logon authorization.
    #[cfg(windows)]
    Windows,
}

#[derive(Debug)]
pub(crate) enum CredsspState {
    Ongoing,
    Finished(AuthIdentity),
    ServerError(sspi::Error),
}

#[derive(Clone, Copy, Debug)]
struct CredsspTsRequestHint;

const CREDSSP_TS_REQUEST_HINT: CredsspTsRequestHint = CredsspTsRequestHint;

impl PduHint for CredsspTsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(other_err!("CredsspTsRequestHint", source: e)),
        }
    }
}

/// Start of an NTLM message that is not wrapped in SPNEGO ([MS-NLMP] 2.2.1.1).
const NTLM_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// NTSTATUS code sent to the client in `TsRequest.errorCode` when CredSSP fails before the client's
/// AUTHENTICATE ([MS-CSSP] 2.2.1).
///
/// The sspi crate derives the code from the SSPI error, which is not an NTSTATUS value.
/// A logon refusal is reported as STATUS_LOGON_FAILURE, as Windows does, so that the client can ask for
/// new credentials.
/// Other errors keep the code from sspi.
fn client_error_code(error: &sspi::Error) -> Option<NStatusCode> {
    match error.error_type {
        sspi::ErrorKind::LogonDenied | sspi::ErrorKind::NoCredentials => Some(NStatusCode::LOGON_FAILURE),
        _ => None,
    }
}

/// The answer to every failure once the client has sent its AUTHENTICATE: STATUS_LOGON_FAILURE and nothing
/// else, so that it tells neither whether the account exists nor which check refused the logon.
fn logon_failure() -> TsRequest {
    TsRequest {
        error_code: Some(NStatusCode::LOGON_FAILURE),
        ..TsRequest::default()
    }
}

/// The NTLM AUTHENTICATE message ([MS-NLMP] 2.2.1.3) in a client's negoToken, bare or as the responseToken of an
/// SPNEGO NegTokenResp, parsed as sspi parses it.
fn ntlm_authenticate(nego_token: &[u8]) -> Option<Cow<'_, [u8]>> {
    let message = if nego_token.starts_with(NTLM_SIGNATURE) {
        Cow::Borrowed(nego_token)
    } else {
        let response: NegTokenTarg1 = picky_asn1_der::from_bytes(nego_token).ok()?;
        Cow::Owned(response.0.response_token.0?.0.0)
    };
    (message.starts_with(NTLM_SIGNATURE) && message.get(8..12) == Some(&[3, 0, 0, 0])).then_some(message)
}

/// Whether sspi checks a MIC in an AUTHENTICATE ([MS-NLMP] 2.2.1.3, 2.2.2.1).
///
/// sspi reads the MIC only when NTLMSSP_NEGOTIATE_TARGET_INFO is set, and checks it only when the first MsvAvFlags
/// pair in the NTLMv2 response has its MIC bit.
fn carries_mic(message: &[u8]) -> bool {
    const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    const AV_FLAGS: u16 = 6;
    const AV_FLAG_MIC: u32 = 0x2;
    /// NTProofStr and the fixed fields of NTLMv2_CLIENT_CHALLENGE before its AvPairs ([MS-NLMP] 2.2.2.7, 2.2.2.8).
    const AV_PAIRS_OFFSET: usize = 16 + 28;

    fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
    }
    fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
    }

    let mic_flag = || -> Option<bool> {
        if u32_at(message, 60)? & NEGOTIATE_TARGET_INFO == 0 {
            return Some(false);
        }
        let length = usize::from(u16_at(message, 20)?);
        let offset = usize::try_from(u32_at(message, 24)?).ok()?;
        let response = message.get(offset..offset.checked_add(length)?)?;
        let mut av_pairs = response.get(AV_PAIRS_OFFSET..)?;
        while !av_pairs.is_empty() {
            let id = u16_at(av_pairs, 0)?;
            let length = usize::from(u16_at(av_pairs, 2)?);
            let value = av_pairs.get(4..4 + length)?;
            if id == AV_FLAGS {
                return Some(value.len() == 4 && u32_at(value, 0)? & AV_FLAG_MIC != 0);
            }
            av_pairs = &av_pairs[4 + length..];
        }
        Some(false)
    };
    mic_flag().unwrap_or(false)
}

/// A generator that ends at once with `error`, for a request refused before sspi reads it.
fn refused<'a>(error: sspi::Error) -> CredsspProcessGenerator<'a> {
    Generator::new(move |_| async move {
        Err(ServerError {
            ts_request: None,
            error,
        })
    })
}

pub type CredsspProcessGenerator<'a> =
    Generator<'a, NetworkRequest, sspi::Result<Vec<u8>>, Result<ServerState, ServerError>>;

#[derive(Debug)]
pub struct CredsspSequence<'a> {
    server: CredSspServer<CredentialsProxyImpl<'a>>,
    /// Replaces `server` when the first client token is a bare NTLM message.
    /// Boxed so that the futures holding a `CredsspSequence` stay small.
    bare_ntlm_server: Option<Box<CredSspServer<CredentialsProxyImpl<'a>>>>,
    state: CredsspState,
    authenticate_received: bool,
}

/// Where CredSSP finds the credentials it checks a client against.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Source<'a> {
    /// One identity, matched in full.
    Fixed(&'a AuthIdentity),
    /// Local accounts. Bare NTLM matches the account name and ignores the client's domain or UPN suffix;
    /// SPNEGO filters `auth_data` first, so it needs an entry with the client's exact user and domain form.
    Users(&'a [AuthIdentity]),
}

#[derive(Debug)]
struct CredentialsProxyImpl<'a> {
    source: Source<'a>,
}

impl CredentialsProxy for CredentialsProxyImpl<'_> {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<Self::AuthenticationData> {
        let password = match &self.source {
            Source::Fixed(credentials) => {
                if !usernames_match(&credentials.username, username) {
                    return Err(std::io::Error::other("invalid username"));
                }
                credentials.password.clone()
            }
            Source::Users(users) => {
                let account = account_name(username);
                users
                    .iter()
                    .find(|user| account_name(&user.username).eq_ignore_ascii_case(account))
                    .ok_or_else(|| std::io::Error::other("invalid username"))?
                    .password
                    .clone()
            }
        };

        // keep the original user/domain
        Ok(AuthIdentity {
            username: username.clone(),
            password,
        })
    }

    fn auth_data(&mut self) -> Result<Vec<Self::AuthenticationData>, std::io::Error> {
        match self.source {
            Source::Fixed(credentials) => Ok(vec![credentials.clone()]),
            Source::Users(users) => Ok(users.to_vec()),
        }
    }
}

fn account_name(username: &Username) -> &str {
    match username.parts() {
        UsernameParts::UserPrincipalName(parts) => parts.account_name(),
        UsernameParts::DownLevelLogonName(parts) => parts.account_name(),
    }
}

fn usernames_match(expected: &Username, requested: &Username) -> bool {
    let requested_parts = requested.parts();
    let requested_account = account_name(requested);

    match expected.parts() {
        UsernameParts::UserPrincipalName(expected_parts) => {
            let UsernameParts::UserPrincipalName(requested_parts) = requested_parts else {
                return false;
            };
            expected_parts
                .account_name()
                .eq_ignore_ascii_case(requested_parts.account_name())
                && expected_parts.suffix().eq_ignore_ascii_case(requested_parts.suffix())
        }
        UsernameParts::DownLevelLogonName(expected_parts) => {
            if !expected_parts.account_name().eq_ignore_ascii_case(requested_account) {
                return false;
            }

            let Some(expected_domain) = expected_parts.netbios_domain() else {
                return true;
            };
            let UsernameParts::DownLevelLogonName(requested_parts) = requested_parts else {
                return false;
            };
            requested_parts
                .netbios_domain()
                .is_some_and(|requested_domain| expected_domain.eq_ignore_ascii_case(requested_domain))
        }
    }
}

pub(crate) async fn resolve_generator(
    generator: &mut CredsspProcessGenerator<'_>,
    network_client: &mut impl NetworkClient,
) -> Result<ServerState, ServerError> {
    let mut state = match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| generator.start())) {
        Ok(s) => s,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .copied()
                .map(String::from)
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "CredSSP processing panic (generator.start)".to_owned());
            return Err(ServerError {
                ts_request: None,
                error: sspi::Error::new(sspi::ErrorKind::InternalError, msg),
            });
        }
    };

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = network_client.send(&request).await.map_err(|err| ServerError {
                    ts_request: None,
                    error: sspi::Error::new(sspi::ErrorKind::InternalError, err),
                })?;
                state = match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| generator.resume(Ok(response))))
                {
                    Ok(s) => s,
                    Err(panic) => {
                        let msg = panic
                            .downcast_ref::<&str>()
                            .copied()
                            .map(String::from)
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "CredSSP processing panic".to_owned());
                        return Err(ServerError {
                            ts_request: None,
                            error: sspi::Error::new(sspi::ErrorKind::InternalError, msg),
                        });
                    }
                };
            }
            GeneratorState::Completed(client_state) => break client_state,
        }
    }
}

impl<'a> CredsspSequence<'a> {
    pub fn next_pdu_hint(&self) -> ConnectorResult<Option<&dyn PduHint>> {
        match &self.state {
            CredsspState::Ongoing => Ok(Some(&CREDSSP_TS_REQUEST_HINT)),
            CredsspState::Finished(_) => Ok(None),
            CredsspState::ServerError(err) => Err(custom_err!("Credssp server error", err.clone())),
        }
    }

    /// Consume the completed CredSSP sequence and return its captured identity.
    pub fn into_identity(self) -> Option<AuthIdentity> {
        match self.state {
            CredsspState::Finished(identity) => Some(identity),
            CredsspState::Ongoing | CredsspState::ServerError(_) => None,
        }
    }

    /// Starts the server side of a CredSSP exchange.
    ///
    /// Without a Kerberos configuration, the server authenticates with NTLM, either bare or wrapped
    /// in SPNEGO as mstsc sends it.
    /// The first client token selects which one.
    /// A bare NTLM client may qualify the configured account name with a domain or a UPN suffix.
    /// A SPNEGO client must send the configured username in exactly the configured form, because
    /// sspi matches it against the configured identity before the NTLM exchange completes.
    pub fn init(
        creds: &'a AuthIdentity,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        krb_config: Option<KerberosServerConfig>,
    ) -> ConnectorResult<Self> {
        Self::with_source(Source::Fixed(creds), client_computer_name, public_key, krb_config)
    }

    /// [`CredsspSequence::init`] with the credentials taken from `source`.
    pub(crate) fn with_source(
        source: Source<'a>,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        krb_config: Option<KerberosServerConfig>,
    ) -> ConnectorResult<Self> {
        let client_computer_name = client_computer_name.into_inner();
        let new_server = |server_mode| {
            let credentials = CredentialsProxyImpl { source };
            CredSspServer::new(public_key.clone(), credentials, server_mode)
                .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))
        };

        let (server, bare_ntlm_server) = if let Some(krb_config) = krb_config {
            let server = new_server(ServerMode::Negotiate(NegotiateConfig {
                protocol_config: Box::new(krb_config),
                package_list: None,
                client_computer_name,
            }))?;
            (server, None)
        } else {
            let server = new_server(ServerMode::Negotiate(NegotiateConfig {
                protocol_config: Box::new(sspi::ntlm::NtlmConfig::default()),
                // Restrict to NTLM when no Kerberos server config is provided.
                // This avoids environment-dependent Kerberos negotiation.
                package_list: Some("!kerberos,!pku2u".to_owned()),
                client_computer_name: client_computer_name.clone(),
            }))?;
            let bare_ntlm_server = new_server(ServerMode::Ntlm(sspi::ntlm::NtlmConfig::new(client_computer_name)))?;
            (server, Some(Box::new(bare_ntlm_server)))
        };

        let sequence = Self {
            server,
            bare_ntlm_server,
            state: CredsspState::Ongoing,
            authenticate_received: false,
        };

        Ok(sequence)
    }

    /// Returns Some(ts_request) when a TS request is received from client,
    pub fn decode_client_message(&mut self, input: &[u8]) -> ConnectorResult<Option<TsRequest>> {
        match self.state {
            CredsspState::Ongoing => {
                let decode = || -> ConnectorResult<Option<TsRequest>> {
                    let message = TsRequest::from_buffer(input).map_err(|e| custom_err!("TsRequest", e))?;

                    debug!(?message, "Received");

                    Ok(Some(message))
                };

                match std::panic::catch_unwind(core::panic::AssertUnwindSafe(decode)) {
                    Ok(res) => res,
                    Err(panic) => {
                        let msg = panic
                            .downcast_ref::<&str>()
                            .copied()
                            .map(String::from)
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "CredSSP decode_client_message panic".to_owned());
                        Err(ConnectorError::new(
                            "CredSSP decode",
                            ConnectorErrorKind::Credssp(sspi::Error::new(sspi::ErrorKind::InternalError, msg)),
                        ))
                    }
                }
            }
            _ => Err(general_err!(
                "attempted to feed client request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    pub fn process_ts_request(&mut self, request: TsRequest) -> CredsspProcessGenerator<'_> {
        if let Some(bare_ntlm_server) = self.bare_ntlm_server.take()
            && request
                .nego_tokens
                .as_deref()
                .is_some_and(|token| token.starts_with(NTLM_SIGNATURE))
        {
            self.server = *bare_ntlm_server;
        }

        // Like sspi's own parsing, which runs inside the generator, a panic here must not end the process.
        let authenticate = std::panic::catch_unwind(|| {
            let authenticate = ntlm_authenticate(request.nego_tokens.as_deref()?)?;
            Some(carries_mic(&authenticate))
        })
        .unwrap_or(Some(false));
        if let Some(carries_mic) = authenticate {
            self.authenticate_received = true;
            // sspi's CHALLENGE carries MsvAvTimestamp, so every NTLMv2 client sends a MIC ([MS-NLMP] 3.1.5.1.2).
            // sspi does not check NTProofStr, so without the MIC a wrong password would pass the AUTHENTICATE.
            if !carries_mic {
                return refused(sspi::Error::new(
                    sspi::ErrorKind::InvalidToken,
                    "the NTLM AUTHENTICATE carries no MIC",
                ));
            }
        }

        // sspi splits pubKeyAuth at the signature size without checking its length.
        if request
            .pub_key_auth
            .as_ref()
            .is_some_and(|proof| proof.len() < sspi::ntlm::SIGNATURE_SIZE)
        {
            return refused(sspi::Error::new(
                sspi::ErrorKind::InvalidToken,
                "pubKeyAuth is shorter than a message signature",
            ));
        }

        self.server.process(request)
    }

    pub fn handle_process_result(
        &mut self,
        result: Result<ServerState, ServerError>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<(Written, Option<AuthIdentity>)> {
        let (ts_request, next_state, credentials) = match result {
            Ok(ServerState::ReplyNeeded(ts_request)) => (Some(ts_request), CredsspState::Ongoing, None),
            Ok(ServerState::Finished(identity)) => (None, CredsspState::Finished(identity.clone()), Some(identity)),
            Err(err) => {
                let ts_request = if self.authenticate_received {
                    Some(logon_failure())
                } else {
                    err.ts_request.map(|ts_request| {
                        let mut ts_request = *ts_request;
                        if let Some(code) = client_error_code(&err.error) {
                            ts_request.error_code = Some(code);
                        }
                        ts_request
                    })
                };
                (ts_request, CredsspState::ServerError(err.error), None)
            }
        };

        self.state = next_state;
        let written = if let Some(ts_request) = ts_request {
            debug!(?ts_request, "Send");
            let length = usize::from(ts_request.buffer_len().map_err(|e| custom_err!("TsRequest", e))?);
            let unfilled_buffer = output.unfilled_to(length);

            ts_request
                .encode_ts_request(unfilled_buffer)
                .map_err(|e| custom_err!("TsRequest", e))?;

            output.advance(length);

            Written::from_size(length)?
        } else {
            Written::Nothing
        };
        Ok((written, credentials))
    }
}
