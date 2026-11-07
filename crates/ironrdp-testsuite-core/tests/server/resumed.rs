use core::time::Duration;
use std::sync::{Arc, Mutex};

use ironrdp_acceptor::ReplayStep;
use ironrdp_connector::{ClientConnector, ConnectorError, State as _};
use ironrdp_core::{WriteBuf, decode};
use ironrdp_dvc::DrdynvcClient;
use ironrdp_pdu::mcs;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::x224::X224;
use ironrdp_server::{
    CredentialDecision, CredentialValidationError, CredentialValidator, Credentials, DesktopSize, DisplayContext,
    DisplayUpdate, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, Resumed, ServerResult,
};
use ironrdp_tokio::TokioFramed;
use tokio::io::{AsyncReadExt as _, DuplexStream};

use super::replay::{acceptor, client, record, steps};

/// Differs from the front's 1024x768, so the size the client confirms shows which acceptor it talked to.
const DISPLAY_SIZE: DesktopSize = DesktopSize {
    width: 800,
    height: 600,
};

/// Keeps every size the server asks it to start at.
struct SizingDisplay(Arc<Mutex<Vec<DesktopSize>>>);

#[async_trait::async_trait]
impl RdpServerDisplay for SizingDisplay {
    async fn size(&mut self) -> DesktopSize {
        DISPLAY_SIZE
    }

    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        self.0.lock().unwrap().push(client_size);
        client_size
    }

    async fn updates(&mut self, _ctx: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(PendingUpdates))
    }
}

struct PendingUpdates;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for PendingUpdates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        core::future::pending().await
    }
}

/// Keeps the credentials it is asked about and answers `accept`.
struct RecordingValidator {
    accept: bool,
    seen: Mutex<Vec<Credentials>>,
}

#[async_trait::async_trait]
impl CredentialValidator for RecordingValidator {
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        self.seen.lock().unwrap().push(credentials.clone());
        Ok(if self.accept {
            CredentialDecision::Accept
        } else {
            CredentialDecision::Reject
        })
    }
}

fn server(requests: &Arc<Mutex<Vec<DesktopSize>>>, validator: Option<Arc<dyn CredentialValidator>>) -> RdpServer {
    RdpServer::builder()
        .with_addr(([127, 0, 0, 1], 0))
        .with_no_security()
        .with_no_input()
        .with_display_handler(SizingDisplay(Arc::clone(requests)))
        .with_credential_validator(validator)
        .build()
}

/// Records `client` against the front's bare acceptor up to Licensing.
fn front(security: SecurityProtocol, client: &mut ClientConnector) -> Vec<ReplayStep> {
    steps(&record(&mut acceptor(security), client))
}

/// Steps `client` over `framed` until it connects, or returns the state it failed in and the error.
async fn finish(
    client: &mut ClientConnector,
    framed: &mut TokioFramed<DuplexStream>,
) -> Result<(), (&'static str, ConnectorError)> {
    let mut buf = WriteBuf::new();
    while !client.state.is_terminal() {
        let state = client.state.name();
        ironrdp_async::single_sequence_step(framed, client, &mut buf)
            .await
            .map_err(|error| (state, error))?;
    }
    Ok(())
}

/// Runs `resumed` on `server` while `client` finishes connecting over the other end of the stream.
async fn resume(
    server: &mut RdpServer,
    client: &mut ClientConnector,
    resumed: Resumed,
) -> (ServerResult<()>, Result<(), (&'static str, ConnectorError)>) {
    let (client_side, server_side) = tokio::io::duplex(65536);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(Box::pin(server.run_connection_resumed(server_side, resumed)), async {
            // Dropping the stream once connected ends the server's session.
            finish(client, &mut TokioFramed::new(client_side)).await
        })
    })
    .await
    .expect("the resumed connection ended")
}

/// Runs `resumed` on a server and returns its result with everything the client side read.
async fn resume_raw(server: &mut RdpServer, resumed: Resumed) -> (ServerResult<()>, Vec<u8>) {
    let (mut client_side, server_side) = tokio::io::duplex(65536);
    let result = server.run_connection_resumed(server_side, resumed).await;
    let mut read = Vec::new();
    client_side.read_to_end(&mut read).await.unwrap();
    (result, read)
}

#[tokio::test]
async fn a_bare_acceptors_recording_replays_through_the_server() {
    let mut client = client(false);
    let steps = front(SecurityProtocol::SSL, &mut client);
    let requests = Arc::default();
    let mut server = server(&requests, None);

    let resumed = Resumed {
        security: SecurityProtocol::SSL,
        steps,
    };
    let (_, connected) = resume(&mut server, &mut client, resumed).await;

    connected.expect("the client connects");
    assert_eq!(client.state.name(), "Connected");
    assert_eq!(
        *requests.lock().unwrap(),
        [DISPLAY_SIZE],
        "the display is asked for its size once, at the size it offered"
    );
}

#[tokio::test]
async fn a_resumed_connection_runs_the_credential_validator() {
    let anna = Credentials {
        username: "anna".into(),
        password: String::new(),
        domain: None,
    };
    for accept in [true, false] {
        let mut client = client(true);
        let steps = front(SecurityProtocol::HYBRID_EX, &mut client);
        let validator = Arc::new(RecordingValidator {
            accept,
            seen: Mutex::default(),
        });
        let shared: Arc<dyn CredentialValidator> = Arc::<RecordingValidator>::clone(&validator);
        let mut server = server(&Arc::default(), Some(shared));

        let resumed = Resumed {
            security: SecurityProtocol::HYBRID_EX,
            steps,
        };
        let (ended, connected) = resume(&mut server, &mut client, resumed).await;

        assert_eq!(validator.seen.lock().unwrap().as_slice(), core::slice::from_ref(&anna));
        if accept {
            connected.expect("an accepted user connects");
            assert_eq!(client.state.name(), "Connected");
        } else {
            ended.expect_err("a refused user ends the connection with an error");
            let (state, _) = connected.expect_err("a refused user does not connect");
            // The client waits here for the server's first PDU after Client Info, which would be Licensing.
            assert_eq!(state, "ConnectTimeAutoDetection", "refused before Demand Active");
        }
    }
}

#[tokio::test]
async fn a_diverging_replay_ends_the_connection_with_an_error() {
    let mut steps = front(SecurityProtocol::SSL, &mut client(false));
    let output = steps
        .iter_mut()
        .find_map(|step| match step {
            ReplayStep::Pdu { output, .. } if !output.is_empty() => Some(output),
            _ => None,
        })
        .expect("a step that writes");
    output[0] ^= 0xff;
    let mut server = server(&Arc::default(), None);

    let resumed = Resumed {
        security: SecurityProtocol::SSL,
        steps,
    };
    let (result, read) = resume_raw(&mut server, resumed).await;

    let error = result.expect_err("a diverging replay is an error");
    assert!(
        error.report().to_string().contains("diverged"),
        "the error says the replay diverged: {}",
        error.report()
    );
    assert!(read.is_empty(), "the client reads EOF and nothing else: {read:?}");
}

#[tokio::test]
async fn a_recording_short_of_licensing_ends_the_connection_with_an_error() {
    let mut steps = front(SecurityProtocol::SSL, &mut client(false));
    steps.pop();
    let mut server = server(&Arc::default(), None);

    let resumed = Resumed {
        security: SecurityProtocol::SSL,
        steps,
    };
    let (result, read) = resume_raw(&mut server, resumed).await;

    let error = result.expect_err("a recording that stops before Licensing is an error");
    assert!(
        error.to_string().contains("Licensing"),
        "the error names Licensing: {error}"
    );
    assert!(read.is_empty(), "the client reads EOF and nothing else: {read:?}");
}

#[tokio::test]
async fn a_resumed_connection_starts_the_channels_the_client_joined() {
    let mut client = client(false).with_static_channel(DrdynvcClient::new());
    let steps = front(SecurityProtocol::SSL, &mut client);
    let drdynvc = client
        .static_channels
        .get_channel_id_by_type::<DrdynvcClient>()
        .expect("the client joined drdynvc");
    let mut server = server(&Arc::default(), None);

    let resumed = Resumed {
        security: SecurityProtocol::SSL,
        steps,
    };
    let (client_side, server_side) = tokio::io::duplex(65536);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_served, ()) = tokio::join!(Box::pin(server.run_connection_resumed(server_side, resumed)), async {
            let mut framed = TokioFramed::new(client_side);
            finish(&mut client, &mut framed).await.expect("the client connects");
            loop {
                let (_, frame) = framed.read_pdu().await.expect("the server writes to drdynvc");
                if let Ok(X224(data)) = decode::<X224<mcs::SendDataIndication<'_>>>(&frame)
                    && data.channel_id == drdynvc
                {
                    break;
                }
            }
        });
    })
    .await
    .expect("the server starts drdynvc");
}
