use ironrdp_acceptor::{Acceptor, CredentialOrigin, DesktopSize, ReplayStep};
use ironrdp_connector::{ClientConnector, Credentials, Sequence as _};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::PduHint;
use ironrdp_pdu::nego::SecurityProtocol;

fn acceptor(protocol: SecurityProtocol) -> Acceptor {
    Acceptor::new(
        protocol,
        DesktopSize {
            width: 1024,
            height: 768,
        },
        vec![],
        None,
    )
}

fn client(enable_credssp: bool) -> ClientConnector {
    let mut config = crate::connector::test_config();
    config.credentials = Credentials::UsernamePassword {
        username: "anna".into(),
        password: "secret".into(),
    };
    config.enable_credssp = enable_credssp;
    ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap())
}

/// Takes the next PDU `hint` asks for off `queue`: empty for a send-only step, `None` while incomplete.
fn take_pdu(hint: Option<&dyn PduHint>, queue: &mut Vec<u8>) -> Option<Vec<u8>> {
    let Some(hint) = hint else {
        return Some(Vec::new());
    };
    let (_, size) = hint.find_size(queue).unwrap()?;
    Some(queue.drain(..size).collect())
}

fn step(sequence: &mut dyn ironrdp_connector::Sequence, input: &[u8]) -> Vec<u8> {
    let mut buf = WriteBuf::new();
    let written = sequence.step(input, None, &mut buf).unwrap();
    buf.filled()[..written.size().unwrap_or(0)].to_vec()
}

/// Runs `client` against `acceptor` in memory until the acceptor has read Client Info, recording each
/// acceptor step with the state it started in. Both sides skip TLS and CredSSP.
fn record(acceptor: &mut Acceptor, mut client: ClientConnector) -> Vec<(&'static str, ReplayStep)> {
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    let mut record = Vec::new();
    while acceptor.client_info_flags().is_none() {
        let state = acceptor.state().name();
        if acceptor.reached_security_upgrade().is_some() {
            acceptor.mark_security_upgrade_as_done();
            record.push((state, ReplayStep::SecurityUpgradeDone));
        } else if acceptor.should_perform_credssp() {
            acceptor.mark_credssp_as_done();
            record.push((
                state,
                ReplayStep::CredsspDone {
                    username: "anna".into(),
                    domain: None,
                },
            ));
        } else if let Some(input) = take_pdu(acceptor.next_pdu_hint(), &mut to_server) {
            let output = step(acceptor, &input);
            to_client.extend_from_slice(&output);
            record.push((state, ReplayStep::Pdu { input, output }));
        } else if client.should_perform_security_upgrade() {
            client.mark_security_upgrade_as_done();
        } else if client.should_perform_credssp() {
            client.mark_credssp_as_done();
        } else {
            let input = take_pdu(client.next_pdu_hint(), &mut to_client).expect("one side has a PDU to read");
            to_server.extend_from_slice(&step(&mut client, &input));
        }
    }
    record
}

fn steps(record: &[(&'static str, ReplayStep)]) -> Vec<ReplayStep> {
    record.iter().map(|(_, step)| step.clone()).collect()
}

#[test]
fn a_recorded_accept_replays_to_the_same_state() {
    let mut recorded = acceptor(SecurityProtocol::SSL);
    let record = record(&mut recorded, client(false));

    let mut replayed = acceptor(SecurityProtocol::SSL);
    replayed.replay(&steps(&record)).unwrap();

    assert_eq!(replayed.state().name(), recorded.state().name());
    for acceptor in [&recorded, &replayed] {
        let received = acceptor.received_credentials().expect("Client Info credentials");
        assert_eq!(received.credentials.username, "anna");
        assert_eq!(received.credentials.password, "secret");
        assert_eq!(received.origin, CredentialOrigin::ClientInfo);
    }
}

#[test]
fn a_replay_whose_reply_differs_is_an_error() {
    let record = record(&mut acceptor(SecurityProtocol::SSL), client(false));
    let i = record
        .iter()
        .position(|(state, _)| *state == "BasicSettingsSendResponse")
        .expect("an MCS Connect Response step");
    let mut steps = steps(&record);
    let ReplayStep::Pdu { output, .. } = &mut steps[i] else {
        panic!("step {i} is a PDU");
    };
    *output.last_mut().expect("a non-empty reply") ^= 0xff;

    let error = acceptor(SecurityProtocol::SSL).replay(&steps).unwrap_err();

    assert!(
        error.to_string().contains(&format!("step {i}")),
        "error names step {i}: {error}"
    );
}

#[test]
fn credssp_done_with_gives_the_handler_the_user() {
    let record = steps(&record(&mut acceptor(SecurityProtocol::HYBRID), client(true)));
    assert!(record.contains(&ReplayStep::CredsspDone {
        username: "anna".into(),
        domain: None,
    }));

    let mut replayed = acceptor(SecurityProtocol::HYBRID);
    replayed.replay(&record).unwrap();

    assert!(replayed.client_info_flags().is_some());
    let received = replayed.received_credentials().expect("CredSSP credentials");
    assert_eq!(received.credentials.username, "anna");
    assert_eq!(received.credentials.password, "");
    assert_eq!(received.origin, CredentialOrigin::CredSspDelegated);
}
