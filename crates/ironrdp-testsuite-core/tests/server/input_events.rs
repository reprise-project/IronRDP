use ironrdp_ainput::{MouseEventFlags, MousePdu as AinputMousePdu};
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::input::scan_code::{KeyboardFlags as ScanCodeFlags, ScanCodePdu};
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent};

fn fast_path_keys(pdu: &[u8]) -> Vec<KeyboardEvent> {
    let input: FastPathInput = ironrdp_core::decode(pdu).expect("fast-path input PDU");
    input
        .input_events()
        .iter()
        .map(|event| match *event {
            FastPathInputEvent::KeyboardEvent(flags, key) => (key, flags).into(),
            other => panic!("unexpected event {other:?}"),
        })
        .collect()
}

#[test]
fn fast_path_pause_keeps_the_e1_prefix() {
    // E1 1D down, 45 down, E1 1D up, 45 up, as FreeRDP sends Pause.
    let events = fast_path_keys(&[0x10, 0x0a, 0x04, 0x1d, 0x00, 0x45, 0x05, 0x1d, 0x01, 0x45]);

    assert!(matches!(
        events.as_slice(),
        [
            KeyboardEvent::Pressed {
                code: 0x1d,
                extended: false,
                extended1: true
            },
            KeyboardEvent::Pressed {
                code: 0x45,
                extended: false,
                extended1: false
            },
            KeyboardEvent::Released {
                code: 0x1d,
                extended: false,
                extended1: true
            },
            KeyboardEvent::Released {
                code: 0x45,
                extended: false,
                extended1: false
            },
        ]
    ));
}

#[test]
fn fast_path_ctrl_has_no_e1_prefix() {
    let events = fast_path_keys(&[0x10, 0x0a, 0x00, 0x1d, 0x00, 0x45, 0x01, 0x1d, 0x01, 0x45]);

    assert!(events.iter().all(|event| matches!(
        event,
        KeyboardEvent::Pressed { extended1: false, .. } | KeyboardEvent::Released { extended1: false, .. }
    )));
}

#[test]
fn slow_path_scan_code_keeps_the_e1_prefix() {
    let pdu = ScanCodePdu {
        flags: ScanCodeFlags::EXTENDED_1,
        key_code: 0x1d,
    };

    let event: KeyboardEvent = (pdu.key_code, pdu.flags).into();

    assert!(matches!(
        event,
        KeyboardEvent::Pressed {
            code: 0x1d,
            extended: false,
            extended1: true
        }
    ));
}

#[test]
fn ainput_xbuttons_are_x1_and_x2() {
    let cases = [
        (MouseEventFlags::XBUTTON1 | MouseEventFlags::DOWN, MouseButton::X1, true),
        (MouseEventFlags::XBUTTON1, MouseButton::X1, false),
        (MouseEventFlags::XBUTTON2 | MouseEventFlags::DOWN, MouseButton::X2, true),
        (MouseEventFlags::XBUTTON2, MouseButton::X2, false),
    ];

    for (flags, expected_button, expected_pressed) in cases {
        let event: MouseEvent = AinputMousePdu {
            time: 0,
            flags,
            x: 100,
            y: 200,
        }
        .into();

        match event {
            MouseEvent::Button { x, y, button, pressed } => {
                assert_eq!((x, y, button, pressed), (100, 200, expected_button, expected_pressed));
            }
            other => panic!("{flags:?} decoded as {other:?}"),
        }
    }
}

#[test]
fn ainput_relative_buttons_carry_their_delta() {
    let cases = [
        (
            MouseEventFlags::BUTTON1 | MouseEventFlags::DOWN,
            MouseButton::Left,
            true,
        ),
        (MouseEventFlags::BUTTON2, MouseButton::Right, false),
        (
            MouseEventFlags::BUTTON3 | MouseEventFlags::DOWN,
            MouseButton::Middle,
            true,
        ),
        (MouseEventFlags::XBUTTON1, MouseButton::X1, false),
        (MouseEventFlags::XBUTTON2 | MouseEventFlags::DOWN, MouseButton::X2, true),
    ];
    for (flags, expected_button, expected_pressed) in cases {
        let event: MouseEvent = AinputMousePdu {
            time: 0,
            flags: flags | MouseEventFlags::REL | MouseEventFlags::HAVE_REL,
            x: -3,
            y: 4,
        }
        .into();
        match event {
            MouseEvent::ButtonRel { x, y, button, pressed } => {
                assert_eq!((x, y, button, pressed), (-3, 4, expected_button, expected_pressed));
            }
            other => panic!("{flags:?} decoded as {other:?}"),
        }
    }
}
