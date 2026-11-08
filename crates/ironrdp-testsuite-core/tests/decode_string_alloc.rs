#![allow(unused_crate_dependencies)] // false positives because there is both a library and a binary
//! Counts heap allocations while decoding a string, in its own binary because it installs a global allocator.
//!
//! A decode that grows or re-allocates its output frees a copy of the text (a password, for Client Info) without
//! wiping it, so the decoded string must be the only allocation.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

use ironrdp_pdu::utils::{CharacterSet, decode_string};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count() {
    ALLOCATIONS.with(|n| n.set(n.get() + 1));
}

// SAFETY: forwards every call to `System` unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's contract is `System::alloc`'s.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's contract is `System::alloc_zeroed`'s.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: the caller's contract is `System::realloc`'s.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is `System::dealloc`'s.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The decoded string and the number of allocations decoding it took.
fn decode_counted(src: &[u8], character_set: CharacterSet) -> (String, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let decoded = decode_string(src, character_set, true).expect("decodes");
    (decoded, ALLOCATIONS.with(Cell::get) - before)
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn decode_string_allocates_once() {
    let ascii = "correct horse battery staple";
    let cjk = "\u{5bc6}\u{78bc}\u{306f}\u{79d8}\u{5bc6}\u{306e}\u{9375}";
    let cases = [
        (format!("{ascii}\0").into_bytes(), CharacterSet::Ansi, ascii),
        (format!("{ascii}\0\0\0").into_bytes(), CharacterSet::Ansi, ascii),
        (format!("{cjk}\0").into_bytes(), CharacterSet::Ansi, cjk),
        (utf16(&format!("{ascii}\0")), CharacterSet::Unicode, ascii),
        (utf16(&format!("{cjk}\0")), CharacterSet::Unicode, cjk),
        (utf16(&format!("{cjk}\0\0\0")), CharacterSet::Unicode, cjk),
    ];

    for (src, character_set, expected) in cases {
        let (decoded, allocations) = decode_counted(&src, character_set);
        assert_eq!(decoded, expected);
        assert_eq!(allocations, 1, "{character_set:?} {expected:?} takes one allocation");
        assert_eq!(decoded.capacity(), expected.len(), "{expected:?} fills its allocation");
    }
}

#[test]
fn decode_string_of_nulls_allocates_nothing() {
    for (src, character_set) in [(vec![0; 3], CharacterSet::Ansi), (vec![0; 6], CharacterSet::Unicode)] {
        let (decoded, allocations) = decode_counted(&src, character_set);
        assert_eq!(decoded, "");
        assert_eq!(allocations, 0, "{character_set:?} nulls take no allocation");
    }
}
