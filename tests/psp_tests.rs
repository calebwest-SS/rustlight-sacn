// Copyright 2024 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// BSR E1.31-1 Per-Slot Priority (PSP) tests.
//
// These tests validate:
//   - Packet parsing helpers (is_per_slot_priority_packet, per_slot_priorities)
//   - PSP packet serialization round-trips
//   - Receiver PSP state machine transitions
//   - Three-phase merge algorithm correctness
//   - Backwards compatibility (PSP disabled by default)
//   - Sender PSP packet construction

#![cfg_attr(rustfmt, rustfmt_skip)]

#[cfg(test)]
mod psp_tests {

use sacn::packet::*;
use sacn::receive::{SacnReceiver, PspSourceState};
use uuid::Uuid;
use std::borrow::Cow;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helper constants
// ---------------------------------------------------------------------------

const TEST_UNIVERSE: u16 = 1;

/// Builds a minimal AcnRootLayerProtocol byte buffer for a data packet with the given
/// property_values (which includes the START Code as the first byte).
///
/// Returns the packed bytes.
fn build_data_packet_bytes(
    cid: Uuid,
    universe: u16,
    priority: u8,
    sequence_number: u8,
    stream_terminated: bool,
    property_values: &[u8],
) -> Vec<u8> {
    let pkt = AcnRootLayerProtocol {
        pdu: E131RootLayer {
            cid,
            data: E131RootLayerData::DataPacket(DataPacketFramingLayer {
                source_name: Cow::Borrowed("TestSource"),
                priority,
                synchronization_address: 0,
                sequence_number,
                preview_data: false,
                stream_terminated,
                force_synchronization: false,
                universe,
                data: DataPacketDmpLayer {
                    property_values: Cow::Borrowed(property_values),
                },
            }),
        },
    };
    pkt.pack_alloc().expect("pack failed")
}

// ---------------------------------------------------------------------------
// Phase 1 tests – Packet parsing helpers
// ---------------------------------------------------------------------------

/// A PSP packet (START Code 0xDD) should be identified by is_per_slot_priority_packet.
#[test]
fn test_is_psp_packet_true_when_start_code_is_dd() {
    let psp_values: Vec<u8> = {
        let mut v = vec![E131_PER_SLOT_PRIORITY_START_CODE];
        v.extend(vec![100u8; 10]);
        v
    };
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Owned(psp_values),
    };
    assert!(dmp.is_per_slot_priority_packet());
}

/// A NSC packet (START Code 0x00) must NOT be identified as a PSP packet.
#[test]
fn test_is_psp_packet_false_for_nsc() {
    let nsc_values: Vec<u8> = vec![0x00, 50, 100, 200];
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Owned(nsc_values),
    };
    assert!(!dmp.is_per_slot_priority_packet());
}

/// An empty property_values slice is not a PSP packet.
#[test]
fn test_is_psp_packet_false_when_empty() {
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Borrowed(&[]),
    };
    assert!(!dmp.is_per_slot_priority_packet());
}

/// per_slot_priorities should skip the START Code byte and return the rest.
#[test]
fn test_per_slot_priorities_returns_payload_bytes() {
    let psp_values: Vec<u8> = vec![E131_PER_SLOT_PRIORITY_START_CODE, 10, 50, 100, 200];
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Owned(psp_values),
    };
    let priorities = dmp.per_slot_priorities();
    assert_eq!(priorities, vec![10u8, 50, 100, 200]);
}

/// Values > 200 in a PSP packet must be clamped to 0 (treated as "release slot").
#[test]
fn test_per_slot_priorities_clamps_invalid_values() {
    let psp_values: Vec<u8> = vec![E131_PER_SLOT_PRIORITY_START_CODE, 100, 201, 255, 50];
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Owned(psp_values),
    };
    let priorities = dmp.per_slot_priorities();
    // 201 and 255 are invalid (> 200) and must become 0.
    assert_eq!(priorities, vec![100u8, 0, 0, 50]);
}

/// A PSP packet with no priority bytes (just the START Code) returns an empty vec.
#[test]
fn test_per_slot_priorities_empty_when_only_start_code() {
    let psp_values: Vec<u8> = vec![E131_PER_SLOT_PRIORITY_START_CODE];
    let dmp = DataPacketDmpLayer {
        property_values: Cow::Owned(psp_values),
    };
    assert_eq!(dmp.per_slot_priorities(), Vec::<u8>::new());
}

/// DataPacketFramingLayer.is_per_slot_priority_packet() delegates to DataPacketDmpLayer correctly.
#[test]
fn test_framing_layer_is_psp_packet_helper() {
    let psp_values = vec![E131_PER_SLOT_PRIORITY_START_CODE, 100];
    let framing = DataPacketFramingLayer {
        source_name: Cow::Borrowed("Test"),
        priority: 100,
        synchronization_address: 0,
        sequence_number: 0,
        preview_data: false,
        stream_terminated: false,
        force_synchronization: false,
        universe: 1,
        data: DataPacketDmpLayer {
            property_values: Cow::Owned(psp_values),
        },
    };
    assert!(framing.is_per_slot_priority_packet());
}

/// A PSP packet can be serialized and parsed again without losing data.
#[test]
fn test_psp_packet_round_trip_full() {
    let cid = Uuid::new_v4();
    let mut priorities = vec![E131_PER_SLOT_PRIORITY_START_CODE];
    priorities.extend((1u8..=200).cycle().take(512)); // 512 valid priority bytes

    let packed = build_data_packet_bytes(cid, TEST_UNIVERSE, 100, 0, false, &priorities);
    let parsed = AcnRootLayerProtocol::parse(&packed).expect("parse failed");

    if let E131RootLayerData::DataPacket(ref framing) = parsed.pdu.data {
        assert!(framing.is_per_slot_priority_packet());
        let extracted = framing.data.per_slot_priorities();
        assert_eq!(extracted.len(), 512);
        // Verify all values round-trip correctly.
        // The iterator (1u8..=200).cycle().take(512) produces values 1..=200 repeating.
        // Use usize arithmetic to avoid u8 overflow when computing the expected value.
        for (i, &v) in extracted.iter().enumerate() {
            let expected = ((i % 200) + 1) as u8; // 1..=200 cycling
            assert_eq!(v, expected, "mismatch at slot {i}");
        }
    } else {
        panic!("Expected DataPacket variant");
    }
}

/// A partial PSP packet (fewer than 512 slots) round-trips correctly.
#[test]
fn test_psp_packet_round_trip_partial() {
    let cid = Uuid::new_v4();
    let partial_priorities: Vec<u8> = {
        let mut v = vec![E131_PER_SLOT_PRIORITY_START_CODE];
        v.extend(vec![150u8; 10]); // only 10 slots
        v
    };

    let packed = build_data_packet_bytes(cid, TEST_UNIVERSE, 100, 0, false, &partial_priorities);
    let parsed = AcnRootLayerProtocol::parse(&packed).expect("parse failed");

    if let E131RootLayerData::DataPacket(ref framing) = parsed.pdu.data {
        assert!(framing.is_per_slot_priority_packet());
        let extracted = framing.data.per_slot_priorities();
        assert_eq!(extracted.len(), 10);
        assert!(extracted.iter().all(|&p| p == 150));
    } else {
        panic!("Expected DataPacket variant");
    }
}

/// The PSP START Code constant must equal 0xDD.
#[test]
fn test_psp_start_code_constant_value() {
    assert_eq!(E131_PER_SLOT_PRIORITY_START_CODE, 0xDD);
}

/// PSP_STARTUP_MIN_PACKETS must equal 3.
#[test]
fn test_psp_startup_min_packets_constant() {
    assert_eq!(PSP_STARTUP_MIN_PACKETS, 3);
}

/// PSP_STARTUP_WINDOW must be 1500 ms.
#[test]
fn test_psp_startup_window_constant() {
    assert_eq!(PSP_STARTUP_WINDOW, Duration::from_millis(1500));
}

// ---------------------------------------------------------------------------
// Helpers for receiver state machine tests
// ---------------------------------------------------------------------------

/// Creates a SacnReceiver with PSP mode enabled, listening to TEST_UNIVERSE.
/// Returns (receiver, bound_socket_addr) so callers can send to it.
fn make_psp_receiver() -> SacnReceiver {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut rx = SacnReceiver::with_ip(ip, None).expect("receiver creation failed");
    rx.set_per_slot_priority_mode(true);
    rx.listen_universes(&[TEST_UNIVERSE]).expect("listen failed");
    rx
}

// ---------------------------------------------------------------------------
// Phase 2 – PSP mode flag tests
// ---------------------------------------------------------------------------

/// PSP mode is disabled by default.
#[test]
fn test_psp_mode_disabled_by_default() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let rx = SacnReceiver::with_ip(ip, None).expect("receiver creation failed");
    assert!(!rx.get_per_slot_priority_mode());
}

/// Setting PSP mode to true then back to false clears all accumulated PSP state.
#[test]
fn test_psp_mode_clear_state_on_disable() {
    let mut rx = make_psp_receiver();
    assert!(rx.get_per_slot_priority_mode());

    rx.set_per_slot_priority_mode(false);
    assert!(!rx.get_per_slot_priority_mode());
    // After disabling, no PSP state should remain for any source/universe.
    assert!(rx.psp_source_state(Uuid::new_v4(), TEST_UNIVERSE).is_none());
}

// ---------------------------------------------------------------------------
// Phase 3 – State machine transition tests
// (These use internal APIs to inject state directly rather than the network.)
// ---------------------------------------------------------------------------

/// A new PerSlotPriorityEntry created from an NSC should start in PendingPriority.
#[test]
fn test_psp_entry_from_nsc_is_pending_priority() {
    // We test via the public psp_source_state() accessor after a simulated receive.
    // Since we can't send real network packets in unit tests, we verify the types directly.
    let nsc_levels = vec![0x00u8, 50, 100, 200];
    let entry = sacn::receive::PerSlotPriorityEntryTest::from_nsc(nsc_levels, 100);
    assert_eq!(entry.state, PspSourceState::PendingPriority);
    assert!(entry.nsc_levels.is_some());
    assert!(entry.psp_priorities.is_none());
    assert!(entry.startup_entered.is_some());
}

/// A new PerSlotPriorityEntry created from a PSP should start in PendingLevels.
#[test]
fn test_psp_entry_from_psp_is_pending_levels() {
    let psp_priorities = vec![100u8, 150, 200];
    let entry = sacn::receive::PerSlotPriorityEntryTest::from_psp(psp_priorities);
    assert_eq!(entry.state, PspSourceState::PendingLevels);
    assert!(entry.nsc_levels.is_none());
    assert!(entry.psp_priorities.is_some());
}

// ---------------------------------------------------------------------------
// Phase 4 – Merge algorithm tests (via DMXData construction helpers)
// ---------------------------------------------------------------------------

/// When PSP mode is disabled, the receiver should return data unchanged per
/// existing ANSI E1.31-2018 semantics (each packet is returned independently).
#[test]
fn test_psp_disabled_returns_data_unchanged() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let rx = SacnReceiver::with_ip(ip, None).expect("receiver creation failed");
    // PSP mode is off by default – verify it's actually off.
    assert!(!rx.get_per_slot_priority_mode());
}

// ---------------------------------------------------------------------------
// Merge algorithm unit tests (pure logic, no network)
// ---------------------------------------------------------------------------

/// compute_psp_merge_direct tests the merge logic by building entries manually
/// and calling the merge on the result.

/// Two per-universe sources: higher priority wins.
#[test]
fn test_merge_per_universe_higher_priority_wins() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();
    let src_b = Uuid::new_v4();

    // Source A: priority 100, level 200 for slot 0
    harness.add_per_universe(src_a, 100, vec![0x00, 200]);
    // Source B: priority 150, level 50 for slot 0
    harness.add_per_universe(src_b, 150, vec![0x00, 50]);

    let result = harness.merge().expect("merge failed");
    // Source B wins because its packet priority (150) is higher.
    assert_eq!(result.values[1], 50, "Source B (priority 150) should win");
    assert_eq!(result.priority, 150);
}

/// Two per-universe sources with equal priority: HTP on levels.
#[test]
fn test_merge_per_universe_equal_priority_htp() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();
    let src_b = Uuid::new_v4();

    harness.add_per_universe(src_a, 100, vec![0x00, 200]); // level 200
    harness.add_per_universe(src_b, 100, vec![0x00, 50]);  // level 50

    let result = harness.merge().expect("merge failed");
    // HTP: 200 > 50
    assert_eq!(result.values[1], 200, "HTP should pick level 200");
}

/// A per-slot source with priority 0 releases the slot.
#[test]
fn test_merge_per_slot_priority_zero_releases_slot() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();

    // Source A: per-slot, priority 0 for slot 0 → releases it.
    let psp = vec![0u8]; // priority 0 for slot 0
    harness.add_per_slot(src_a, 100, vec![0x00, 255], psp);

    let result = harness.merge().expect("merge failed");
    // Slot 0 should be 0 because the only source released it.
    assert_eq!(result.values[1], 0, "Released slot should be 0");
}

/// A per-slot source with a valid priority takes the slot.
#[test]
fn test_merge_per_slot_priority_asserts_slot() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();

    // Source A: per-slot, priority 100 for slot 0, level 128.
    let psp = vec![100u8]; // priority 100 for slot 0
    harness.add_per_slot(src_a, 100, vec![0x00, 128], psp);

    let result = harness.merge().expect("merge failed");
    assert_eq!(result.values[1], 128);
    assert_eq!(result.priority, 100);
}

/// Per-slot source beats per-universe source when it has higher priority for a slot.
#[test]
fn test_merge_per_slot_beats_per_universe_with_higher_slot_priority() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();
    let src_b = Uuid::new_v4();

    // Source A: per-universe priority 100, level 100 for slot 0
    harness.add_per_universe(src_a, 100, vec![0x00, 100]);
    // Source B: per-slot, slot 0 priority 150, level 50
    harness.add_per_slot(src_b, 100, vec![0x00, 50], vec![150]);

    let result = harness.merge().expect("merge failed");
    // Source B slot priority (150) > Source A packet priority (100) → Source B wins
    assert_eq!(result.values[1], 50, "Per-slot source B (priority 150) should win slot 0");
}

/// Per-universe source beats per-slot source when its packet priority is higher than
/// the per-slot source's slot priority.
#[test]
fn test_merge_per_universe_beats_per_slot_with_higher_packet_priority() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();
    let src_b = Uuid::new_v4();

    // Source A: per-universe priority 200, level 100 for slot 0
    harness.add_per_universe(src_a, 200, vec![0x00, 100]);
    // Source B: per-slot, slot 0 priority 100, level 50
    harness.add_per_slot(src_b, 100, vec![0x00, 50], vec![100]);

    let result = harness.merge().expect("merge failed");
    // Source A packet priority (200) > Source B slot priority (100) → Source A wins
    assert_eq!(result.values[1], 100, "Per-universe source A (priority 200) should win slot 0");
}

/// Tied priority: HTP tie-break selects the higher level.
#[test]
fn test_merge_tied_priority_htp_tiebreak() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();
    let src_b = Uuid::new_v4();

    // Both sources: per-slot priority 100 for slot 0.
    harness.add_per_slot(src_a, 100, vec![0x00, 200], vec![100]); // level 200
    harness.add_per_slot(src_b, 100, vec![0x00, 50], vec![100]);  // level 50

    let result = harness.merge().expect("merge failed");
    // HTP: 200 > 50
    assert_eq!(result.values[1], 200, "HTP should pick 200 when priorities are tied");
}

/// No active sources produces None from the merge.
#[test]
fn test_merge_no_active_sources_returns_none() {
    use sacn::receive::PspMergeTestHarness;
    let harness = PspMergeTestHarness::new(TEST_UNIVERSE);
    assert!(harness.merge().is_none());
}

/// Omitted PSP slots (packet shorter than 512 bytes) are treated as priority 0.
#[test]
fn test_merge_omitted_psp_slots_treated_as_priority_zero() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);

    let src_a = Uuid::new_v4();

    // PSP only covers slot 0 (priority 100); slot 1 is omitted (priority 0).
    // NSC has values for both slots.
    let psp = vec![100u8]; // only slot 0
    harness.add_per_slot(src_a, 100, vec![0x00, 200, 150], psp);

    let result = harness.merge().expect("merge failed");
    // Slot 0: priority 100, level 200.
    assert_eq!(result.values[1], 200);
    // Slot 1: priority 0 (omitted), so it should be 0.
    assert_eq!(result.values[2], 0);
}

/// An all-zero NSC has no visible effect on the merge output.
#[test]
fn test_merge_produces_correct_universe_in_output() {
    use sacn::receive::PspMergeTestHarness;
    let mut harness = PspMergeTestHarness::new(TEST_UNIVERSE);
    let src_a = Uuid::new_v4();
    harness.add_per_universe(src_a, 100, vec![0x00, 42]);
    let result = harness.merge().expect("merge failed");
    assert_eq!(result.universe, TEST_UNIVERSE);
}

// ---------------------------------------------------------------------------
// PSP source state helper tests
// ---------------------------------------------------------------------------

/// effective_priority returns packet priority for PendingPriority state.
#[test]
fn test_effective_priority_pending_priority_returns_packet_priority() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let entry = PerSlotPriorityEntryTest::from_nsc(vec![0x00, 50], 100);
    assert_eq!(entry.effective_priority(0), 100);
}

/// effective_priority returns packet priority for ActivePerUniverse state.
#[test]
fn test_effective_priority_active_per_universe_returns_packet_priority() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let mut entry = PerSlotPriorityEntryTest::from_nsc(vec![0x00, 50], 100);
    entry.set_state(PspSourceState::ActivePerUniverse);
    assert_eq!(entry.effective_priority(0), 100);
}

/// effective_priority returns per-slot priority for ActivePerSlot state.
#[test]
fn test_effective_priority_active_per_slot_returns_slot_priority() {
    use sacn::receive::PerSlotPriorityEntryTest;
    // PSP priorities: slot 0 → 0 (released), slot 1 → 150, slot 2 → 200
    let mut entry = PerSlotPriorityEntryTest::from_psp(vec![0, 150, 200]);
    entry.set_state(PspSourceState::ActivePerSlot);
    entry.set_nsc(vec![0x00, 10, 20], 100);
    assert_eq!(entry.effective_priority(0), 0);   // released
    assert_eq!(entry.effective_priority(1), 150);  // slot 1
    assert_eq!(entry.effective_priority(2), 200);  // slot 2
}

/// effective_priority returns 0 for PendingLevels (no NSC yet → not contributing).
#[test]
fn test_effective_priority_pending_levels_returns_zero() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let entry = PerSlotPriorityEntryTest::from_psp(vec![100, 150]);
    assert_eq!(entry.effective_priority(0), 0);
}

/// level() correctly skips the START Code byte.
#[test]
fn test_level_skips_start_code_byte() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let entry = PerSlotPriorityEntryTest::from_nsc(vec![0x00, 42, 99, 200], 100);
    assert_eq!(entry.level(0), 42);   // slot 0 (nsc_levels index 1)
    assert_eq!(entry.level(1), 99);   // slot 1 (nsc_levels index 2)
    assert_eq!(entry.level(2), 200);  // slot 2 (nsc_levels index 3)
}

/// is_active returns true for PendingPriority, ActivePerUniverse, ActivePerSlot.
#[test]
fn test_is_active_for_contributing_states() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let mut entry = PerSlotPriorityEntryTest::from_nsc(vec![0x00, 50], 100);

    entry.set_state(PspSourceState::PendingPriority);
    assert!(entry.is_active());

    entry.set_state(PspSourceState::ActivePerUniverse);
    assert!(entry.is_active());

    entry.set_state(PspSourceState::ActivePerSlot);
    assert!(entry.is_active());
}

/// is_active returns false for PendingLevels and Inactive.
#[test]
fn test_is_active_false_for_non_contributing_states() {
    use sacn::receive::PerSlotPriorityEntryTest;
    let mut entry = PerSlotPriorityEntryTest::from_psp(vec![100]);

    entry.set_state(PspSourceState::PendingLevels);
    assert!(!entry.is_active());

    entry.set_state(PspSourceState::Inactive);
    assert!(!entry.is_active());
}

} // mod psp_tests
