//! On-device tests for Heltec Mesh Node T114
//!
//! Requires probe-rs + connected T114 board.
//! Run with: `cargo test --package reticulum-nrf --target thumbv7em-none-eabihf`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use defmt_rtt as _;
use panic_probe as _;

use reticulum_nrf::init_heap;

// Dummy RNG for tests (deterministic, NOT cryptographically secure)
struct DummyRng(u64);

impl DummyRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl rand_core::RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut pos = 0;
        while pos < dest.len() {
            let val = self.next_u64().to_le_bytes();
            let remaining = dest.len() - pos;
            let to_copy = remaining.min(8);
            dest[pos..pos + to_copy].copy_from_slice(&val[..to_copy]);
            pos += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DummyRng {}

// Dummy clock for tests (returns a fixed timestamp)
struct DummyClock {
    now: core::cell::Cell<u64>,
}

impl DummyClock {
    fn new(now_ms: u64) -> Self {
        Self {
            now: core::cell::Cell::new(now_ms),
        }
    }
}

impl reticulum_core::traits::Clock for DummyClock {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
}

#[defmt_test::tests]
mod tests {
    use super::*;

    #[init]
    fn setup() {
        init_heap();
    }

    #[test]
    fn heap_allocator_works() {
        let v: alloc::vec::Vec<u8> = vec![42; 1024];
        defmt::assert_eq!(v.len(), 1024);
        defmt::assert_eq!(v[0], 42);
        defmt::assert_eq!(v[1023], 42);
    }

    #[test]
    fn core_nodebuilder_creates_on_device() {
        use reticulum_core::node::NodeCoreBuilder;

        let rng = DummyRng::new(0xDEAD_BEEF);
        let clock = DummyClock::new(1000);
        let storage = reticulum_core::traits::NoStorage;

        let node = NodeCoreBuilder::new()
            .build(rng, clock, storage)
            .expect("NodeCore build failed on device");

        defmt::assert_eq!(node.path_count(), 0);
    }

    #[test]
    fn core_handle_packet_doesnt_overflow_stack() {
        use reticulum_core::node::NodeCoreBuilder;
        use reticulum_core::transport::InterfaceId;

        let rng = DummyRng::new(0xCAFE_BABE);
        let clock = DummyClock::new(2000);
        let storage = reticulum_core::traits::NoStorage;

        let mut node = NodeCoreBuilder::new()
            .build(rng, clock, storage)
            .expect("NodeCore build failed");

        // 500-byte junk packet — should be rejected gracefully, not crash
        let packet = vec![0xFFu8; 500];
        let output = node.handle_packet(InterfaceId(0), &packet);
        // Just verify we didn't crash and got a valid output
        let _ = output.actions.len();
    }

    #[test]
    fn embassy_channel_round_trip() {
        use reticulum_net::IncomingPacket;

        // Verify IncomingPacket can be created and destructured on device
        let pkt = IncomingPacket {
            data: vec![1, 2, 3, 4],
        };
        defmt::assert_eq!(pkt.data.len(), 4);
        defmt::assert_eq!(pkt.data[0], 1);
    }
}
