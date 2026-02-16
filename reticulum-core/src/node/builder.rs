//! NodeCore builder pattern implementation
//!
//! The [`NodeCoreBuilder`] provides a fluent API for configuring and creating
//! a [`NodeCore`] instance.

use crate::destination::ProofStrategy;
use crate::identity::Identity;
use crate::transport::TransportConfig;
use rand_core::CryptoRngCore;

use super::NodeCore;

/// Builder for creating [`NodeCore`] instances
///
/// # Example
///
/// ```no_run
/// use reticulum_core::node::NodeCoreBuilder;
/// use reticulum_core::identity::Identity;
/// use reticulum_core::destination::ProofStrategy;
/// use reticulum_core::traits::{Clock, NoStorage};
/// # use core::cell::Cell;
/// # struct MyClock(Cell<u64>);
/// # impl MyClock { fn new(ms: u64) -> Self { Self(Cell::new(ms)) } }
/// # impl Clock for MyClock { fn now_ms(&self) -> u64 { self.0.get() } }
///
/// # fn example() {
/// let my_identity = Identity::generate(&mut rand_core::OsRng);
///
/// let node = NodeCoreBuilder::new()
///     .identity(my_identity)
///     .proof_strategy(ProofStrategy::All)
///     .enable_transport(true)
///     .build(rand_core::OsRng, MyClock::new(0), NoStorage);
/// # }
/// ```
pub struct NodeCoreBuilder {
    identity: Option<Identity>,
    proof_strategy: ProofStrategy,
    transport_config: TransportConfig,
    max_known_identities: usize,
}

impl Default for NodeCoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeCoreBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            identity: None,
            proof_strategy: ProofStrategy::None,
            transport_config: TransportConfig::default(),
            max_known_identities: 256,
        }
    }

    /// Set the node's identity
    ///
    /// If not set, a new identity will be generated during `build()`.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the default proof strategy for destinations
    pub fn proof_strategy(mut self, strategy: ProofStrategy) -> Self {
        self.proof_strategy = strategy;
        self
    }

    /// Enable or disable transport mode (routing for other nodes)
    pub fn enable_transport(mut self, enable: bool) -> Self {
        self.transport_config.enable_transport = enable;
        self
    }

    /// Set the maximum number of hops for path finding
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.transport_config.max_hops = hops;
        self
    }

    /// Set the path expiry time in seconds
    pub fn path_expiry_secs(mut self, secs: u64) -> Self {
        self.transport_config.path_expiry_secs = secs;
        self
    }

    /// Set the announce rate limit interval in milliseconds
    pub fn announce_rate_limit_ms(mut self, ms: u64) -> Self {
        self.transport_config.announce_rate_limit_ms = ms;
        self
    }

    /// Set the packet cache expiry time in milliseconds
    pub fn packet_cache_expiry_ms(mut self, ms: u64) -> Self {
        self.transport_config.packet_cache_expiry_ms = ms;
        self
    }

    /// Set the maximum number of remote identities to cache
    ///
    /// Identities are learned from announces and used for single-packet encryption.
    /// Default: 256.
    pub fn max_known_identities(mut self, n: usize) -> Self {
        self.max_known_identities = n;
        self
    }

    /// Set the full transport configuration
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.transport_config = config;
        self
    }

    /// Check if transport mode is enabled in this builder
    pub fn is_transport_enabled(&self) -> bool {
        self.transport_config.enable_transport
    }

    /// Build the NodeCore instance
    ///
    /// If no identity was provided, a new one will be generated using the RNG.
    ///
    /// # Arguments
    /// * `rng` - Random number generator (moved into NodeCore)
    /// * `clock` - Clock instance (moved into NodeCore)
    /// * `storage` - Storage instance (moved into NodeCore)
    pub fn build<R, Clk, S>(self, mut rng: R, clock: Clk, storage: S) -> NodeCore<R, Clk, S>
    where
        R: CryptoRngCore,
        Clk: crate::traits::Clock,
        S: crate::traits::Storage,
    {
        // Get or generate identity
        let identity = match self.identity {
            Some(id) => id,
            None => Identity::generate(&mut rng),
        };

        NodeCore::new(
            identity,
            self.transport_config,
            self.proof_strategy,
            self.max_known_identities,
            rng,
            clock,
            storage,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MockClock, TEST_TIME_MS};
    use crate::traits::NoStorage;
    use rand_core::OsRng;

    #[test]
    fn test_builder_default() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        assert_eq!(node.active_link_count(), 0);
        assert_eq!(node.pending_link_count(), 0);
    }

    #[test]
    fn test_builder_with_identity() {
        let identity = Identity::generate(&mut OsRng);
        let id_hash = *identity.hash();
        let clock = MockClock::new(TEST_TIME_MS);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .build(OsRng, clock, NoStorage);

        assert_eq!(node.identity().hash(), &id_hash);
    }

    #[test]
    fn test_builder_with_proof_strategy() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new()
            .proof_strategy(ProofStrategy::All)
            .build(OsRng, clock, NoStorage);

        assert_eq!(node.default_proof_strategy(), ProofStrategy::All);
    }

    #[test]
    fn test_builder_with_transport_config() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new()
            .enable_transport(true)
            .max_hops(10)
            .path_expiry_secs(7200)
            .build(OsRng, clock, NoStorage);

        assert!(node.transport_config().enable_transport);
        assert_eq!(node.transport_config().max_hops, 10);
        assert_eq!(node.transport_config().path_expiry_secs, 7200);
    }

    #[test]
    fn test_builder_chaining() {
        let identity = Identity::generate(&mut OsRng);
        let clock = MockClock::new(TEST_TIME_MS);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .proof_strategy(ProofStrategy::App)
            .enable_transport(false)
            .max_hops(5)
            .path_expiry_secs(3600)
            .announce_rate_limit_ms(5000)
            .packet_cache_expiry_ms(120_000)
            .build(OsRng, clock, NoStorage);

        assert_eq!(node.default_proof_strategy(), ProofStrategy::App);
        assert!(!node.transport_config().enable_transport);
        assert_eq!(node.transport_config().max_hops, 5);
    }
}
