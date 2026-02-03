//! NodeCore builder pattern implementation
//!
//! The [`NodeCoreBuilder`] provides a fluent API for configuring and creating
//! a [`NodeCore`] instance.

use crate::destination::ProofStrategy;
use crate::identity::Identity;
use crate::traits::Context;
use crate::transport::TransportConfig;

use super::NodeCore;

/// Error type for NodeCore building
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// No identity was provided and none could be generated
    NoIdentity,
    /// Invalid configuration
    InvalidConfig,
}

/// Builder for creating [`NodeCore`] instances
///
/// # Example
///
/// ```no_run
/// use reticulum_core::node::NodeCoreBuilder;
/// use reticulum_core::identity::Identity;
/// use reticulum_core::destination::ProofStrategy;
/// use reticulum_core::traits::{Clock, NoStorage, PlatformContext};
/// # use core::cell::Cell;
/// # struct MyClock(Cell<u64>);
/// # impl MyClock { fn new(ms: u64) -> Self { Self(Cell::new(ms)) } }
/// # impl Clock for MyClock { fn now_ms(&self) -> u64 { self.0.get() } }
///
/// # fn example() {
/// let mut ctx = PlatformContext {
///     rng: rand_core::OsRng,
///     clock: MyClock::new(0),
///     storage: NoStorage,
/// };
/// let my_identity = Identity::generate(&mut ctx);
///
/// let node = NodeCoreBuilder::new()
///     .identity(my_identity)
///     .proof_strategy(ProofStrategy::All)
///     .enable_transport(true)
///     .build(&mut ctx, MyClock::new(0), NoStorage)
///     .unwrap();
/// # }
/// ```
pub struct NodeCoreBuilder {
    identity: Option<Identity>,
    proof_strategy: ProofStrategy,
    transport_config: TransportConfig,
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

    /// Set the full transport configuration
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.transport_config = config;
        self
    }

    /// Build the NodeCore instance
    ///
    /// If no identity was provided, a new one will be generated using the
    /// context's RNG.
    ///
    /// # Arguments
    /// * `ctx` - Platform context providing RNG, clock, and storage (consumed)
    ///
    /// Note: This takes ownership of the clock and storage from the context.
    /// You'll need to provide new instances for subsequent operations.
    pub fn build<C, Clk, S>(
        self,
        ctx: &mut C,
        clock: Clk,
        storage: S,
    ) -> Result<NodeCore<Clk, S>, BuildError>
    where
        C: Context,
        Clk: crate::traits::Clock,
        S: crate::traits::Storage,
    {
        // Get or generate identity
        let identity = match self.identity {
            Some(id) => id,
            None => Identity::generate(ctx),
        };

        Ok(NodeCore::new(
            identity,
            self.transport_config,
            self.proof_strategy,
            clock,
            storage,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Clock, NoStorage, PlatformContext};
    use core::cell::Cell;
    use rand_core::OsRng;

    struct MockClock(Cell<u64>);

    impl MockClock {
        fn new(ms: u64) -> Self {
            Self(Cell::new(ms))
        }
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    fn make_ctx() -> PlatformContext<OsRng, MockClock, NoStorage> {
        PlatformContext {
            rng: OsRng,
            clock: MockClock::new(1_000_000),
            storage: NoStorage,
        }
    }

    #[test]
    fn test_builder_default() {
        let mut ctx = make_ctx();
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(&mut ctx, clock, NoStorage)
            .unwrap();

        assert_eq!(node.active_connection_count(), 0);
        assert_eq!(node.pending_connection_count(), 0);
    }

    #[test]
    fn test_builder_with_identity() {
        let mut ctx = make_ctx();
        let identity = Identity::generate_with_rng(&mut OsRng);
        let id_hash = *identity.hash();
        let clock = MockClock::new(1_000_000);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .build(&mut ctx, clock, NoStorage)
            .unwrap();

        assert_eq!(node.identity().hash(), &id_hash);
    }

    #[test]
    fn test_builder_with_proof_strategy() {
        let mut ctx = make_ctx();
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .proof_strategy(ProofStrategy::All)
            .build(&mut ctx, clock, NoStorage)
            .unwrap();

        assert_eq!(node.default_proof_strategy(), ProofStrategy::All);
    }

    #[test]
    fn test_builder_with_transport_config() {
        let mut ctx = make_ctx();
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .enable_transport(true)
            .max_hops(10)
            .path_expiry_secs(7200)
            .build(&mut ctx, clock, NoStorage)
            .unwrap();

        assert!(node.transport_config().enable_transport);
        assert_eq!(node.transport_config().max_hops, 10);
        assert_eq!(node.transport_config().path_expiry_secs, 7200);
    }

    #[test]
    fn test_builder_chaining() {
        let mut ctx = make_ctx();
        let identity = Identity::generate_with_rng(&mut OsRng);
        let clock = MockClock::new(1_000_000);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .proof_strategy(ProofStrategy::App)
            .enable_transport(false)
            .max_hops(5)
            .path_expiry_secs(3600)
            .announce_rate_limit_ms(5000)
            .packet_cache_expiry_ms(120_000)
            .build(&mut ctx, clock, NoStorage)
            .unwrap();

        assert_eq!(node.default_proof_strategy(), ProofStrategy::App);
        assert!(!node.transport_config().enable_transport);
        assert_eq!(node.transport_config().max_hops, 5);
    }
}
