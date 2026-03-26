//! # Bounty Escrow — Event Definitions
//!
//! All events emitted by [`BountyEscrowContract`] conform to **EVENT_VERSION_V2**,
//! the canonical Grainlify event envelope.
//!
//! ## EVENT_VERSION_V2 Contract
//!
//! Every event payload carries a `version: u32` field set to the
//! [`EVENT_VERSION_V2`] constant (`2`).  The **first** topic slot is always a
//! domain `Symbol` that names the event category; the second topic (where
//! present) is the `bounty_id` so indexers can filter by both category *and*
//! bounty without decoding the payload.
//!
//! ```text
//! topics : (category_symbol [, bounty_id: u64])
//! data   : <EventStruct>   ← always carries version: u32 = 2
//! ```
//!
//! ## Why topic-level versioning?
//!
//! Soroban events are permanently archived.  Placing the version in the payload
//! (rather than a topic) would force indexers to decode every event body just to
//! determine whether the schema is relevant.  Placing it in `topics[0]` allows
//! cheap prefix-filter queries at the RPC/Horizon layer.
//!
//! ## Security invariants
//!
//! * Events are emitted **after** all state mutations and token transfers
//!   (Checks-Effects-Interactions ordering) so they accurately reflect final
//!   on-chain state.
//! * No PII, KYC data, or private keys are ever emitted.
//! * All `symbol_short!` strings are ≤ 8 bytes — Soroban silently truncates
//!   longer strings, which would corrupt topic-based filtering.
use crate::CapabilityAction;
use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol};

// ── Version constant ─────────────────────────────────────────────────────────

/// Canonical event schema version included in **every** event payload.
///
/// Increment this value  and update all emitter functions whenever the
/// payload schema changes in a breaking way.  Non-breaking additions that is new
/// optional fields do not require a version bump.
pub const EVENT_VERSION_V2: u32 = 2;

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_bounty_initialized`] event.
///
/// Emitted **exactly once** when [`BountyEscrowContract::init`] succeeds.
/// Indexers can treat the presence of this event as proof that the contract
/// was legitimately initialised with a specific admin or token pair.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"init"` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `admin` | `Address` | Initial admin address |
/// | `token` | `Address` | Reward token contract |
/// | `timestamp` | `u64` | Ledger time of initialization |
///
/// ### Security notes
/// - This event is replay-safe: the contract enforces
///   `AlreadyInitialized` on subsequent `init` calls, so this event is
///   emitted at most once per deployed contract instance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BountyEscrowInitialized {
    pub version: u32,
    pub admin: Address, // address granted admin authority over this contract.
    pub token: Address, // Soroban compatible token contract address (SAC or SEP-41).
    pub timestamp: u64,
}

/// Emit [`BountyEscrowInitialized`].
///
/// # Arguments
/// * `env`   — Soroban execution environment.
/// * `event` — Pre constructed event payload.
///
/// # Panics
/// Never panics; publishing is infallible in Soroban.
pub fn emit_bounty_initialized(env: &Env, event: BountyEscrowInitialized) {
    let topics = (symbol_short!("init"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUNDS LOCK , RELEASE and  REFUND EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_funds_locked`] event.
///
/// Emitted after a successful [`BountyEscrowContract::lock_funds`] call.
/// The `amount` field reflects the **gross** deposit (before fee deduction).
/// Net escrowed principal can be derived as `amount - lock_fee`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_lock"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - Emitted after the token transfer succeeds, so the event reliably
///   represents funds that are already in the escrow contract.
/// - `deadline` is stored on-chain; this field is purely informational
///   for off-chain consumers.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsLocked {
    pub version: u32,
    pub bounty_id: u64,     // a unique bounty identifier assigned by the backend
    pub amount: i128,       //  gross amount deposited
    pub depositor: Address, // address that does the deposit
    pub deadline: u64,
}

/// Emit [`FundsLocked`].
///
/// # Arguments
/// * `env`   — Soroban execution environment.
/// * `event` — Pre-constructed event payload; `bounty_id` is also published
///   as `topics[1]` for cheap indexed filtering.
pub fn emit_funds_locked(env: &Env, event: FundsLocked) {
    let topics = (symbol_short!("f_lock"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_funds_released`] event.
///
/// Emitted after a successful fund release to a contributor, including
/// [`BountyEscrowContract::release_funds`], `partial_release`, and
/// `release_with_capability` paths.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_rel"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - For `partial_release`, this event is emitted per call.  Consumers
///   should sum all `FundsReleased` events to reconstruct total payout.
/// - `amount` is the net payout after any release fee.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsReleased {
    pub version: u32,
    pub bounty_id: u64,
    pub amount: i128,       // amount transferred to `recipient`
    pub recipient: Address, // the contributor wallet address that received the funds.
    pub timestamp: u64,
}

/// Emit [`FundsReleased`].
pub fn emit_funds_released(env: &Env, event: FundsReleased) {
    let topics = (symbol_short!("f_rel"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

// ── Refund trigger type ───────────────────────────────────────────────────────

/// Discriminator indicating which code path triggered a refund.
///
/// Carried in [`FundsRefunded`] and [`RefundRecord`] so that indexers and
/// auditors can distinguish between the three refund mechanisms without
/// inspecting storage or transaction inputs.
///
/// | Variant | Trigger |
/// |---------|---------|
/// | `AdminApproval` | Admin called `approve_refund` then `refund` (existing dual-auth path). |
/// | `DeadlineExpired` | `auto_refund` called permissionlessly after the deadline passed. |
/// | `OracleAttestation` | Configured oracle called `oracle_refund` to attest a dispute outcome. |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundTriggerType {
    /// Admin-approved refund (existing dual-auth behavior).
    AdminApproval,
    /// Time-based auto-refund after deadline (permissionless).
    DeadlineExpired,
    /// Oracle-attested refund (dispute resolved in favor of depositor).
    OracleAttestation,
}

/// Payload for the [`emit_funds_refunded`] event.
///
/// Emitted after a successful refund via [`BountyEscrowContract::refund`],
/// `refund_resolved` (anonymous escrow path), `oracle_refund`, or
/// `auto_refund`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_ref"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - `refund_to` may differ from the original depositor when an admin
///   approval overrides the recipient (e.g. custom partial-refund target).
/// - For anonymous escrows the depositor identity is never revealed; only
///   the on-chain resolver-approved `recipient` is used.
/// - `trigger_type` identifies which refund path was taken so downstream
///   consumers can distinguish oracle-attested from time-based refunds.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsRefunded {
    pub version: u32,
    pub bounty_id: u64,
    pub amount: i128,
    pub refund_to: Address,
    pub timestamp: u64,
    /// Which code path triggered this refund.
    pub trigger_type: RefundTriggerType,
}

/// Emit [`FundsRefunded`].
pub fn emit_funds_refunded(env: &Env, event: FundsRefunded) {
    let topics = (symbol_short!("f_ref"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

// ── Oracle config event ───────────────────────────────────────────────────────

/// Payload for the [`emit_oracle_config_updated`] event.
///
/// Emitted when the admin configures or updates the oracle address via
/// [`BountyEscrowContract::set_oracle`].
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"orc_cfg"` |
///
/// ### Security notes
/// - Only the admin can call `set_oracle`; this event serves as an
///   on-chain audit trail of oracle configuration changes.
/// - When `enabled = false` the oracle address is stored but
///   `oracle_refund` calls will be rejected until re-enabled.
#[contracttype]
#[derive(Clone, Debug)]
pub struct OracleConfigUpdated {
    pub version: u32,
    pub oracle_address: Address,
    pub enabled: bool,
    pub admin: Address,
    pub timestamp: u64,
}

/// Emit [`OracleConfigUpdated`].
pub fn emit_oracle_config_updated(env: &Env, event: OracleConfigUpdated) {
    let topics = (symbol_short!("orc_cfg"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEE EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Discriminator for fee-collection operations.
///
/// Used in [`FeeCollected`] to distinguish lock-time fees from
/// release-time fees without requiring separate event types.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeOperationType {
    /// Fee collected at lock time (`lock_funds` / `batch_lock_funds`).
    Lock,
    /// Fee collected at release time (`release_funds` / `batch_release_funds`).
    Release,
}

/// Payload for the [`emit_fee_collected`] event.
///
/// Emitted whenever a non-zero fee is transferred to `recipient`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee"` |
///
/// ### Security notes
/// - Fee amounts use **ceiling division** (`⌈amount × rate / 10_000⌉`)
///   to prevent principal drain via dust-splitting.
/// - Both `amount` (actual fee transferred) and `fee_rate` (basis points)
///   are published so auditors can verify correctness off-chain.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeCollected {
    pub operation_type: FeeOperationType, // determines if the fee was collected on lock or release.
    pub amount: i128,                     // actual fee amount transferred
    pub fee_rate: i128,                   // fee rate applied in basis points (1 bp = 0.01 %).
    pub fee_fixed: i128,                  // flat fee component
    pub recipient: Address,
    pub timestamp: u64, // Ledger timestamp.
}

/// Emit [`FeeCollected`]
pub fn emit_fee_collected(env: &Env, event: FeeCollected) {
    let topics = (symbol_short!("fee"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_batch_funds_locked`] event.
///
/// Emitted once per successful [`BountyEscrowContract::batch_lock_funds`]
/// call, after all individual [`FundsLocked`] events.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"b_lock"` |
///
/// ### Security notes
/// - `count` and `total_amount` are derived from the ordered, validated
///   item list so they match the sum of the per-item `FundsLocked` events
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchFundsLocked {
    pub count: u32,         //  numbers of escrows created in this batch.
    pub total_amount: i128, // the sum of all locked amounts in this batch.
    pub timestamp: u64,
}

/// Emit [`BatchFundsLocked`]
pub fn emit_batch_funds_locked(env: &Env, event: BatchFundsLocked) {
    let topics = (symbol_short!("b_lock"),);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_fee_config_updated`] event.
///
/// Emitted when the global fee configuration is changed by the admin.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_cfg"` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeConfigUpdated {
    /// New lock fee rate in basis points.
    pub lock_fee_rate: i128,
    /// New release fee rate in basis points.
    pub release_fee_rate: i128,
    /// New lock fixed fee.
    pub lock_fixed_fee: i128,
    /// New release fixed fee.
    pub release_fixed_fee: i128,
    /// Address designated to receive fees.
    pub fee_recipient: Address,
    /// Whether fee collection is active after this update.
    pub fee_enabled: bool,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeConfigUpdated`]
pub fn emit_fee_config_updated(env: &Env, event: FeeConfigUpdated) {
    let topics = (symbol_short!("fee_cfg"),);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_fee_routing_updated`] event.
///
/// Emitted when a bounty-specific fee routing rule is set or changed.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_rte"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeRoutingUpdated {
    /// Bounty this routing config applies to.
    pub bounty_id: u64,
    /// Primary treasury recipient.
    pub treasury_recipient: Address,
    /// Treasury share in basis points.
    pub treasury_bps: i128,
    /// Optional partner/referral recipient.
    pub partner_recipient: Option<Address>,
    /// Partner share in basis points.
    pub partner_bps: i128,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeRoutingUpdated`]
pub fn emit_fee_routing_updated(env: &Env, event: FeeRoutingUpdated) {
    let topics = (symbol_short!("fee_rte"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_fee_routed`] event
///
/// Emitted when a split fee is distributed to multiple recipients.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_rt"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeRouted {
    /// Bounty this fee was collected for.
    pub bounty_id: u64,
    /// Whether this was a lock or release fee.
    pub operation_type: FeeOperationType,
    /// Original deposit amount before fee.
    pub gross_amount: i128,
    /// Total fee collected.
    pub total_fee: i128,
    /// Rate applied in basis points.
    pub fee_rate: i128,
    /// Treasury address.
    pub treasury_recipient: Address,
    /// Portion sent to treasury.
    pub treasury_fee: i128,
    /// Optional partner address.
    pub partner_recipient: Option<Address>,
    /// Portion sent to partner.
    pub partner_fee: i128,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeRouted`]
pub fn emit_fee_routed(env: &Env, event: FeeRouted) {
    let topics = (symbol_short!("fee_rt"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_batch_funds_released`] event.
///
/// Emitted once per successful [`BountyEscrowContract::batch_release_funds`]
/// call, after all individual [`FundsReleased`] events.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"b_rel"` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchFundsReleased {
    pub count: u32,
    pub total_amount: i128,
    pub timestamp: u64,
}

/// Emit [`BatchFundsReleased`]
pub fn emit_batch_funds_released(env: &Env, event: BatchFundsReleased) {
    let topics = (symbol_short!("b_rel"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// APPROVAL & CLAIM EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_approval_added`] event.
///
/// Emitted when a multisig signer approves a large-amount release.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"approval"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct ApprovalAdded {
    pub bounty_id: u64,       // requiring multisig approval.
    pub contributor: Address, // intended contributor recipient
    pub approver: Address,    // signer who submitted this approval
    pub timestamp: u64,
}

/// Emit [`ApprovalAdded`]
pub fn emit_approval_added(env: &Env, event: ApprovalAdded) {
    let topics = (symbol_short!("approval"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload emitted when a pending claim is created via `authorize_claim`.
///
/// ### Topics
/// `("claim", "created")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCreated {
    pub bounty_id: u64, // use program_id+schedule_id equivalent in program-escrow
    pub recipient: Address,
    pub amount: i128,
    pub expires_at: u64,
}

/// Payload emitted when a claim is successfully executed.
///
/// ### Topics
/// `("claim", "done")`/// Payload emitted when a claim is successfully executed.
///
/// ### Topics
/// `("claim", "done")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimExecuted {
    pub bounty_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub claimed_at: u64,
}

/// Payload emitted when an admin cancels a pending claim.
///
/// ### Topics
/// `("claim", "cancel")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCancelled {
    pub bounty_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub cancelled_at: u64,
    pub cancelled_by: Address,
}

/// Discriminator used in [`record_receipt`]-style internal bookkeeping.
///
/// Not emitted directly as a standalone event; embedded in receipt payloads.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CriticalOperationOutcome {
    /// Funds were successfully released to a contributor.
    Released,
    /// Funds were successfully refunded to the depositor.
    Refunded,
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC SELECTION EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_deterministic_selection`] event.
///
/// Emitted when a winner is chosen via
/// [`BountyEscrowContract::issue_claim_ticket_deterministic`].
/// Publishing the `seed_hash` and `winner_score` allows any observer to
/// reproduce and verify the selection off-chain.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"prng_sel"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - This is **deterministic pseudo-randomness**, not cryptographically
///   unpredictable.  Callers who co