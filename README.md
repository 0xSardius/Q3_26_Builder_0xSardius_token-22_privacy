# Remittance Stablecoin on Token-2022

Turbin3 Q3 2026, week 4. An Anchor program for issuing a remittance stablecoin with Token-2022 extensions: a protocol fee on every transfer, accounts frozen until KYC clears, on-chain metadata, a closable mint, and a re-issued version that adds seizure and confidential transfers.

Program: `programs/t22` · Program ID `6sC5C8VFoTpEZQVn3YK9EUSd5g3Cs6zTT3HCDBGQkyo4`

![All tests passing](docs/tests-passing.png)

## The two mints

**v1 — remittance mint** (`create_remittance_mint`)

| Extension | Why |
|---|---|
| `TransferFeeConfig` | Issuer revenue on every transfer |
| `MetadataPointer` → the mint itself | Wallets read metadata on-chain, no off-chain registry |
| `DefaultAccountState` = Frozen | New accounts can't move funds until KYC |
| `MintCloseAuthority` | The mint can be closed if decommissioned |

**v2 — re-issued mint** (`reissue_remittance_mint`) carries all four forward and adds:

| Extension | Why |
|---|---|
| `PermanentDelegate` | Seizure authority for sanctioned wallets |
| `ConfidentialTransferMint` (manual approve) | Hidden transfer amounts; each account needs issuer approval |
| `ConfidentialTransferFeeConfig` | Required by Token-2022 when transfer fees and confidential transfers are on the same mint |

Most mint extensions can only be set before `InitializeMint`. A v1 mint can never gain confidential transfers, so the v2 mint is a new mint rather than an upgrade. A test confirms this (`v1_mint_cannot_gain_confidential_transfers_after_initialize`).

## Tasks

### 1. Mint with four stacked extensions
`create_remittance_mint` sizes the account with `ExtensionType::try_calculate_account_len::<Mint>` over the exact extension list, creates it, runs every extension init, and only then calls `InitializeMint2`. A freeze authority is set, because a frozen-by-default mint without one could never thaw anything.

Tests (`tests/remittance.rs`): `remittance_mint_is_sized_from_try_calculate_account_len`, `remittance_mint_initializes_the_four_required_extensions`, `new_holder_accounts_on_the_remittance_mint_start_frozen`.

### 2. Transfer with the protocol fee
`transfer_with_protocol_fee` reads the mint's `TransferFeeConfig`, computes the fee with `calculate_epoch_fee(Clock::get()?.epoch, amount)`, and passes it to `transfer_checked_with_fee`. Token-2022 rejects the transfer if the fee doesn't match, so a stale cached rate can't slip through. The fee is withheld on the destination account. `quote_remittance_fee` exposes the same calculation for clients.

Tests: `quote_matches_calculate_epoch_fee_including_the_maximum_cap`, `quote_uses_the_live_epoch_rate_not_the_scheduled_newer_rate`, `remittance_transfer_withholds_the_live_epoch_fee`, `remittance_transfer_fails_while_the_source_is_frozen`.

### 3. State reads through `StateWithExtensions`
Every mint and account read in the program and tests goes through `StateWithExtensions::<T>::unpack` (helper: `unpack_mint`). Raw `Pack::unpack` fails on extended accounts because of the TLV data after the base struct.

Test: `remittance_state_requires_state_with_extensions`.

### 4. KYC unfreeze path
`thaw_after_kyc` runs `ThawAccount` on one token account, signed by the freeze authority. The mint's default state stays Frozen, so the next new account still starts frozen.

Tests: `thaw_after_kyc_unfreezes_one_account_without_changing_mint_default`, `thaw_after_kyc_rejects_a_non_freeze_authority`.

### 5. Re-issue with seizure and confidential transfers
`reissue_remittance_mint` builds the seven-extension mint above, with `auto_approve_new_accounts = false` (manual approve) and the fee authority's ElGamal public key for encrypted withheld fees.

Tests: `reissued_mint_carries_v1_extensions_plus_seizure_and_confidential`, `v1_mint_cannot_gain_confidential_transfers_after_initialize`.

### 6. Full confidential lifecycle
All on the v2 mint, in `tests/remittance_confidential.rs`:

| Step | How | Tests |
|---|---|---|
| Create account | Anyone can create and initialize a holder account | `anyone_can_create_the_account_only_the_owner_can_configure` |
| ConfigureAccount | `configure_confidential_account`, owner signature required; uses a pre-verified pubkey-validity proof context | same |
| Approve | `approve_confidential_account`, confidential authority (manual policy) | `manual_approve_is_required_after_configure` |
| Deposit | `deposit_confidential`, public balance → pending | `deposit_is_rejected_until_the_account_is_approved`, `deposit_moves_public_tokens_into_pending_confidential` |
| ApplyPendingBalance | `apply_pending_balance`, pending → available | `apply_pending_moves_inbox_to_available`, `apply_pending_does_not_verify_the_aes_ciphertext` |
| Confidential transfer | `TransferWithFee` with five staged proofs; the fee is withheld encrypted to the fee authority | `confidential_remittance_withholds_an_encrypted_fee_then_withdraws` |
| Withdraw | Apply pending first, then withdraw with equality + range proofs | same, plus `a_withdraw_proof_that_lies_about_the_balance_is_rejected` |

A few things the tests pin down:

- **Configure is not creation.** The payer can create the account for someone else, but only the owner can register encryption keys on it.
- **Manual approve is a second gate.** Even with KYC thaw done, a configured account can't deposit until the confidential authority approves it.
- **Apply before withdraw.** Incoming funds land in pending. A withdraw proof can't be built against pending funds (`NotEnoughFunds`); after apply it succeeds.
- **Apply trusts the client's AES ciphertext.** Token-2022 can't verify it, and the credit counter is a consistency hint rather than a check.
- **Proofs are bound to account state.** A mathematically valid proof against a different ciphertext is rejected with `Balance mismatch`.

Configure, approve, deposit and apply are program instructions (CPIs into Token-2022). Transfer and withdraw are sent by the client directly to Token-2022, since the wallet holds the keys needed to generate the proofs.

## Other test files

`tests/test_initialize.rs`, `tests/confidential.rs` and `tests/authority.rs` cover the study material this program grew out of: declarative vs. manual mint creation, extension allowlisting, the confidential lifecycle on a plain mint, permanent delegate, and CPI Guard basics. The optional CPI Guard delegated-transfer challenge was not attempted.

## Running the tests

Tests run in [LiteSVM](https://github.com/LiteSVM/litesvm) against the compiled program.

```bash
cargo-build-sbf --manifest-path programs/t22/Cargo.toml
cargo test --manifest-path programs/t22/Cargo.toml
```

The tests load `target/deploy/t22.so`. If `CARGO_TARGET_DIR` points elsewhere, copy the built `.so` there first:

```bash
mkdir -p target/deploy && cp "$CARGO_TARGET_DIR/deploy/t22.so" target/deploy/t22.so
```
