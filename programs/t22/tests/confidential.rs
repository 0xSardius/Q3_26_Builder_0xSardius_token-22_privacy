//! Stage 1 of the confidential lifecycle: mint, account, configure.

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use proofext::instruction::ProofLocation;
use proofgen::{transfer::transfer_split_proof_data, transfer_with_fee::transfer_with_fee_split_proof_data ,withdraw::withdraw_proof_data};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use std::num::NonZeroI8;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        confidential_transfer::{instruction as ct_ix, ConfidentialTransferAccount},
        confidential_transfer_fee::{instruction::{disable_harvest_to_mint, enable_harvest_to_mint},ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, Mint as MintState}
};
use zk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use zkif::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::ZkProofData,
    state::ProofContextState,
};

const ZK_PROGRAM_ID: Pubkey = zkif::ID;

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 2;
const FEE_BASIS_POINTS: u16 = 250;
const MAXIMUM_FEE: u64 = 5_000;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    svm.add_program_from_file(ID, path).unwrap();
    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    if let Err(e) = svm.send_transaction(tx) {
        panic!("tx failed: {:#?}", e.meta.logs);
    }
}

#[test]
fn stage1_configure_account() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateConfidentialMint {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateConfidentialMint {
            decimals: DECIMALS,
            auto_approve_new_accounts: true,
        }
        .data(),
    };
    send(&mut svm, &payer, &[ix], &[&mint]);
    println!(
        "mint len = {}",
        svm.get_account(&mint.pubkey()).unwrap().data.len()
    );

    let ta = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .unwrap();
    println!("token account len = {space}");
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(
                &TOKEN_2022_PROGRAM_ID,
                &ta.pubkey(),
                &mint.pubkey(),
                &payer.pubkey(),
            )
            .unwrap(),
        ],
        &[&ta],
    );

    let (elgamal, aes) = derive_confidential_keys(&payer, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();

    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta.pubkey(),
        &mint.pubkey(),
        &aes.encrypt(0).into(),
        65536,
        &payer.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[]);

    let acct = svm.get_account(&ta.pubkey()).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    println!("extensions = {:?}", state.get_extension_types().unwrap());
    let ct = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    println!("approved = {}", bool::from(ct.approved));
}

// ---------------------------------------------------------------------------
// Helpers shared by the later stages.
// ---------------------------------------------------------------------------

struct Holder {
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn create_and_configure(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Keypair,
) -> Holder {
    let ta = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, &owner.pubkey())
                .unwrap(),
        ],
        &[&ta],
    );

    // Both keys come from one signature over a fixed derivation message, via
    // HKDF-SHA512. Three things worth saying out loud:
    //
    //   - The owner can always recover them from their wallet. Nothing is
    //     stored, and losing them means losing the ability to read the balance.
    //   - Whatever can produce that signature can decrypt every confidential
    //     balance the wallet holds.
    //   - The empty seed is the standard, wallet level derivation. It is
    //     byte identical to what the spl-token CLI and the JavaScript client
    //     derive, so those tools can read accounts configured here. A non
    //     empty seed scopes keys more finely but breaks that interoperability.
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta.pubkey(),
        mint,
        &aes.encrypt(0).into(),
        65536,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(svm, payer, &ixs, &[owner]);

    Holder {
        account: ta.pubkey(),
        elgamal,
        aes,
    }
}

/// Read the confidential extension off a token account.
fn read_ct(svm: &LiteSVM, account: &Pubkey) -> ConfidentialTransferAccount {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    *state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

/// Decrypt the available balance. Only the owner can do this, which is the
/// whole point of the extension.
fn available_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let ciphertext: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    elgamal.secret().decrypt_u32(&ciphertext).unwrap()
}

/// Decrypt the pending balance, which is stored as a low and a high component
/// because ElGamal decryption is a discrete log search and has to stay cheap.
fn pending_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    let lo = elgamal.secret().decrypt_u32(&lo).unwrap();
    let hi = elgamal.secret().decrypt_u32(&hi).unwrap();
    lo + (hi << 16)
}

/// Move pending into available.
///
/// The program cannot compute the new decryptable balance, because it has no
/// access to the owner's AES key. The client decrypts, adds, re-encrypts, and
/// hands the ciphertext in as an instruction argument.
fn apply_pending(svm: &mut LiteSVM, payer: &Keypair, holder: &Holder, owner: &Keypair) {
    let ct = read_ct(svm, &holder.account);
    let counter: u64 = ct.pending_balance_credit_counter.into();
    let new_available =
        available_balance(&ct, &holder.elgamal) + pending_balance(&ct, &holder.elgamal);
    let ciphertext: [u8; 36] = holder.aes.encrypt(new_available).to_bytes();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::ApplyPendingBalance {
            token_account: holder.account,
            authority: owner.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: ciphertext,
        }
        .data(),
    };
    send(svm, payer, &[ix], &[owner]);
}

/// Verify a proof into its own context state account, so the token instruction
/// can reference it instead of carrying it inline. A confidential transfer's
/// three proofs do not fit in one 1232 byte transaction, which is why the
/// lifecycle needs several dependent transactions.
fn stage_proof<T, U>(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction_kind: ProofInstruction,
    proof: &T,
) -> Pubkey
where
    T: bytemuck::Pod + ZkProofData<U>,
    U: bytemuck::Pod,
{
    // Size comes from the proof's own context type rather than a magic
    // number: authority, proof type tag, then the context data itself.
    let context_len = std::mem::size_of::<ProofContextState<U>>();
    let context = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(context_len);
    send(
        svm,
        payer,
        &[solana_system_interface::instruction::create_account(
            &payer.pubkey(),
            &context.pubkey(),
            lamports,
            context_len as u64,
            &ZK_PROGRAM_ID,
        )],
        &[&context],
    );
    let ix = instruction_kind.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &context.pubkey(),
            context_state_authority: &payer.pubkey(),
        }),
        proof,
    );
    send(svm, 
        payer, 
        &[
        ComputeBudgetInstruction::set_compute_unit_limit(400_000),
        ix
        ], &[]);
    context.pubkey()
    
}

/// Close proof context accounts and return their rent to the payer.
///
/// Each context account holds real lamports. Leaving them open leaks rent on
/// every confidential transfer, which adds up fast for an active account.
/// Closing is part of the flow, not an optimization.
fn close_contexts(svm: &mut LiteSVM, payer: &Keypair, contexts: &[Pubkey]) -> u64 {
    let before = svm.get_balance(&payer.pubkey()).unwrap();
    let ixs: Vec<Instruction> = contexts
        .iter()
        .map(|c| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: c,
                    context_state_authority: &payer.pubkey(),
                },
                &payer.pubkey(),
            )
        })
        .collect();
    send(svm, payer, &ixs, &[]);
    for c in contexts {
        assert!(svm
            .get_account(c)
            .map(|a| a.data.is_empty())
            .unwrap_or(true));
    }
    svm.get_balance(&payer.pubkey())
        .unwrap()
        .saturating_sub(before)
}

#[test]
fn full_confidential_lifecycle() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // ---- create the confidential mint, via the Anchor program -------------
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateConfidentialMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateConfidentialMint {
                decimals: DECIMALS,
                auto_approve_new_accounts: true,
            }
            .data(),
        }],
        &[&mint],
    );

    // ---- two configured holders -------------------------------------------
    let alice_owner = payer.insecure_clone();
    let bob_owner = Keypair::new();
    svm.airdrop(&bob_owner.pubkey(), 10_000_000_000).unwrap();

    let alice = create_and_configure(&mut svm, &payer, &mint.pubkey(), &alice_owner);
    let bob = create_and_configure(&mut svm, &payer, &mint.pubkey(), &bob_owner);

    // ---- mint public tokens to alice, then deposit them confidentially ----
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice.account,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice.account,
                mint: mint.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 10_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    let ct = read_ct(&svm, &alice.account);
    println!(
        "after deposit: pending={} available={}",
        pending_balance(&ct, &alice.elgamal),
        available_balance(&ct, &alice.elgamal)
    );

    // ---- apply pending balance --------------------------------------------
    apply_pending(&mut svm, &payer, &alice, &alice_owner);
    let ct = read_ct(&svm, &alice.account);
    let alice_available = available_balance(&ct, &alice.elgamal);
    println!(
        "after apply: pending={} available={}",
        pending_balance(&ct, &alice.elgamal),
        alice_available
    );
    assert_eq!(alice_available, 10_000);

    // ---- confidential transfer to bob -------------------------------------
    let transfer_amount = 2_500u64;
    let ct = read_ct(&svm, &alice.account);
    let current_available: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    let current_decryptable: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    let bob_ct = read_ct(&svm, &bob.account);
    let bob_pubkey: ElGamalPubkey = bob_ct.elgamal_pubkey.try_into().unwrap();

    let proofs = transfer_split_proof_data(
        &current_available,
        &current_decryptable,
        transfer_amount,
        &alice.elgamal,
        &alice.aes,
        &bob_pubkey,
        None,
    )
    .unwrap();

    let eq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let val_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let range_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU128,
        &proofs.range_proof_data,
    );

    let new_alice_decryptable = alice.aes.encrypt(alice_available - transfer_amount);
    let ixs = ct_ix::transfer(
        &TOKEN_2022_PROGRAM_ID,
        &alice.account,
        &mint.pubkey(),
        &bob.account,
        &new_alice_decryptable.into(),
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &alice_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[&alice_owner]);

    let recovered = close_contexts(&mut svm, &payer, &[eq_ctx, val_ctx, range_ctx]);
    println!("rent recovered from transfer proofs = {recovered} lamports");

    // Bob's incoming amount lands in pending, not available.
    let bob_ct = read_ct(&svm, &bob.account);
    println!(
        "bob after transfer: pending={} available={}",
        pending_balance(&bob_ct, &bob.elgamal),
        available_balance(&bob_ct, &bob.elgamal)
    );
    assert_eq!(pending_balance(&bob_ct, &bob.elgamal), transfer_amount);
    assert_eq!(available_balance(&bob_ct, &bob.elgamal), 0);

    apply_pending(&mut svm, &payer, &bob, &bob_owner);
    let bob_ct = read_ct(&svm, &bob.account);
    assert_eq!(available_balance(&bob_ct, &bob.elgamal), transfer_amount);
    println!("bob after apply: available={}", transfer_amount);

    // ---- withdraw back to the public balance ------------------------------
    let withdraw_amount = 1_000u64;
    let bob_ct = read_ct(&svm, &bob.account);
    let bob_available = available_balance(&bob_ct, &bob.elgamal);
    let bob_current: ElGamalCiphertext = bob_ct.available_balance.try_into().unwrap();

    let wproofs =
        withdraw_proof_data(&bob_current, bob_available, withdraw_amount, &bob.elgamal).unwrap();

    let weq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &wproofs.equality_proof_data,
    );
    let wrange_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &wproofs.range_proof_data,
    );

    let new_bob_decryptable = bob.aes.encrypt(bob_available - withdraw_amount);
    let ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &bob.account,
        &mint.pubkey(),
        withdraw_amount,
        DECIMALS,
        &new_bob_decryptable.into(),
        &bob_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&weq_ctx),
        ProofLocation::ContextStateAccount(&wrange_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[&bob_owner]);

    let recovered = close_contexts(&mut svm, &payer, &[weq_ctx, wrange_ctx]);
    println!("rent recovered from withdraw proofs = {recovered} lamports");

    let acct = svm.get_account(&bob.account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    println!("bob public balance = {}", state.base.amount);
    assert_eq!(state.base.amount, withdraw_amount);

    let bob_ct = read_ct(&svm, &bob.account);
    assert_eq!(
        available_balance(&bob_ct, &bob.elgamal),
        transfer_amount - withdraw_amount
    );
    println!(
        "bob confidential available = {}",
        transfer_amount - withdraw_amount
    );
}




// this test proves the program doesn't just accept anything ( Flips a single bit inside the proof of an otherwise valid
/// PubkeyValidity proof and confirms the ZK ElGamal Proof program rejects it.).
#[test]
fn a_tampered_proof_is_rejected() {
    let (mut svm, payer) = setup();
    let (elgamal, _aes) = derive_confidential_keys(&payer, b"").unwrap();
 
    let good = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let mut tampered = good;
 
    // The struct is Pod, so it can be viewed as raw bytes. The context sits
    // first and the proof after it; flipping a bit in the tail corrupts the
    // proof while leaving the claimed public key intact.
    let bytes = bytemuck::bytes_of_mut(&mut tampered);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
 
    let ok_ix = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, &good);
    let bad_ix = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, &tampered);
 
    // The untouched proof verifies.
    send(&mut svm, &payer, &[ok_ix], &[]);
 
    // One flipped bit does not.
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(&[bad_ix], Some(&payer.pubkey())));
    tx.try_sign(&[&payer], bh).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => panic!("a tampered proof was accepted"),
        Err(e) => {
            let logs = e.meta.logs.join("\n");
            println!("tampered proof rejected:\n{logs}");
            assert!(logs.contains("proof verification failed"));
        }
    }
}
 
#[test]
fn confidential_transfer_fee_mint_stacks_three_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
 
    // The fee is withheld as an ElGamal ciphertext, so the withdraw withheld
    // authority needs a key pair, not just an address. Only the holder of this
    // key can total the fees the mint has collected.
    let (fee_authority_elgamal, _) = derive_confidential_keys(&payer, b"").unwrap();
    let fee_authority_pubkey: [u8; 32] = fee_authority_elgamal.pubkey().into();
 
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateConfidentialFeeMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateConfidentialFeeMint {
                decimals: DECIMALS,
                basis_points: 250,
                maximum_fee: 5_000,
                withdraw_withheld_authority_elgamal_pubkey: fee_authority_pubkey,
            }
            .data(),
        }],
        &[&mint],
    );
 
    let acct = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let extensions = state.get_extension_types().unwrap();
    println!("confidential fee mint len = {}", acct.data.len());
    println!("extensions = {extensions:?}");
 
    assert!(extensions.contains(&ExtensionType::TransferFeeConfig));
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferMint));
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferFeeConfig));
    assert_eq!(acct.data.len(), 480);
 
    // All three pieces of mint side state the extension defines.
    let fee_config = state
        .get_extension::<ConfidentialTransferFeeConfig>()
        .unwrap();
 
    // 1. The authority is an ElGamal public key, not an address. Whoever holds
    //    the matching secret key can decrypt every withheld fee on this mint.
    assert_eq!(
        fee_config.withdraw_withheld_authority_elgamal_pubkey.0,
        fee_authority_pubkey
    );
 
    // 2. The harvest flag, which the mint authority controls.
    println!(
        "harvest_to_mint_enabled = {}",
        bool::from(fee_config.harvest_to_mint_enabled)
    );
 
    // 3. The running total of fees harvested to the mint, itself a ciphertext.
    //    It starts at zero, and only the fee authority's key can read it.
    let harvested: ElGamalCiphertext = fee_config.withheld_amount.try_into().unwrap();
    let harvested = fee_authority_elgamal
        .secret()
        .decrypt_u32(&harvested)
        .unwrap();
    println!("harvested so far = {harvested}");
    assert_eq!(harvested, 0);
}
 
/// Build a fee bearing confidential mint and return it with the fee
/// authority's ElGamal keypair, which is the only key that can read withheld
/// fee amounts.
fn create_fee_mint(svm: &mut LiteSVM, payer: &Keypair) -> (Keypair, ElGamalKeypair) {
    let mint = Keypair::new();
    let (fee_authority_elgamal, _) = derive_confidential_keys(payer, b"").unwrap();
    let pubkey: [u8; 32] = fee_authority_elgamal.pubkey().into();
 
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateConfidentialFeeMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateConfidentialFeeMint {
                decimals: DECIMALS,
                basis_points: 250,
                maximum_fee: 5_000,
                withdraw_withheld_authority_elgamal_pubkey: pubkey,
            }
            .data(),
        }],
        &[&mint],
    );
    (mint, fee_authority_elgamal)
}
 
fn harvest_enabled(svm: &LiteSVM, mint: &Pubkey) -> bool {
    let acct = svm.get_account(mint).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    bool::from(
        state
            .get_extension::<ConfidentialTransferFeeConfig>()
            .unwrap()
            .harvest_to_mint_enabled,
    )
}
 
#[test]
fn the_mint_authority_controls_whether_accounts_may_harvest() {
    let (mut svm, payer) = setup();
    let (mint, _) = create_fee_mint(&mut svm, &payer);
 
    // Harvesting is permissionless by default, so anyone can push an account's
    // withheld fees to the mint. The mint authority can switch that off.
    assert!(harvest_enabled(&svm, &mint.pubkey()));
 
    send(
        &mut svm,
        &payer,
        &[
            disable_harvest_to_mint(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &payer.pubkey(), &[])
                .unwrap(),
        ],
        &[],
    );
    assert!(!harvest_enabled(&svm, &mint.pubkey()));
 
    send(
        &mut svm,
        &payer,
        &[
            enable_harvest_to_mint(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &payer.pubkey(), &[])
                .unwrap(),
        ],
        &[],
    );
    assert!(harvest_enabled(&svm, &mint.pubkey()));
}
 
#[test]
fn a_holder_on_a_fee_mint_carries_its_own_withheld_balance() {
    let (mut svm, payer) = setup();
    let (mint, fee_authority_elgamal) = create_fee_mint(&mut svm, &payer);
 
    // Size for all three account side extensions up front. Only
    // TransferFeeAmount is required at InitializeAccount3; the two
    // confidential ones are written by ConfigureAccount, so the space has to
    // be there before it runs.
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::ConfidentialTransferFeeAmount,
    ])
    .unwrap();
    assert_eq!(space, 545);
 
    let ta = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(
                &TOKEN_2022_PROGRAM_ID,
                &ta.pubkey(),
                &mint.pubkey(),
                &payer.pubkey(),
            )
            .unwrap(),
        ],
        &[&ta],
    );
 
    let (elgamal, aes) = derive_confidential_keys(&payer, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta.pubkey(),
        &mint.pubkey(),
        &aes.encrypt(0).into(),
        65536,
        &payer.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[]);
 
    let acct = svm.get_account(&ta.pubkey()).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let extensions = state.get_extension_types().unwrap();
    println!("holder extensions = {extensions:?}");
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferFeeAmount));
 
    // The per account withheld balance. It is encrypted under the fee
    // authority's key, not the holder's, so the holder cannot read what has
    // been withheld from them.
    let fee_amount = state
        .get_extension::<ConfidentialTransferFeeAmount>()
        .unwrap();
    let withheld: ElGamalCiphertext = fee_amount.withheld_amount.try_into().unwrap();
    let withheld = fee_authority_elgamal
        .secret()
        .decrypt_u32(&withheld)
        .unwrap();
    println!("withheld on this account = {withheld}");
    assert_eq!(withheld, 0);
}



/// Create a fee bearing confidential holder: a token account sized for all
/// three account extensions, initialized, and configured.
fn configure_fee_holder(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Keypair,
) -> Holder {
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::ConfidentialTransferFeeAmount,
    ])
    .unwrap();
    let ta = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, &owner.pubkey())
                .unwrap(),
        ],
        &[&ta],
    );
 
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta.pubkey(),
        mint,
        &aes.encrypt(0).into(),
        65536,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(svm, payer, &ixs, &[owner]);
 
    Holder {
        account: ta.pubkey(),
        elgamal,
        aes,
    }
}
 
/// Read the withheld fee sitting on a token account. Encrypted under the fee
/// authority's key, so only that key can read it, not the holder's.
fn withheld_on_account(svm: &LiteSVM, account: &Pubkey, fee_authority: &ElGamalKeypair) -> u64 {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let ext = state
        .get_extension::<ConfidentialTransferFeeAmount>()
        .unwrap();
    let ciphertext: ElGamalCiphertext = ext.withheld_amount.try_into().unwrap();
    fee_authority.secret().decrypt_u32(&ciphertext).unwrap()
}
 
#[test]
fn a_confidential_transfer_with_fee_withholds_an_encrypted_fee() {
    let (mut svm, payer) = setup();
    let (mint, fee_authority) = create_fee_mint(&mut svm, &payer);
 
    let alice_owner = payer.insecure_clone();
    let bob_owner = Keypair::new();
    svm.airdrop(&bob_owner.pubkey(), 10_000_000_000).unwrap();
 
    let alice = configure_fee_holder(&mut svm, &payer, &mint.pubkey(), &alice_owner);
    let bob = configure_fee_holder(&mut svm, &payer, &mint.pubkey(), &bob_owner);
 
    // Fund alice and move it into her confidential available balance.
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice.account,
            &payer.pubkey(),
            &[],
            100_000,
        )
        .unwrap()],
        &[],
    );
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice.account,
                mint: mint.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 100_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );
    apply_pending(&mut svm, &payer, &alice, &alice_owner);
 
    let alice_available = available_balance(&read_ct(&svm, &alice.account), &alice.elgamal);
    assert_eq!(alice_available, 100_000);
    assert_eq!(withheld_on_account(&svm, &bob.account, &fee_authority), 0);
 
    // ---- the fee bearing transfer ----------------------------------------
    let transfer_amount = 10_000u64;
    let ct = read_ct(&svm, &alice.account);
    let current_available: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    let current_decryptable: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    let bob_pubkey: ElGamalPubkey = read_ct(&svm, &bob.account)
        .elgamal_pubkey
        .try_into()
        .unwrap();
 
    // Five proofs now. The two extra ones exist because the fee is
    // a percentage of an amount nobody can see:
    //
    //   percentage_with_cap  proves the fee was computed correctly from the
    //                        hidden transfer amount, at the mint's rate and
    //                        capped at the mint's maximum
    //   fee_ciphertext_validity
    //                        proves the withheld fee ciphertext is well formed
    //                        under both the destination and the fee authority
    //                        keys
    //
    // The range proof also widens from U128 to U256, because there are more
    // committed values to bound.
    let proofs = transfer_with_fee_split_proof_data(
        &current_available,
        &current_decryptable,
        transfer_amount,
        &alice.elgamal,
        &alice.aes,
        &bob_pubkey,
        None,
        fee_authority.pubkey(),
        FEE_BASIS_POINTS,
        MAXIMUM_FEE,
    )
    .unwrap();
 
    let eq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let val_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let pct_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyPercentageWithCap,
        &proofs.percentage_with_cap_proof_data,
    );
    let fee_val_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
        &proofs.fee_ciphertext_validity_proof_data,
    );
    let range_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU256,
        &proofs.range_proof_data,
    );
 
    let new_alice_decryptable = alice.aes.encrypt(alice_available - transfer_amount);
    let ixs = ct_ix::transfer_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        &alice.account,
        &mint.pubkey(),
        &bob.account,
        &new_alice_decryptable.into(),
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &alice_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&pct_ctx),
        ProofLocation::ContextStateAccount(&fee_val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[&alice_owner]);
 
    close_contexts(
        &mut svm,
        &payer,
        &[eq_ctx, val_ctx, pct_ctx, fee_val_ctx, range_ctx],
    );
 
    // ---- what the fee did -------------------------------------------------
    let expected_fee = transfer_amount * u64::from(FEE_BASIS_POINTS) / 10_000;
 
    // The fee is withheld on the recipient's account, not deducted from the
    // sender. Alice is debited the full amount.
    let alice_after = available_balance(&read_ct(&svm, &alice.account), &alice.elgamal);
    assert_eq!(alice_after, alice_available - transfer_amount);
 
    // Bob receives the amount minus the fee, still in pending.
    let bob_pending = pending_balance(&read_ct(&svm, &bob.account), &bob.elgamal);
    println!("transfer={transfer_amount} fee={expected_fee} bob_pending={bob_pending}");
    assert_eq!(bob_pending, transfer_amount - expected_fee);
 
    // And the fee sits on bob's account, readable only by the fee authority.
    let withheld = withheld_on_account(&svm, &bob.account, &fee_authority);
    println!("withheld on bob's account = {withheld}");
    assert_eq!(withheld, expected_fee);
 
    // Bob cannot read it. The ciphertext is under the fee authority's key.
    let acct = svm.get_account(&bob.account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let raw: ElGamalCiphertext = state
        .get_extension::<ConfidentialTransferFeeAmount>()
        .unwrap()
        .withheld_amount
        .try_into()
        .unwrap();
    assert_ne!(bob.elgamal.secret().decrypt_u32(&raw), Some(expected_fee));
}
 