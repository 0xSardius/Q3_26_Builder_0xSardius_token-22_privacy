use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use bytemuck;
use litesvm::LiteSVM;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, AE_CIPHERTEXT_LEN, ID};
use proofext::instruction::ProofLocation;
use proofgen::{transfer_with_fee::transfer_with_fee_split_proof_data, withdraw::withdraw_proof_data};
use t22new::{
    extension::{
        confidential_transfer::{instruction as ct_ix, ConfidentialTransferAccount},
        confidential_transfer_fee::ConfidentialTransferFeeAmount,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::Account as TokenAccountState,
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
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 250;
const MAXIMUM_FEE: u64 = 1_000;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    assert!(path.exists(), "run cargo-build-sbf first");
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

fn send_expecting_failure(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
    extra: &[&Keypair],
) -> String {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => panic!("expected failure, got success"),
        Err(e) => e.meta.logs.join("\n"),
    }
}

fn create_v2_mint(svm: &mut LiteSVM, payer: &Keypair) -> Keypair {
    create_v2_mint_with_fee_authority(svm, payer).0
}

fn create_v2_mint_with_fee_authority(
    svm: &mut LiteSVM,
    payer: &Keypair,
) -> (Keypair, ElGamalKeypair) {
    let mint = Keypair::new();
    let fee_authority = ElGamalKeypair::new_rand();
    let fee_authority_pubkey: [u8; 32] = fee_authority.pubkey().into();
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ReissueRemittanceMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::ReissueRemittanceMint {
                decimals: DECIMALS,
                basis_points: BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
                withdraw_withheld_authority_elgamal_pubkey: fee_authority_pubkey,
            }
            .data(),
        }],
        &[&mint],
    );
    (mint, fee_authority)
}

fn create_holder_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
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
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, owner).unwrap(),
        ],
        &[&ta],
    );
    ta.pubkey()
}

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
    send(
        svm,
        payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(400_000),
            instruction_kind.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: &context.pubkey(),
                    context_state_authority: &payer.pubkey(),
                }),
                proof,
            ),
        ],
        &[],
    );
    context.pubkey()
}

fn stage_pubkey_proof(
    svm: &mut LiteSVM,
    payer: &Keypair,
    owner: &Keypair,
) -> (ElGamalKeypair, AeKey, [u8; AE_CIPHERTEXT_LEN], Pubkey) {
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyPubkeyValidity,
        &proof,
    );
    let zero_balance = aes.encrypt(0).to_bytes();
    (elgamal, aes, zero_balance, ctx)
}

fn thaw_ix(token_account: &Pubkey, mint: &Pubkey, freeze_authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::ThawAfterKyc {
            token_account: *token_account,
            mint: *mint,
            freeze_authority: *freeze_authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ThawAfterKyc {}.data(),
    }
}

fn deposit_ix(
    token_account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::DepositConfidential {
            token_account: *token_account,
            mint: *mint,
            authority: *authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::DepositConfidential {
            amount,
            decimals: DECIMALS,
        }
        .data(),
    }
}

fn public_amount(svm: &LiteSVM, account: &Pubkey) -> u64 {
    let acct = svm.get_account(account).unwrap();
    StateWithExtensions::<TokenAccountState>::unpack(&acct.data)
        .unwrap()
        .base
        .amount
}

fn available_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let ciphertext: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    elgamal.secret().decrypt_u32(&ciphertext).unwrap()
}

fn pending_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    let lo = elgamal.secret().decrypt_u32(&lo).unwrap();
    let hi = elgamal.secret().decrypt_u32(&hi).unwrap();
    lo + (hi << 16)
}

fn read_ct(svm: &LiteSVM, account: &Pubkey) -> ConfidentialTransferAccount {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    *state.get_extension::<ConfidentialTransferAccount>().unwrap()
}

fn configure_ix(
    token_account: &Pubkey,
    mint: &Pubkey,
    proof_context: &Pubkey,
    owner: &Pubkey,
    decryptable_zero_balance: [u8; AE_CIPHERTEXT_LEN],
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::ConfigureConfidentialAccount {
            token_account: *token_account,
            mint: *mint,
            proof_context: *proof_context,
            owner: *owner,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ConfigureConfidentialAccount {
            decryptable_zero_balance,
            maximum_pending_balance_credit_counter: 65536,
        }
        .data(),
    }
}

fn apply_ix(
    token_account: &Pubkey,
    authority: &Pubkey,
    expected_pending_balance_credit_counter: u64,
    new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::ApplyPendingBalance {
            token_account: *token_account,
            authority: *authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter,
            new_decryptable_available_balance,
        }
        .data(),
    }
}

fn approve_ix(token_account: &Pubkey, mint: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::ApproveConfidentialAccount {
            token_account: *token_account,
            mint: *mint,
            confidential_authority: *authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ApproveConfidentialAccount {}.data(),
    }
}

fn ct_approved(svm: &LiteSVM, account: &Pubkey) -> bool {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    bool::from(
        state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap()
            .approved,
    )
}

#[test]
fn anyone_can_create_the_account_only_the_owner_can_configure() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer);

    let owner = Keypair::new();
    svm.airdrop(&owner.pubkey(), 10_000_000_000).unwrap();

    let account = create_holder_account(&mut svm, &payer, &mint.pubkey(), &owner.pubkey());
    let (_elgamal, _aes, zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &payer.pubkey(),
            zero_balance,
        )],
        &[],
    );
    assert!(
        logs.contains("owner") || logs.contains("authority") || logs.contains("0x4"),
        "stranger configure rejected for the wrong reason:\n{logs}"
    );

    send(
        &mut svm,
        &payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &owner.pubkey(),
            zero_balance,
        )],
        &[&owner],
    );

    assert!(!ct_approved(&svm, &account));
}

#[test]
fn manual_approve_is_required_after_configure() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer);
    let owner = payer.insecure_clone();
    let account = create_holder_account(&mut svm, &payer, &mint.pubkey(), &owner.pubkey());
    let (_elgamal, _aes, zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

    send(
        &mut svm,
        &payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &owner.pubkey(),
            zero_balance,
        )],
        &[],
    );
    assert!(!ct_approved(&svm, &account));

    send(
        &mut svm,
        &payer,
        &[approve_ix(&account, &mint.pubkey(), &payer.pubkey())],
        &[],
    );
    assert!(ct_approved(&svm, &account));
}

fn fund_public(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    account: &Pubkey,
    amount: u64,
) {
    send(
        svm,
        payer,
        &[
            thaw_ix(account, mint, &payer.pubkey()),
            mint_to(
                &TOKEN_2022_PROGRAM_ID,
                mint,
                account,
                &payer.pubkey(),
                &[],
                amount,
            )
            .unwrap(),
        ],
        &[],
    );
}

#[test]
fn deposit_is_rejected_until_the_account_is_approved() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer);
    let owner = payer.insecure_clone();
    let account = create_holder_account(&mut svm, &payer, &mint.pubkey(), &owner.pubkey());
    let (_elgamal, _aes, zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

    send(
        &mut svm,
        &payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &owner.pubkey(),
            zero_balance,
        )],
        &[],
    );
    fund_public(&mut svm, &payer, &mint.pubkey(), &account, 10_000);

    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[deposit_ix(&account, &mint.pubkey(), &owner.pubkey(), 10_000)],
        &[],
    );
    assert!(
        logs.contains("approved") || logs.contains("0x13") || logs.contains("custom program error"),
        "unapproved deposit rejected for the wrong reason:\n{logs}"
    );
    assert_eq!(public_amount(&svm, &account), 10_000);
}

#[test]
fn deposit_moves_public_tokens_into_pending_confidential() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer);
    let owner = payer.insecure_clone();
    let account = create_holder_account(&mut svm, &payer, &mint.pubkey(), &owner.pubkey());
    let (elgamal, _aes, zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

    send(
        &mut svm,
        &payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &owner.pubkey(),
            zero_balance,
        )],
        &[],
    );
    send(
        &mut svm,
        &payer,
        &[approve_ix(&account, &mint.pubkey(), &payer.pubkey())],
        &[],
    );
    fund_public(&mut svm, &payer, &mint.pubkey(), &account, 10_000);
    assert_eq!(public_amount(&svm, &account), 10_000);

    send(
        &mut svm,
        &payer,
        &[deposit_ix(&account, &mint.pubkey(), &owner.pubkey(), 10_000)],
        &[],
    );

    let ct = read_ct(&svm, &account);
    assert_eq!(public_amount(&svm, &account), 0);
    assert_eq!(pending_balance(&ct, &elgamal), 10_000);
    assert_eq!(u64::from(ct.pending_balance_credit_counter), 1);
}

fn deposited(
    svm: &mut LiteSVM,
    payer: &Keypair,
    amount: u64,
) -> (Pubkey, Pubkey, ElGamalKeypair, AeKey) {
    let mint = create_v2_mint(svm, payer);
    let owner = payer.insecure_clone();
    let account = create_holder_account(svm, payer, &mint.pubkey(), &owner.pubkey());
    let (elgamal, aes, zero_balance, proof_ctx) = stage_pubkey_proof(svm, payer, &owner);

    send(
        svm,
        payer,
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof_ctx,
            &owner.pubkey(),
            zero_balance,
        )],
        &[],
    );
    send(
        svm,
        payer,
        &[approve_ix(&account, &mint.pubkey(), &payer.pubkey())],
        &[],
    );
    fund_public(svm, payer, &mint.pubkey(), &account, amount);
    send(
        svm,
        payer,
        &[deposit_ix(&account, &mint.pubkey(), &owner.pubkey(), amount)],
        &[],
    );
    (mint.pubkey(), account, elgamal, aes)
}

#[test]
fn apply_pending_does_not_verify_the_aes_ciphertext() {
    let (mut svm, payer) = setup();
    let (_mint, account, elgamal, aes) = deposited(&mut svm, &payer, 10_000);

    send(
        &mut svm,
        &payer,
        &[apply_ix(
            &account,
            &payer.pubkey(),
            0,
            aes.encrypt(0).to_bytes(),
        )],
        &[],
    );

    let ct = read_ct(&svm, &account);
    assert_eq!(pending_balance(&ct, &elgamal), 0);
    assert_eq!(available_balance(&ct, &elgamal), 10_000);

    let decryptable: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    assert_eq!(aes.decrypt(&decryptable).unwrap(), 0);
    assert_eq!(u64::from(ct.expected_pending_balance_credit_counter), 0);
    assert_eq!(u64::from(ct.actual_pending_balance_credit_counter), 1);
}

#[test]
fn apply_pending_moves_inbox_to_available() {
    let (mut svm, payer) = setup();
    let (_mint, account, elgamal, aes) = deposited(&mut svm, &payer, 10_000);
    let ct = read_ct(&svm, &account);
    let counter: u64 = ct.pending_balance_credit_counter.into();
    let new_available = available_balance(&ct, &elgamal) + pending_balance(&ct, &elgamal);

    send(
        &mut svm,
        &payer,
        &[apply_ix(
            &account,
            &payer.pubkey(),
            counter,
            aes.encrypt(new_available).to_bytes(),
        )],
        &[],
    );

    let ct = read_ct(&svm, &account);
    assert_eq!(pending_balance(&ct, &elgamal), 0);
    assert_eq!(available_balance(&ct, &elgamal), 10_000);
}

struct Holder {
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn onboard(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, owner: &Keypair) -> Holder {
    let account = create_holder_account(svm, payer, mint, &owner.pubkey());
    let (elgamal, aes, zero_balance, proof_ctx) = stage_pubkey_proof(svm, payer, owner);
    send(
        svm,
        payer,
        &[configure_ix(&account, mint, &proof_ctx, &owner.pubkey(), zero_balance)],
        &[owner],
    );
    send(
        svm,
        payer,
        &[
            approve_ix(&account, mint, &payer.pubkey()),
            thaw_ix(&account, mint, &payer.pubkey()),
        ],
        &[],
    );
    Holder {
        account,
        elgamal,
        aes,
    }
}

fn apply(svm: &mut LiteSVM, payer: &Keypair, holder: &Holder, owner: &Keypair) {
    let ct = read_ct(svm, &holder.account);
    let counter: u64 = ct.pending_balance_credit_counter.into();
    let new_available =
        available_balance(&ct, &holder.elgamal) + pending_balance(&ct, &holder.elgamal);
    send(
        svm,
        payer,
        &[apply_ix(
            &holder.account,
            &owner.pubkey(),
            counter,
            holder.aes.encrypt(new_available).to_bytes(),
        )],
        &[owner],
    );
}

fn close_contexts(svm: &mut LiteSVM, payer: &Keypair, contexts: &[Pubkey]) {
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
}

fn withheld_on(svm: &LiteSVM, account: &Pubkey, fee_authority: &ElGamalKeypair) -> u64 {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let withheld: ElGamalCiphertext = state
        .get_extension::<ConfidentialTransferFeeAmount>()
        .unwrap()
        .withheld_amount
        .try_into()
        .unwrap();
    fee_authority.secret().decrypt_u32(&withheld).unwrap()
}

fn confidential_transfer_with_fee(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    source: &Holder,
    source_owner: &Keypair,
    destination: &Holder,
    fee_authority: &ElGamalKeypair,
    amount: u64,
) {
    let ct = read_ct(svm, &source.account);
    let current_available: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    let current_decryptable: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    let available = available_balance(&ct, &source.elgamal);
    let destination_pubkey: ElGamalPubkey = read_ct(svm, &destination.account)
        .elgamal_pubkey
        .try_into()
        .unwrap();

    let proofs = transfer_with_fee_split_proof_data(
        &current_available,
        &current_decryptable,
        amount,
        &source.elgamal,
        &source.aes,
        &destination_pubkey,
        None,
        fee_authority.pubkey(),
        BASIS_POINTS,
        MAXIMUM_FEE,
    )
    .unwrap();

    let eq_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let val_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let pct_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyPercentageWithCap,
        &proofs.percentage_with_cap_proof_data,
    );
    let fee_val_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
        &proofs.fee_ciphertext_validity_proof_data,
    );
    let range_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyBatchedRangeProofU256,
        &proofs.range_proof_data,
    );

    let ixs = ct_ix::transfer_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        &source.account,
        mint,
        &destination.account,
        &source.aes.encrypt(available - amount).into(),
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &source_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&pct_ctx),
        ProofLocation::ContextStateAccount(&fee_val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(svm, payer, &ixs, &[source_owner]);

    close_contexts(svm, payer, &[eq_ctx, val_ctx, pct_ctx, fee_val_ctx, range_ctx]);
}

fn withdraw(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    holder: &Holder,
    owner: &Keypair,
    amount: u64,
) {
    let ct = read_ct(svm, &holder.account);
    let current: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    let available = available_balance(&ct, &holder.elgamal);
    let proofs = withdraw_proof_data(&current, available, amount, &holder.elgamal).unwrap();

    let eq_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let range_ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &proofs.range_proof_data,
    );

    let ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &holder.account,
        mint,
        amount,
        DECIMALS,
        &holder.aes.encrypt(available - amount).into(),
        &owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(svm, payer, &ixs, &[owner]);

    close_contexts(svm, payer, &[eq_ctx, range_ctx]);
}

#[test]
fn confidential_remittance_withholds_an_encrypted_fee_then_withdraws() {
    let (mut svm, payer) = setup();
    let (mint, fee_authority) = create_v2_mint_with_fee_authority(&mut svm, &payer);
    let mint = mint.pubkey();

    let sender_owner = payer.insecure_clone();
    let recipient_owner = Keypair::new();
    svm.airdrop(&recipient_owner.pubkey(), 10_000_000_000).unwrap();

    let sender = onboard(&mut svm, &payer, &mint, &sender_owner);
    let recipient = onboard(&mut svm, &payer, &mint, &recipient_owner);

    send(
        &mut svm,
        &payer,
        &[
            mint_to(&TOKEN_2022_PROGRAM_ID, &mint, &sender.account, &payer.pubkey(), &[], 100_000)
                .unwrap(),
            deposit_ix(&sender.account, &mint, &sender_owner.pubkey(), 100_000),
        ],
        &[],
    );
    apply(&mut svm, &payer, &sender, &sender_owner);

    let amount = 10_000u64;
    let fee = amount * u64::from(BASIS_POINTS) / 10_000;
    confidential_transfer_with_fee(
        &mut svm,
        &payer,
        &mint,
        &sender,
        &sender_owner,
        &recipient,
        &fee_authority,
        amount,
    );

    let sender_ct = read_ct(&svm, &sender.account);
    assert_eq!(available_balance(&sender_ct, &sender.elgamal), 100_000 - amount);
    let recipient_ct = read_ct(&svm, &recipient.account);
    assert_eq!(pending_balance(&recipient_ct, &recipient.elgamal), amount - fee);
    assert_eq!(available_balance(&recipient_ct, &recipient.elgamal), 0);
    assert_eq!(withheld_on(&svm, &recipient.account, &fee_authority), fee);
    assert_eq!(public_amount(&svm, &sender.account), 0);
    assert_eq!(public_amount(&svm, &recipient.account), 0);

    let err = withdraw_proof_data(
        &recipient_ct.available_balance.try_into().unwrap(),
        available_balance(&recipient_ct, &recipient.elgamal),
        1_000,
        &recipient.elgamal,
    );
    assert!(err.is_err(), "withdraw must not be provable from pending");

    apply(&mut svm, &payer, &recipient, &recipient_owner);
    withdraw(&mut svm, &payer, &mint, &recipient, &recipient_owner, 1_000);

    let recipient_ct = read_ct(&svm, &recipient.account);
    assert_eq!(public_amount(&svm, &recipient.account), 1_000);
    assert_eq!(
        available_balance(&recipient_ct, &recipient.elgamal),
        amount - fee - 1_000
    );
}

#[test]
fn a_withdraw_proof_that_lies_about_the_balance_is_rejected() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer).pubkey();
    let owner = payer.insecure_clone();
    let holder = onboard(&mut svm, &payer, &mint, &owner);

    send(
        &mut svm,
        &payer,
        &[
            mint_to(&TOKEN_2022_PROGRAM_ID, &mint, &holder.account, &payer.pubkey(), &[], 5_000)
                .unwrap(),
            deposit_ix(&holder.account, &mint, &owner.pubkey(), 5_000),
        ],
        &[],
    );

    let ct = read_ct(&svm, &holder.account);
    assert_eq!(available_balance(&ct, &holder.elgamal), 0);
    assert_eq!(pending_balance(&ct, &holder.elgamal), 5_000);

    let current: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    assert!(withdraw_proof_data(&current, 5_000, 5_000, &holder.elgamal).is_err());

    let fake_available = holder.elgamal.pubkey().encrypt(5_000u64);
    let proofs = withdraw_proof_data(&fake_available, 5_000, 5_000, &holder.elgamal).unwrap();
    let eq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let range_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &proofs.range_proof_data,
    );

    let ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &holder.account,
        &mint,
        5_000,
        DECIMALS,
        &holder.aes.encrypt(0).into(),
        &owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    let logs = send_expecting_failure(&mut svm, &payer, &ixs, &[]);
    assert!(
        logs.contains("Balance mismatch"),
        "forged withdraw rejected for the wrong reason:\n{logs}"
    );

    assert_eq!(public_amount(&svm, &holder.account), 0);
    assert_eq!(pending_balance(&read_ct(&svm, &holder.account), &holder.elgamal), 5_000);
}
