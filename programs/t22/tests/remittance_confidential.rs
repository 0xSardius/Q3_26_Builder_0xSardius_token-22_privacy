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
use t22new::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    instruction::initialize_account3,
    state::Account as TokenAccountState,
};
use zk::{
    encryption::derivation::derive_confidential_keys,
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use zkif::{
    instruction::{ContextStateInfo, ProofInstruction},
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
    let mint = Keypair::new();
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
                withdraw_withheld_authority_elgamal_pubkey: [0u8; 32],
            }
            .data(),
        }],
        &[&mint],
    );
    mint
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
) -> ([u8; AE_CIPHERTEXT_LEN], Pubkey) {
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ctx = stage_proof(
        svm,
        payer,
        ProofInstruction::VerifyPubkeyValidity,
        &proof,
    );
    (aes.encrypt(0).to_bytes(), ctx)
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
    let (zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

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
    let (zero_balance, proof_ctx) = stage_pubkey_proof(&mut svm, &payer, &owner);

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
