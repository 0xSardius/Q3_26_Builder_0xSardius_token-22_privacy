//! Week 4 remittance mint: Task 1.
//!
//! The issuer mint must stack TransferFeeConfig, MetadataPointer (pointed
//! at the mint itself), DefaultAccountState (Frozen), and MintCloseAuthority.
//! Space comes from `ExtensionType::try_calculate_account_len`. Every
//! extension init runs before InitializeMint.

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use anchor_spl::token_interface::spl_token_2022::{
    extension::{
        default_account_state::DefaultAccountState, metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority, transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::initialize_account3,
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 250;
const MAXIMUM_FEE: u64 = 1_000;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let program_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    assert!(
        program_path.exists(),
        "program binary not found at {}. Run cargo-build-sbf first.",
        program_path.display()
    );
    svm.add_program_from_file(ID, program_path).unwrap();

    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let blockhash = svm.latest_blockhash();
    let mut transaction = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    transaction.try_sign(&signers, blockhash).unwrap();
    if let Err(err) = svm.send_transaction(transaction) {
        panic!("transaction failed:\n{err:#?}");
    }
}

fn create_remittance_mint_ix(payer: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceMint {
            payer: *payer,
            mint: *mint,
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceMint {
            decimals: DECIMALS,
            basis_points: BASIS_POINTS,
            maximum_fee: MAXIMUM_FEE,
        }
        .data(),
    }
}

fn remittance_extensions() -> [ExtensionType; 4] {
    [
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ]
}

#[test]
fn remittance_mint_is_sized_from_try_calculate_account_len() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let account = svm.get_account(&mint.pubkey()).unwrap();
    assert_eq!(account.owner, TOKEN_2022_PROGRAM_ID);

    let expected =
        ExtensionType::try_calculate_account_len::<MintState>(&remittance_extensions()).unwrap();
    assert_eq!(account.data.len(), expected);
}

#[test]
fn remittance_mint_initializes_the_four_required_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let account = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&account.data).unwrap();

    assert_eq!(state.base.decimals, DECIMALS);
    assert_eq!(
        Option::<Pubkey>::from(state.base.freeze_authority),
        Some(payer.pubkey()),
        "Frozen-by-default needs a freeze authority or thaw is impossible"
    );

    let types = state.get_extension_types().unwrap();
    for required in remittance_extensions() {
        assert!(
            types.contains(&required),
            "missing {required:?} on remittance mint; have {types:?}"
        );
    }

    let fee = state.get_extension::<TransferFeeConfig>().unwrap();
    assert_eq!(
        u16::from(fee.newer_transfer_fee.transfer_fee_basis_points),
        BASIS_POINTS
    );
    assert_eq!(u64::from(fee.newer_transfer_fee.maximum_fee), MAXIMUM_FEE);

    let pointer = state.get_extension::<MetadataPointer>().unwrap();
    assert_eq!(
        Option::<Pubkey>::from(pointer.metadata_address),
        Some(mint.pubkey()),
        "MetadataPointer must point at the mint itself, not an off-chain registry"
    );

    let default_state = state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(default_state.state, AccountState::Frozen as u8);

    let close = state.get_extension::<MintCloseAuthority>().unwrap();
    assert_eq!(
        Option::<Pubkey>::from(close.close_authority),
        Some(payer.pubkey())
    );
}

#[test]
fn new_holder_accounts_on_the_remittance_mint_start_frozen() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    // TransferFeeConfig on the mint forces TransferFeeAmount onto holders.
    let holder_extensions =
        ExtensionType::get_required_init_account_extensions(&remittance_extensions());
    let space =
        ExtensionType::try_calculate_account_len::<TokenAccountState>(&holder_extensions).unwrap();
    let holder = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &holder.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(
                &TOKEN_2022_PROGRAM_ID,
                &holder.pubkey(),
                &mint.pubkey(),
                &payer.pubkey(),
            )
            .unwrap(),
        ],
        &[&holder],
    );

    let account = svm.get_account(&holder.pubkey()).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&account.data).unwrap();
    assert_eq!(state.base.state, AccountState::Frozen);
}
