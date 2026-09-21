use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, program_pack::Pack, system_program},
    InstructionData, ToAccountMetas,
};
use anchor_spl::token_interface::spl_token_2022::{
    extension::{
        default_account_state::DefaultAccountState, metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        transfer_fee::{instruction::set_transfer_fee, TransferFeeAmount, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{freeze_account, initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use litesvm::types::TransactionMetadata;
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

fn send_ok(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
    extra: &[&Keypair],
) -> TransactionMetadata {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let blockhash = svm.latest_blockhash();
    let mut transaction = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    transaction.try_sign(&signers, blockhash).unwrap();
    match svm.send_transaction(transaction) {
        Ok(meta) => meta,
        Err(err) => panic!("transaction failed:\n{err:#?}"),
    }
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let _ = send_ok(svm, payer, ixs, extra);
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

fn quote_remittance_fee_ix(mint: &Pubkey, amount: u64) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::QuoteRemittanceFee {
            mint: *mint,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::QuoteRemittanceFee { amount }.data(),
    }
}

fn quoted_fee(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, amount: u64) -> u64 {
    let meta = send_ok(
        svm,
        payer,
        &[quote_remittance_fee_ix(mint, amount)],
        &[],
    );
    u64::from_le_bytes(meta.return_data.data[..8].try_into().unwrap())
}

fn live_epoch_fee(svm: &LiteSVM, mint: &Pubkey, amount: u64) -> u64 {
    let account = svm.get_account(mint).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&account.data).unwrap();
    let config = state.get_extension::<TransferFeeConfig>().unwrap();
    config.calculate_epoch_fee(0, amount).unwrap()
}

#[test]
fn quote_matches_calculate_epoch_fee_including_the_maximum_cap() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    assert_eq!(quoted_fee(&mut svm, &payer, &mint.pubkey(), 10_000), 250);
    assert_eq!(live_epoch_fee(&svm, &mint.pubkey(), 10_000), 250);
    assert_eq!(quoted_fee(&mut svm, &payer, &mint.pubkey(), 50_000), MAXIMUM_FEE);
}

#[test]
fn quote_uses_the_live_epoch_rate_not_the_scheduled_newer_rate() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    send(
        &mut svm,
        &payer,
        &[set_transfer_fee(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &payer.pubkey(),
            &[],
            500,
            MAXIMUM_FEE,
        )
        .unwrap()],
        &[],
    );

    let account = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&account.data).unwrap();
    let config = state.get_extension::<TransferFeeConfig>().unwrap();
    let cached_newer = u16::from(config.newer_transfer_fee.transfer_fee_basis_points);
    assert_eq!(cached_newer, 500);

    let amount = 10_000u64;
    let from_cached_newer = amount * u64::from(cached_newer) / 10_000;
    assert_eq!(from_cached_newer, 500);

    let fee = quoted_fee(&mut svm, &payer, &mint.pubkey(), amount);
    assert_eq!(fee, 250);
    assert_eq!(fee, live_epoch_fee(&svm, &mint.pubkey(), amount));
    assert_ne!(fee, from_cached_newer);
}

fn holder_account(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, owner: &Pubkey) -> Pubkey {
    let extensions = ExtensionType::get_required_init_account_extensions(&remittance_extensions());
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&extensions).unwrap();
    let holder = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &holder.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &holder.pubkey(), mint, owner).unwrap(),
        ],
        &[&holder],
    );
    holder.pubkey()
}

fn thaw_after_kyc_ix(token_account: &Pubkey, mint: &Pubkey, freeze_authority: &Pubkey) -> Instruction {
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

fn thaw(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, account: &Pubkey) {
    send(
        svm,
        payer,
        &[thaw_after_kyc_ix(account, mint, &payer.pubkey())],
        &[],
    );
}

fn mint_default_state(svm: &LiteSVM, mint: &Pubkey) -> u8 {
    let account = svm.get_account(mint).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&account.data).unwrap();
    state.get_extension::<DefaultAccountState>().unwrap().state
}

fn read_holder(svm: &LiteSVM, account: &Pubkey) -> (u64, u64, AccountState) {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let withheld = u64::from(
        state
            .get_extension::<TransferFeeAmount>()
            .unwrap()
            .withheld_amount,
    );
    (state.base.amount, withheld, state.base.state)
}

fn transfer_with_protocol_fee_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::TransferWithProtocolFee {
            source: *source,
            mint: *mint,
            destination: *destination,
            authority: *authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::TransferWithProtocolFee { amount }.data(),
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
    let blockhash = svm.latest_blockhash();
    let mut transaction = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    transaction.try_sign(&signers, blockhash).unwrap();
    match svm.send_transaction(transaction) {
        Ok(_) => panic!("expected the transaction to fail, but it succeeded"),
        Err(err) => format!("{err:#?}"),
    }
}

#[test]
fn remittance_transfer_withholds_the_live_epoch_fee() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let source = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    thaw(&mut svm, &payer, &mint.pubkey(), &source);
    thaw(&mut svm, &payer, &mint.pubkey(), &dest);

    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &source,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    let amount = 10_000u64;
    let fee = live_epoch_fee(&svm, &mint.pubkey(), amount);
    assert_eq!(fee, 250);

    send(
        &mut svm,
        &payer,
        &[transfer_with_protocol_fee_ix(
            &source,
            &mint.pubkey(),
            &dest,
            &payer.pubkey(),
            amount,
        )],
        &[],
    );

    let (source_amount, source_withheld, _) = read_holder(&svm, &source);
    let (dest_amount, dest_withheld, _) = read_holder(&svm, &dest);
    assert_eq!(source_amount, 0);
    assert_eq!(source_withheld, 0);
    assert_eq!(dest_amount, amount - fee);
    assert_eq!(dest_withheld, fee);
}

#[test]
fn remittance_transfer_fails_while_the_source_is_frozen() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let source = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    thaw(&mut svm, &payer, &mint.pubkey(), &source);
    thaw(&mut svm, &payer, &mint.pubkey(), &dest);

    send(
        &mut svm,
        &payer,
        &[
            mint_to(
                &TOKEN_2022_PROGRAM_ID,
                &mint.pubkey(),
                &source,
                &payer.pubkey(),
                &[],
                10_000,
            )
            .unwrap(),
            freeze_account(
                &TOKEN_2022_PROGRAM_ID,
                &source,
                &mint.pubkey(),
                &payer.pubkey(),
                &[],
            )
            .unwrap(),
        ],
        &[],
    );

    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[transfer_with_protocol_fee_ix(
            &source,
            &mint.pubkey(),
            &dest,
            &payer.pubkey(),
            10_000,
        )],
        &[],
    );
    assert!(
        logs.contains("AccountFrozen") || logs.contains("frozen"),
        "rejected for the wrong reason:\n{logs}"
    );
}

#[test]
fn remittance_state_requires_state_with_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );
    let holder = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    let mint_data = svm.get_account(&mint.pubkey()).unwrap().data;
    assert!(MintState::unpack(&mint_data).is_err());
    let base = MintState::unpack(&mint_data[..MintState::LEN]).unwrap();
    assert_eq!(base.decimals, DECIMALS);

    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data).unwrap();
    assert!(mint_state.get_extension::<TransferFeeConfig>().is_ok());
    assert!(mint_state.get_extension::<DefaultAccountState>().is_ok());

    let holder_data = svm.get_account(&holder).unwrap().data;
    assert!(TokenAccountState::unpack(&holder_data).is_err());
    let holder_state = StateWithExtensions::<TokenAccountState>::unpack(&holder_data).unwrap();
    assert!(holder_state.get_extension::<TransferFeeAmount>().is_ok());
}

#[test]
fn thaw_after_kyc_unfreezes_one_account_without_changing_mint_default() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let cleared = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let pending = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    assert_eq!(read_holder(&svm, &cleared).2, AccountState::Frozen);
    assert_eq!(mint_default_state(&svm, &mint.pubkey()), AccountState::Frozen as u8);

    thaw(&mut svm, &payer, &mint.pubkey(), &cleared);

    assert_eq!(read_holder(&svm, &cleared).2, AccountState::Initialized);
    assert_eq!(read_holder(&svm, &pending).2, AccountState::Frozen);
    assert_eq!(mint_default_state(&svm, &mint.pubkey()), AccountState::Frozen as u8);

    let later = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    assert_eq!(read_holder(&svm, &later).2, AccountState::Frozen);
}

#[test]
fn thaw_after_kyc_rejects_a_non_freeze_authority() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(&payer.pubkey(), &mint.pubkey())],
        &[&mint],
    );

    let holder = holder_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let impostor = Keypair::new();
    svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();

    let logs = send_expecting_failure(
        &mut svm,
        &impostor,
        &[thaw_after_kyc_ix(&holder, &mint.pubkey(), &impostor.pubkey())],
        &[],
    );
    assert!(
        logs.contains("owner") || logs.contains("authority") || logs.contains("0x4"),
        "rejected for the wrong reason:\n{logs}"
    );
    assert_eq!(read_holder(&svm, &holder).2, AccountState::Frozen);
}
