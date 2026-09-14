use anchor_lang::{
    prelude::Pubkey,
    solana_program::{
        instruction::{Instruction},
        system_program,
    },
    InstructionData,
    ToAccountMetas,
};

use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

use t22::{
    accounts,
    instruction,
    ID,
};

const TOKEN_2022_PROGRAM_ID: Pubkey =
    anchor_spl::token_interface::spl_token_2022::ID;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();

    let payer = Keypair::new();

    svm.airdrop(
        &payer.pubkey(),
        10_000_000_000,
    )
    .unwrap();

   let program_path =
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy/t22.so");

println!("Loading program from: {}", program_path.display());

assert!(
    program_path.exists(),
    "Program binary not found at {}",
    program_path.display()
);

svm.add_program_from_file(ID, program_path)
    .unwrap();
    (svm, payer)
}

fn send_transaction(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction: Instruction,
    additional_signers: &[&Keypair],
) {
    let blockhash = svm.latest_blockhash();

    let message = Message::new(
        &[instruction],
        Some(&payer.pubkey()),
    );

    let mut transaction =
        Transaction::new_unsigned(message);

    let mut signers: Vec<&Keypair> =
        vec![payer];

    signers.extend_from_slice(additional_signers);

    transaction
        .try_sign(&signers, blockhash)
        .unwrap();

    let result = svm.send_transaction(transaction);

match result {
    Ok(result) => {
        println!("Transaction succeeded");
        println!("Compute units: {:?}", result.compute_units_consumed);
    }
    Err(err) => {
        println!("TRANSACTION FAILED:");
        println!("{:#?}", err);
        panic!("transaction failed");
    }
}
}

#[test]
fn test_create_mint_declarative() {
    let (mut svm, payer) = setup();

    let mint = Keypair::new();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateMintDeclarative {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateMintDeclarative {
            decimals: 6,
        }
        .data(),
    };

    send_transaction(
        &mut svm,
        &payer,
        ix,
        &[&mint],
    );

    let account = svm
        .get_account(&mint.pubkey())
        .unwrap();

    assert_eq!(
        account.owner,
        TOKEN_2022_PROGRAM_ID
    );

    println!(
        "Declarative mint created: {}",
        mint.pubkey()
    );
}

#[test]
fn test_create_mint_with_fee() {
    let (mut svm, payer) = setup();

    let mint = Keypair::new();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateMintWithFee {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateMintWithFee {
            decimals: 6,
            basis_points: 250,
            maximum_fee: 1_000,
        }
        .data(),
    };

    send_transaction(
        &mut svm,
        &payer,
        ix,
        &[&mint],
    );

    let account = svm
        .get_account(&mint.pubkey())
        .unwrap();

    assert_eq!(
        account.owner,
        TOKEN_2022_PROGRAM_ID
    );

    println!(
        "Transfer-fee mint created: {}",
        mint.pubkey()
    );
}

#[test]
fn test_assert_supported_mint() {
    let (mut svm, payer) = setup();

    let mint = Keypair::new();

    // First create a supported mint.
    let create_ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateMintDeclarative {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateMintDeclarative {
            decimals: 9,
        }
        .data(),
    };

    send_transaction(
        &mut svm,
        &payer,
        create_ix,
        &[&mint],
    );

    // Now ask the program to validate it.
    let assert_ix = Instruction {
        program_id: ID,
        accounts: accounts::AssertSupportedMint {
            mint: mint.pubkey(),
        }
        .to_account_metas(None),
        data: instruction::AssertSupportedMint {}.data(),
    };

    send_transaction(
        &mut svm,
        &payer,
        assert_ix,
        &[],
    );

    println!(
        "Supported mint accepted: {}",
        mint.pubkey()
    );
}