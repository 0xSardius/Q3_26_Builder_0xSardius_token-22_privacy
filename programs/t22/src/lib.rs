
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_interface::{
    initialize_mint2, mint_close_authority_initialize, spl_token_2022, transfer_fee_initialize,
    InitializeMint2, Mint, MintCloseAuthorityInitialize, TokenInterface, TransferFeeInitialize,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{instruction as confidential_instruction, DecryptableBalance},
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    state::Mint as MintState,
};

// The length of a ciphertext which is how a decryptable balance is represented in the account data
pub const AE_CIPHERTEXT_LEN: usize = 36;
 
declare_id!("6sC5C8VFoTpEZQVn3YK9EUSd5g3Cs6zTT3HCDBGQkyo4");


const SUPPORTED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::MintCloseAuthority,
    ExtensionType::MetadataPointer,
    ExtensionType::TransferFeeConfig,
];

#[program]
pub mod t22 {
    use super::*;

    ///the declarative path.
    /// Everything happens in the `#[account(init, ...)]` attribute on the
    /// `mint` field. The macro expands to exactly the sequence you would write
    /// by hand:
    ///
    ///   create_account -> each extension initializer -> initialize_mint2
    ///
    ///sizes the allocation with `find_mint_account_size`, which wraps
    /// `ExtensionType::try_calculate_account_len`
    pub fn create_mint_declarative(
        ctx: Context<CreateMintDeclarative>,
        decimals: u8,
    ) -> Result<()> {
        msg!(
            "mint {} created with {} decimals",
            ctx.accounts.mint.key(),
            decimals
        );
        Ok(())
    }



    //the imperative path.
    /// Anchor's `extensions::` constraints cover a closed set of seven:
    /// group_pointer, group_member_pointer, metadata_pointer, close_authority,
    /// permanent_delegate, transfer_hook and pausable. TransferFeeConfig is
    /// not among them, so a mint that charges a transfer fee cannot be
    /// expressed as a constraint at all.
    ///
    /// The fallback is to take the mint as an unchecked account and drive the
    /// three phases yourself with CPIs. The ordering discipline does not
    /// change, only who writes it.
    pub fn create_mint_with_fee(
        ctx: Context<CreateMintWithFee>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::MintCloseAuthority,
            ExtensionType::TransferFeeConfig,
        ];
 
        // Phase 1: allocate at the full extended length. Getting this number
        // from anywhere other than `try_calculate_account_len` is how mints
        // end up too small to initialize.
        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);
 
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;
 
        // Phase 2: initialize each extension, before the mint itself exists.
        mint_close_authority_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
        )?;
 
        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
            Some(&ctx.accounts.payer.key()),
            basis_points,
            maximum_fee,
        )?;
 
        // Phase 3: seal the mint. Nothing can be added after this point, and
        // most mint extensions cannot be added later at all, so a mistake here
        // is permanent rather than recoverable.
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;
 
        msg!(
            "mint {} created with {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

     /// `InterfaceAccount<'info, Mint>` looks like it gives you the whole mint.
    /// It does not. Anchor's deserializer runs
    /// `StateWithExtensions::unpack(buf).map(|t| Mint(t.base))`, which parses
    /// the TLV region and then discards it, keeping only the base struct.
    ///
    /// So the typed account has decimals, supply and authorities, and knows
    /// nothing about extensions. To see them you re-borrow the raw bytes and
    /// run `StateWithExtensions` yourself. That is the same call the plain
    /// Rust client makes.
    /// 
    /// Confidential TF: creating the mint.
    ///
    /// ConfidentialTransferMint is not one of Anchor's seven `extensions::`
    /// constraints, and anchor-spl ships no CPI helper for it either. So this
    /// builds the raw instruction and invokes it directly. Same three phases.
    pub fn create_confidential_mint(
        ctx: Context<CreateConfidentialMint>,
        decimals: u8,
        auto_approve_new_accounts: bool,
    ) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<MintState>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let lamports = Rent::get()?.minimum_balance(space);
 
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;
 
        // No auditor key here. Passing Some(pubkey) would let its holder
        // decrypt every transfer amount for this mint, which is the usual
        // compliance escape hatch.
        let ix = confidential_instruction::initialize_mint(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.mint.key(),
            Some(ctx.accounts.payer.key()),
            auto_approve_new_accounts,
            None,
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
 
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;
 
        msg!(
            "confidential mint {} at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }


     /// Confidential: deposit.
    ///
    /// The only step of the confidential lifecycle a program can drive on its
    /// own. Moving tokens from the public balance into the pending
    /// confidential balance needs no zero knowledge proof, because the amount
    /// was already public before the move.
    pub fn deposit_confidential(
        ctx: Context<DepositConfidential>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        let ix = confidential_instruction::deposit(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            amount,
            decimals,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
 
    
    /// Confidential: apply pending balance.
    ///
    /// Incoming deposits and transfers land in a pending balance that cannot
    /// be spent. Moving it to available requires the owner to supply the new
    /// available balance already encrypted under their AES key.
    ///
    /// Note what that means: the program cannot compute this value. It has no
    /// access to the owner's key. The ciphertext is an instruction argument,
    /// and the program is a pass through. That limitation is the lesson.
    pub fn apply_pending_balance(
        ctx: Context<ApplyPendingBalance>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        let balance = DecryptableBalance::from(new_decryptable_available_balance);
        let ix = confidential_instruction::apply_pending_balance(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            expected_pending_balance_credit_counter,
            &balance,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
 

    pub fn assert_supported_mint(ctx: Context<AssertSupportedMint>) -> Result<()> {
      
        
 
        // Not available from the typed account. Drop to the raw bytes.
        let account_info = ctx.accounts.mint.to_account_info();
        let data = account_info.try_borrow_data()?;
        let state = StateWithExtensions::<MintState>::unpack(&data)?;
          
          // Available from the typed account, no extension awareness needed.
        let decimals = state.base.decimals;
 
        for extension in state.get_extension_types()? {
            require!(
                SUPPORTED_EXTENSIONS.contains(&extension),
                MintError::UnsupportedExtension
            );
        }
 
        // A transfer fee means the amount credited is not the amount debited.
        // Any accounting that assumes otherwise is wrong against this mint, so
        // read the live fee rather than assuming zero.
        //
        // Fees are epoch scheduled: `newer_transfer_fee` may not be in force
        // yet, which is why `get_epoch_fee` takes the current epoch.
        let basis_points = match state.get_extension::<TransferFeeConfig>() {
            Ok(config) => u16::from(
                config
                    .get_epoch_fee(Clock::get()?.epoch)
                    .transfer_fee_basis_points,
            ),
            Err(_) => 0,
        };
 
        msg!(
            "mint accepted: {} decimals, {} bps fee",
            decimals,
            basis_points
        );
        Ok(())
    }
 
  
}


#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct CreateMintDeclarative<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// each extension constraints below adds an
    /// `ExtensionType` to the size calculation and a CPI to the init sequence.
    #[account(
        init,
        payer = payer,
        mint::decimals = decimals,
        mint::authority = payer,
        mint::token_program = token_program,
        extensions::close_authority::authority = payer,
        extensions::metadata_pointer::authority = payer,
        extensions::metadata_pointer::metadata_address = payer,
    )]
    pub mint: InterfaceAccount<'info, Mint>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct CreateMintWithFee<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// Unchecked because the account does not exist yet and Anchor has no
    /// constraint that can describe a transfer fee mint. The instruction body
    /// creates and initializes it.
    ///
    /// CHECK: created and initialized in the handler, and required to sign
    /// because the account is made at its own address.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
 
#[derive(Accounts)]
pub struct AssertSupportedMint<'info> {
    /// Unchecked so the account is parsed exactly once, in the handler.
    ///
    /// The `owner` constraint is not optional. `StateWithExtensions::unpack`
    /// receives a byte slice and validates only the layout, so without this
    /// any account from any program whose bytes look like an initialized mint
    /// would be accepted.
    ///
    /// CHECK: ownership enforced below, contents allowlisted in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// Constrains `owner` above to SPL Token or Token-2022, and nothing else.
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// CHECK: created and initialized in the handler, signs because the
    /// account is made at its own address.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: validated by Token-2022, which rejects any account that is not
    /// a token account for this mint configured for confidential transfers.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
 
    /// CHECK: validated by Token-2022 during the deposit.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
 
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}
 
#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
 
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[error_code]
pub enum MintError {
    #[msg("mint carries an extension this program has not been written to handle")]
    UnsupportedExtension,
}
