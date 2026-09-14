
use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    initialize_mint2, mint_close_authority_initialize, spl_token_2022, transfer_fee_initialize,
    InitializeMint2, Mint, MintCloseAuthorityInitialize, TokenInterface, TransferFeeInitialize,
};
use spl_token_2022::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    state::Mint as MintState,
};
 

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

  
}
