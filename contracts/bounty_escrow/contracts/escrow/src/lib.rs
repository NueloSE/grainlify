use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

pub mod constants;
pub mod errors;
pub mod events;
pub mod state;

use crate::constants::*;
use crate::errors::*;
use crate::events::*;
use crate::state::*;

declare_id!("8vS5pL7e6k2xP7L9R9jGv6D5v8S5pL7e6k2xP7L9R9jG");

#[program]
pub mod bounty_escrow {
    use super::*;

    pub fn initialize_escrow(
        ctx: Context<InitializeEscrow>,
        bounty_id: String,
        amount: u64,
        expiry: i64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.initializer = ctx.accounts.initializer.key();
        escrow.bounty_id = bounty_id;
        escrow.amount = amount;
        escrow.expiry = expiry;
        escrow.status = EscrowStatus::Active;
        escrow.bump = ctx.bumps.escrow;

        // Transfer tokens to vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.initializer_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.initializer.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        emit!(EscrowInitialized {
            bounty_id: escrow.bounty_id.clone(),
            initializer: escrow.initializer,
            amount,
        });

        Ok(())
    }

    pub fn complete_bounty(ctx: Context<CompleteBounty>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(escrow.status == EscrowStatus::Active, EscrowError::EscrowNotActive);

        let seeds = &[
            b"escrow".as_ref(),
            escrow.initializer.as_ref(),
            escrow.bounty_id.as_bytes(),
            &[escrow.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.contributor_token_account.to_account_info(),
            authority: escrow.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, escrow.amount)?;

        escrow.status = EscrowStatus::Completed;

        emit!(BountyCompleted {
            bounty_id: escrow.bounty_id.clone(),
            contributor: ctx.accounts.contributor.key(),
        });

        Ok(())
    }

    // --- NEW FUNCTIONS FROM new_functions.rs ---

    pub fn set_conditional_refund(
        ctx: Context<SetRefund>, 
        mode: RefundMode, 
        config: GasBudgetConfig
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let refund_record = &mut ctx.accounts.refund_record;

        refund_record.escrow = escrow.key();
        refund_record.mode = mode;
        refund_record.gas_budget = config.max_gas;
        refund_record.is_resolved = false;

        emit!(RefundModeSet {
            bounty_id: escrow.bounty_id.clone(),
            mode,
        });

        Ok(())
    }

    pub fn trigger_refund(ctx: Context<TriggerRefund>) -> Result<()> {
        let escrow = &ctx.accounts.escrow;
        let refund_record = &mut ctx.accounts.refund_record;

        require!(!refund_record.is_resolved, EscrowError::RefundAlreadyResolved);
        
        let clock = Clock::get()?;
        if refund_record.mode == RefundMode::TimeBased {
            require!(clock.unix_timestamp > escrow.expiry, EscrowError::ExpiryNotReached);
        }

        emit!(RefundTriggered {
            bounty_id: escrow.bounty_id.clone(),
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    pub fn resolve_refund(ctx: Context<ResolveRefund>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let refund_record = &mut ctx.accounts.refund_record;

        require!(escrow.status == EscrowStatus::Active, EscrowError::EscrowNotActive);
        require!(!refund_record.is_resolved, EscrowError::RefundAlreadyResolved);

        let seeds = &[
            b"escrow".as_ref(),
            escrow.initializer.as_ref(),
            escrow.bounty_id.as_bytes(),
            &[escrow.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.initializer_token_account.to_account_info(),
            authority: escrow.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, escrow.amount)?;

        escrow.status = EscrowStatus::Refunded;
        refund_record.is_resolved = true;

        emit!(RefundResolved {
            bounty_id: escrow.bounty_id.clone(),
            amount: escrow.amount,
        });

        Ok(())
    }
}

// --- ACCOUNT CONTEXTS AND TYPES ---

#[derive(Accounts)]
pub struct InitializeEscrow<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        constraint = initializer_token_account.mint == mint.key(),
        constraint = initializer_token_account.owner == initializer.key()
    )]
    pub initializer_token_account: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = initializer,
        space = 8 + EscrowAccount::LEN,
        seeds = [b"escrow", initializer.key().as_ref(), bounty_id.as_bytes()],
        bump
    )]
    pub escrow: Account<'info, EscrowAccount>,
    #[account(
        init,
        payer = initializer,
        token::mint = mint,
        token::authority = escrow,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct CompleteBounty<'info> {
    #[account(mut)]
    pub contributor: Signer<'info>,
    #[account(
        mut,
        seeds = [b"escrow", escrow.initializer.as_ref(), escrow.bounty_id.as_bytes()],
        bump = escrow.bump,
        has_one = initializer,
    )]
    pub escrow: Account<'info, EscrowAccount>,
    /// CHECK: This is the original initializer of the escrow
    pub initializer: AccountInfo<'info>,
    #[account(
        mut,
        constraint = vault_token_account.owner == escrow.key()
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub contributor_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SetRefund<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    #[account(
        mut,
        has_one = initializer,
        seeds = [b"escrow", initializer.key().as_ref(), escrow.bounty_id.as_bytes()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, EscrowAccount>,
    #[account(
        init,
        payer = initializer,
        space = 8 + RefundRecord::LEN,
        seeds = [b"refund", escrow.key().as_ref()],
        bump
    )]
    pub refund_record: Account<'info, RefundRecord>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TriggerRefund<'info> {
    pub caller: Signer<'info>,
    pub escrow: Account<'info, EscrowAccount>,
    #[account(
        mut,
        seeds = [b"refund", escrow.key().as_ref()],
        bump,
    )]
    pub refund_record: Account<'info, RefundRecord>,
}

#[derive(Accounts)]
pub struct ResolveRefund<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    #[account(
        mut,
        has_one = initializer,
        seeds = [b"escrow", initializer.key().as_ref(), escrow.bounty_id.as_bytes()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, EscrowAccount>,
    #[account(
        mut,
        seeds = [b"refund", escrow.key().as_ref()],
        bump,
    )]
    pub refund_record: Account<'info, RefundRecord>,
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub initializer_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct RefundRecord {
    pub escrow: Pubkey,
    pub mode: RefundMode,
    pub gas_budget: u64,
    pub is_resolved: bool,
}

impl RefundRecord {
    pub const LEN: usize = 32 + 1 + 8 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum RefundMode {
    Oracle,
    TimeBased,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct GasBudgetConfig {
    pub max_gas: u64,
}
