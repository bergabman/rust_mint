use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Errors that may be returned by the UnlockMintbase program.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UnlockError {
    // 0
    // Invalid instruction data passed in.
    #[error("Failed to unpack instruction data")]
    InstructionUnpackError,
    // 1
    #[error("Failed to decode instruction data")]
    InstructionDecodeError,
    // 2
    #[error("Failed to decode main config")]
    MainConfigDecodeError,
    // 3
    #[error("Failed to decode mint config")]
    MintConfigDecodeError,
    // 4
    #[error("Failed to decode current phase whitelist type")]
    PhaseTypeDecodeError,
    // 5
    #[error("No valid phase found for this mint")]
    PhaseNotFound,
    // 6
    #[error("Phase type None, is invalid")]
    PhaseTypeInvalid,
    // 7
    #[error("Mint paused")]
    MintPaused,
    // 8
    #[error("Mint finished")]
    MintFinished,
    // 9
    #[error("Pda is not what's expected")]
    InvalidPda,
}


impl From<UnlockError> for ProgramError {
    fn from(e: UnlockError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
