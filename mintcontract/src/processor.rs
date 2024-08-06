use std::{io::{Write, Read}, mem::size_of, str::FromStr};

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction, InstructionError}, 
    log::sol_log_compute_units, 
    msg,
    pubkey,
    program::{invoke, invoke_signed}, 
    program_error::ProgramError, 
    pubkey::{Pubkey, PUBKEY_BYTES}, 
    rent::Rent, 
    system_instruction::{self, create_account}, 
    system_program, 
    sysvar::{Sysvar, clock::Clock},
    program_pack::{IsInitialized, Pack}, program_memory::sol_memcmp,
};
use spl_token::{
    // state::Account;
    instruction::{initialize_account, initialize_mint, mint_to, set_authority, transfer}
};
use spl_associated_token_account::{get_associated_token_address, create_associated_token_account,};
use mpl_token_metadata::instruction::create_metadata_accounts_v2;
use unlock_mintinstructions::unlock_proto;
use prost::Message;
use arrayref::array_ref;

use crate::error::UnlockError;

const ADMIN_ACCOUNT: Pubkey = pubkey!("CvS3N5Fv17ysJ2oDECUFMtHy84Eja4ppAvfLgfUKFNZL");
// const BERG_ACCOUNT: &str = "bergXKRwwp1JEZXoSqRdJBYCw8N9rd1LtgnmLqrQePY"; // mypubkey_1.json

const MAIN_CONFIG_PDA_SEED: &[u8; 11] = b"main_config";
const MINT_CONFIG: &[u8; 11] = b"mint_config";
const MINT_COUNTER: &[u8; 12] = b"mint_counter";

pub struct MainConfig(Vec<u8>);

/// Instruction processor
// #[allow(unused_variables)]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {

    // Decode Call Contract instruction sent to the contract
    let msg = match unlock_proto::CallContract::decode(instruction_data) {
        Ok(msg) => msg,
        Err(e) => {
            msg!("{}", e.to_string());
            return Err(UnlockError::InstructionUnpackError.into());
        }
    };

    // Iterator on accounts sent to the contract
    let account_info_iter = &mut accounts.iter();
    
    // Decode main instruction to decide what to do
    let main_instruction = unlock_proto::ContractInstruction::from_i32(msg.contract_instruction)
        .ok_or(UnlockError::InstructionDecodeError)?;

    match main_instruction {
        unlock_proto::ContractInstruction::CreateMintConfig => {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?; // also the storage of the config, has to sign and owned by this program
            let mint_config_pda = next_account_info(account_info_iter)?;
            let mint_counter_pda = next_account_info(account_info_iter)?;
            let system_program = next_account_info(account_info_iter)?;
            let rent = Rent::get()?;

            // assert_eq!(mint_admin_account.key, &ADMIN_ACCOUNT);
            if !mint_id.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }

            if !cmp_pubkeys(mint_id.owner, program_id) {
                return Err(ProgramError::IncorrectProgramId);
            }

            let (mint_config_pda_derived, mint_config_pda_bump) = 
                Pubkey::find_program_address(&[MINT_CONFIG, &mint_id.key.to_bytes()], program_id);
            let (mint_count_pda_derived, mint_count_pda_bump) = 
                Pubkey::find_program_address(&[MINT_COUNTER, &mint_id.key.to_bytes()], program_id);

            let mint_config_signer_seeds: &[&[_]] = &[
                MINT_CONFIG,
                &mint_id.key.as_ref(),
                &[mint_config_pda_bump],
            ];

            let mint_counter_signer_seeds: &[&[_]] = &[
                MINT_COUNTER,
                &mint_id.key.as_ref(),
                &[mint_count_pda_bump],
            ];

            if !cmp_pubkeys(mint_config_pda.key, &mint_config_pda_derived) {
                msg!("Mint config");
                return Err(ProgramError::IncorrectProgramId);
            }

            if !cmp_pubkeys(mint_counter_pda.key, &mint_count_pda_derived) {
                msg!("Mint config");
                return Err(ProgramError::IncorrectProgramId);
            }

            let mint_config_bytes = msg.mint_config_bytes.ok_or(UnlockError::MintConfigDecodeError)?;

            if mint_config_pda.data_is_empty() && mint_config_pda.lamports() == 0 {
                invoke_signed(
                    &create_account(
                        payer.key,
                        mint_config_pda.key,
                        rent.minimum_balance(mint_config_bytes.len() + 10),
                        (mint_config_bytes.len() + 10) as u64,
                        program_id,
                    ),
                    &[
                        payer.clone(),
                        mint_config_pda.clone(),
                        system_program.clone(),
                    ],
                    &[mint_config_signer_seeds],
                )?;
                msg!("Mint config pda created {}", mint_config_pda.key);
            }

            if mint_counter_pda.data_is_empty() && mint_counter_pda.lamports() == 0 {
                invoke_signed(
                    &create_account(
                        payer.key,
                        mint_counter_pda.key,
                        rent.minimum_balance(size_of::<u32>()),
                        size_of::<u32>() as u64,
                        program_id,
                    ),
                    &[
                        payer.clone(),
                        mint_counter_pda.clone(),
                        system_program.clone(),
                    ],
                    &[mint_counter_signer_seeds],
                )?;
                msg!("Mint coounter pda created {}", mint_counter_pda.key);
            }

            let mint_config_len = (mint_config_bytes.len() as u16).to_le_bytes();
            let mut final_bytes: Vec<u8> = mint_config_len.to_vec();
            final_bytes.extend(mint_config_bytes.as_slice());
            let mut mint_config_pda_data = mint_config_pda.data.borrow_mut(); // account mint id, created in client before upload
            let write_result = mint_config_pda_data.write(final_bytes.as_slice())?;
            if write_result != final_bytes.as_slice().len() {
                return Err(ProgramError::AccountDataTooSmall)
            }
            // msg!("Write result {}, buffer length {}", &write_result, &mint_config_bytes.len());
        },
        unlock_proto::ContractInstruction::ReadMintConfig => {
            msg!("Use local client to decode mint config");
            return Err(ProgramError::InvalidArgument);
            // let payer = next_account_info(account_info_iter)?;
            // let mint_id = next_account_info(account_info_iter)?; // also the storage of the config, has to sign and owned by this program
            // let mint_config_pda = next_account_info(account_info_iter)?;
            // if !payer.is_signer && mint_id.is_signer {
            //     return Err(ProgramError::MissingRequiredSignature);
            // }
            // let (mint_config_pda_derived, _mint_config_pda_bump) = Pubkey::find_program_address(
            //     &[&mint_id.key.to_bytes(), b"mint_config"], program_id);
            // if mint_config_pda.key != &mint_config_pda_derived {
            //     return Err(ProgramError::IncorrectProgramId);
            // }
            // let mint_config_data = &mint_config_pda.data.borrow_mut().to_vec();
            // let mint_config_len = u16::from_le_bytes(array_ref![mint_config_data, 0, 2].clone());
            // // msg!("mint config len from bytes {}",mint_config_len);
            // let mint_config_bytes = &mint_config_data[2..(mint_config_len + 2) as usize].to_vec();
            // // msg!("mint config bytes len from bytes {}",mint_config_bytes.len());

            // let mint_config = unlock_proto::MintConfig::decode(mint_config_bytes.as_slice()).unwrap();
            // msg!("{:#?}", mint_config);
            // let nft_config = unlock_proto::NftConfig::decode(mint_config.clone().nft_config_bytes.unwrap().as_slice()).unwrap();
            // msg!("nft config {:?}", nft_config);
            // let mut buf = vec![];
            // mint_config.encode(&mut buf).unwrap();
            // msg!("{:?}", buf);
        },
        unlock_proto::ContractInstruction::DeleteMintConfig => {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?;
            let mint_config_pda = next_account_info(account_info_iter)?;
            let mint_counter_pda = next_account_info(account_info_iter)?;
            if !mint_id.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            if mint_id.owner != program_id {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // let (mint_config_pda_derived, _mint_config_pda_bump) = Pubkey::find_program_address(
            //     &[&mint_id.key.as_ref(), b"mint_config"], program_id);
            // if mint_config_pda.key != &mint_config_pda_derived {
            //     return Err(ProgramError::IncorrectProgramId);
            // }
            // let mut mint_id_data = mint_id.data.borrow_mut();
            // mint_id_data.fill(0);
            let payer_lamports = payer.lamports();
            **payer.lamports.borrow_mut() = payer_lamports
                .checked_add(mint_id.lamports())
                .unwrap();
            **mint_id.lamports.borrow_mut() = 0;
            msg!("Mint id deleted");

            let mut data = mint_config_pda.data.borrow_mut();
            data.fill(0);
            let payer_lamports = payer.lamports();
            **payer.lamports.borrow_mut() = payer_lamports
                .checked_add(mint_config_pda.lamports())
                .unwrap();
            **mint_config_pda.lamports.borrow_mut() = 0;
            msg!("Mint config pda deleted");

            let mut data = mint_counter_pda.data.borrow_mut();
            data.fill(0);
            let payer_lamports = payer.lamports();
            **payer.lamports.borrow_mut() = payer_lamports
                .checked_add(mint_counter_pda.lamports())
                .unwrap();
            **mint_counter_pda.lamports.borrow_mut() = 0;
            msg!("Mint counter pda deleted");

        },
        unlock_proto::ContractInstruction::CreateMintData => {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?;
            if !payer.is_signer {
                msg!("You can't fund this transaction");
                return Err(ProgramError::MissingRequiredSignature);
            }

            if !mint_id.is_signer || mint_id.owner != program_id {
                return Err(ProgramError::MissingRequiredSignature);
            }

            if mint_id.data_is_empty() && mint_id.lamports() == 0 {
                msg!("Mint_id data not initialized");
                return Err(ProgramError::UninitializedAccount);
            }

            // let mint_data_bytes = msg.mint_data_bytes.ok_or(UnlockError::MintConfigDecodeError)?;
            // let mint_data_offset = msg.mint_data_offset.ok_or(UnlockError::MintConfigDecodeError)?;

            // account data 
            // let mut data = mint_id.data.borrow_mut();

            // let write_offset = mint_data_offset.saturating_add(mint_data_bytes.len() as u32);
            // msg!("Write offset {}", write_offset);

            // if data.len() < write_offset as usize || (mint_data_offset..write_offset).len() != mint_data_bytes.len() {
            //     return Err(ProgramError::AccountDataTooSmall);
            // }
            
            // data.get_mut(mint_data_offset as usize..write_offset as usize)
            //     .ok_or(InstructionError::AccountDataTooSmall).map_err(|_|return ProgramError::Custom(66))?
            //     .copy_from_slice(&mint_data_bytes);
            // msg!("Done writing");

        },
        unlock_proto::ContractInstruction::CreateMintWhitelist => {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?; // also the storage of the config, has to sign and owned by this program
            let wl_pda = next_account_info(account_info_iter)?;
            let system_program = next_account_info(account_info_iter)?;
            let rent = Rent::get()?;

            if !mint_id.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }

            if mint_id.owner != program_id {
                return Err(ProgramError::IncorrectProgramId);
            }

            let wl_mint = msg.wl_mint.unwrap();
            if let Some (ata_pubkey) =  msg.wl_take_ata_create {
                let ata_to_create = next_account_info(account_info_iter)?;
                let wl_token_mint = next_account_info(account_info_iter)?;
                let nft_deposit = next_account_info(account_info_iter)?;
                let token_program = next_account_info(account_info_iter)?;
                let rent_program = next_account_info(account_info_iter)?;
                let associated_token_program = next_account_info(account_info_iter)?;
                if ata_to_create.lamports() == 0 && ata_to_create.data_is_empty() {
                    // msg!("ata {}", ata_to_create.key);
                    // msg!("wl_token_mint {}", wl_token_mint.key);
                    // msg!("nft_deposit {}", nft_deposit.key);
                    // msg!("token_program {}", token_program.key);
                    // msg!("rent_program {}", rent_program.key);
                    invoke(
                        &create_associated_token_account(
                            &payer.key,
                            &nft_deposit.key,
                            &wl_token_mint.key,
                        ),
                        // accounts,
                        &[
                            payer.clone(),
                            ata_to_create.clone(),
                            nft_deposit.clone(),
                            wl_token_mint.clone(),
                            system_program.clone(),
                            token_program.clone(),
                            rent_program.clone(),
                            associated_token_program.clone(),
                        ],
                    )?;
                } else {
                    // msg!("wl take associated account already exists {}", &ata_to_create.key)
                }
            }

            let wl_pda_signer_seeds: &[&[_]] = &[
                b"wlist",
                &mint_id.key.to_bytes(),
                &msg.wl_id.unwrap(),
                &wl_mint,
                &[msg.wl_bump.unwrap()[0]],
            ];

            let wl_pda_created = Pubkey::create_program_address(
                wl_pda_signer_seeds, 
                &program_id
            )?;
            
            if wl_pda.key != &wl_pda_created {
                // msg!("added {}", wl_pda.key);
                // msg!("created {}", wl_pda_created);
                return Err(UnlockError::InvalidPda.into());
            }

            if wl_pda.data_is_empty() && wl_pda.lamports() == 0 {
                invoke_signed(
                    &create_account(
                        payer.key,
                        wl_pda.key,
                        rent.minimum_balance(1),
                        1 as u64,
                        program_id,
                    ),
                    &[
                        payer.clone(),
                        wl_pda.clone(),
                        system_program.clone(),
                    ],
                    &[wl_pda_signer_seeds],
                )?;
                // msg!("Wl pda created {}", wl_pda.key);
            } else {
                // msg!("WL pda already initialized {}", wl_pda.key);
                // return Err(ProgramError::InvalidArgument);
            }
            
            
        },
        unlock_proto::ContractInstruction::AddMintData => {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?;
            let mint_config_pda = next_account_info(account_info_iter)?;

            if !payer.is_signer {
                // msg!("You can't fund this transaction");
                return Err(ProgramError::MissingRequiredSignature);
            }

            if !mint_id.is_signer {
                // msg!("Mint id must be signer");
                return Err(ProgramError::MissingRequiredSignature);
            }

            if mint_id.owner != program_id {
                // msg!("Mint id must be owned by the rogram");
                return Err(ProgramError::MissingRequiredSignature);
            }

            
            let mut mint_config = {
                let mint_config_data = &mint_config_pda.data.borrow();
                // let mint_config_data = &mint_config_pda.data.
                let mint_config_len = u16::from_le_bytes(array_ref![mint_config_data, 0, 2].clone());
                let mint_config_bytes = &mint_config_data[2..(mint_config_len + 2) as usize].to_vec();
                let mint_config = unlock_proto::MintConfig::decode(mint_config_bytes.as_slice())
                    .map_err(|_| return UnlockError::MintConfigDecodeError)?;
                mint_config
            };
            let mint_data_bytes = msg.mint_data_bytes.ok_or(UnlockError::MintConfigDecodeError)?;
            msg!("new data len {:?}", mint_data_bytes.len());

            let current_upload_index = mint_config.upload_counter;
            sol_log_compute_units();

            let current_mint_data_offset =  {
                let this_data =  mint_id.data.borrow();
                u32::from_le_bytes(array_ref!(this_data, (mint_config.upload_counter * 4) as usize, 4).clone())
            };
            // let from_u16_as_u82_ = {
            //     let this_borrow = mint_id.data.borrow();
            //     let from_u16_as_u82_ = array_ref!(this_borrow, (mint_config.upload_counter * 2) as usize, 2).clone();
            //     from_u16_as_u82_
            // };

            
            // let current_mint_data_offset = u16::from_le_bytes(from_u16_as_u82);
            // msg!("Current offset {}", current_mint_data_offset);

            sol_log_compute_units();

            let new_mint_data_offset = current_mint_data_offset.saturating_add(mint_data_bytes.len() as u32);
            // msg!("New offset {}", new_mint_data_offset);
            // let this_nft_decoded = unlock_proto::NftData::decode(mint_data_bytes.as_slice()).unwrap();

            // account data 
            let mut data = mint_id.data.borrow_mut();

            if data.len() < new_mint_data_offset as usize 
            || (current_mint_data_offset..new_mint_data_offset).len() != mint_data_bytes.len() {
                return Err(ProgramError::AccountDataTooSmall);
            }
            // msg!("Data len ok ");


            // let data_start_offset = indexes_array_u8.len();
            let data_start_offset: usize = (mint_config.nft_amount as usize + 1) * 4;
            
            
            data.get_mut(data_start_offset + current_mint_data_offset as usize..data_start_offset + new_mint_data_offset as usize)
                .ok_or(InstructionError::AccountDataTooSmall).map_err(|_|return ProgramError::Custom(4))?
                .copy_from_slice(&mint_data_bytes);
            msg!("Done writing new bytes");

            sol_log_compute_units();
            data.get_mut(((mint_config.upload_counter+1) * 4) as usize..((mint_config.upload_counter+2) * 4) as usize)
                .ok_or(InstructionError::AccountDataTooSmall).map_err(|_|return ProgramError::Custom(5))?
                .copy_from_slice(&u32::to_le_bytes(new_mint_data_offset));
            msg!("Done writing new index");
            sol_log_compute_units();
            
            mint_config.upload_counter += 1;
            msg!("Upload count {}", mint_config.upload_counter);
            let mut new_mintconfig_bytes = vec![];
            mint_config.encode(&mut new_mintconfig_bytes).unwrap();
            let mint_config_len = (new_mintconfig_bytes.len() as u16).to_le_bytes();
            let mut final_bytes: Vec<u8> = mint_config_len.to_vec();
            final_bytes.extend(new_mintconfig_bytes.as_slice());
            let mut mint_config_data = mint_config_pda.data.borrow_mut();
            let write_result = mint_config_data.write(final_bytes.as_slice())?;
            // msg!("Mint data {:?}", &data);

        },
        unlock_proto::ContractInstruction::ReadMintData => {
            let mint_admin_account = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?;
            let mint_config_pda = next_account_info(account_info_iter)?;

            // assert_eq!(mint_admin_account.key, &ADMIN_ACCOUNT);
            if !mint_id.is_signer || mint_id.owner != program_id {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let (mint_config_pda_derived, _mint_config_pda_bump) = 
                Pubkey::find_program_address(&[&mint_id.key.to_bytes(), b"mint_config"], program_id);

            if mint_config_pda.key != &mint_config_pda_derived {
                return Err(ProgramError::IncorrectProgramId);
            }

            let mint_data = mint_id.data.borrow_mut().to_vec();

            let mut mint_config_pda_data = mint_config_pda.data.borrow_mut();
            let mint_config_len = u16::from_le_bytes(*array_ref![mint_config_pda_data, 0, 2]);
            let mint_config_bytes = &mint_config_pda_data[2..(mint_config_len + 2) as usize].to_vec();
            let mut mint_config = unlock_proto::MintConfig::decode(mint_config_bytes.as_slice()).unwrap();
            let indexes_array_u8 = mint_config.nft_amount * 2;
            
            let indexes_vec_u8 = &mint_data[0..=(indexes_array_u8+2) as usize];
            let mint_data_part = &mint_data[(indexes_array_u8+2) as usize..];
            if mint_config.counter/2 >= mint_config.nft_amount {
                msg!("done minting {}", mint_id.key);
                return Err(ProgramError::AccountDataTooSmall)
            }
            let from_u16_as_u82: [u8;2] = [indexes_vec_u8[mint_config.counter as usize], indexes_vec_u8[(mint_config.counter + 1) as usize]];
            let to_u16_as_u82: [u8;2] = [indexes_vec_u8[(mint_config.counter + 2) as usize], indexes_vec_u8[(mint_config.counter + 3) as usize]];

            let converted_from = u16::from_le_bytes(from_u16_as_u82) as usize;
            let converted_to = u16::from_le_bytes(to_u16_as_u82) as usize;
            let this_bytes = &mint_data_part[converted_from as usize..converted_to as usize];
            // msg!("this bytes len calculated {}", converted_to-converted_from);
            let decoded_data = unlock_proto::NftData::decode(this_bytes).unwrap();
            msg!("nft data decoded {:?}", decoded_data);

            
        },
        unlock_proto::ContractInstruction::DeleteMintData => todo!(),
        unlock_proto::ContractInstruction::Mint => /*8*/ {
            let payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?; // also the storage of the config, has to sign and owned by this program
            let mint_config_pda = next_account_info(account_info_iter)?;
            let mint_counter_pda = next_account_info(account_info_iter)?;
            let sol_deposit = next_account_info(account_info_iter)?;

            let mint_account = next_account_info(account_info_iter)?;
            let user_associated_token_address = next_account_info(account_info_iter)?;
            let token_metadata_account = next_account_info(account_info_iter)?;
            let rent_program = next_account_info(account_info_iter)?;
            let token_program = next_account_info(account_info_iter)?;
            let token_metadata_program = next_account_info(account_info_iter)?;
            let associated_token_program = next_account_info(account_info_iter)?;
            let system_program = next_account_info(account_info_iter)?;

            if !payer.is_signer {
                // msg!("You can't fund this mint");
                return Err(ProgramError::MissingRequiredSignature);
            }

            if !mint_account.is_signer {
                // msg!("Mint not signed");
                return Err(ProgramError::MissingRequiredSignature);
            }

            if !cmp_pubkeys(mint_config_pda.owner, program_id) {
                return Err(ProgramError::IllegalOwner);
            }

            let mint_config_signer_seeds: &[&[_]] = &[
                MINT_CONFIG,
                &mint_id.key.to_bytes(),
                &[msg.mint_config_pda_bump.as_ref().unwrap()[0]],
            ];

            let mint_config_pda_created = Pubkey::create_program_address(
                mint_config_signer_seeds, 
                &program_id
            )?;

            if !cmp_pubkeys(mint_config_pda.key, &mint_config_pda_created) {
                return Err(UnlockError::InvalidPda.into());
            }

            let mint_config: Box<unlock_proto::MintConfig> = {
                let mint_config_data = &mint_config_pda.data.borrow();
                let mint_config_len = u16::from_le_bytes(array_ref![mint_config_data, 0, 2].clone());
                let mint_config_bytes = &mint_config_data[2..(mint_config_len + 2) as usize];
                let mint_config = unlock_proto::MintConfig::decode(mint_config_bytes)
                    .map_err(|_| return UnlockError::MintConfigDecodeError)?;
                Box::new(mint_config)
            };
            
            // sol_log_compute_units();

            // get minted counter pda count, and increment it
            let mut mint_counter_data = mint_counter_pda.data.borrow_mut();
            let this_count = u32::from_le_bytes(array_ref!(mint_counter_data,0,size_of::<u32>()).clone());

            mint_counter_data.get_mut(0..size_of::<u32>())
                .ok_or(InstructionError::AccountDataTooSmall)
                .map_err(|_|return ProgramError::Custom(4))?
                .copy_from_slice(&(this_count+1).to_le_bytes());
            

            if this_count >= mint_config.nft_amount {
                msg!("{} Done minting!, No more NFT in vault.", mint_id.key);
                return Err(UnlockError::MintFinished.into())
            }

            if mint_config.pause_mint {
                msg!("Mint paused.");
                return Err(UnlockError::MintPaused.into());
            }

            let mut found_phase = false;
            for this_phase in mint_config.clone().phases {
                let clock_via_sysvar = Clock::get()?;
                let epoch = clock_via_sysvar.unix_timestamp;
                if (epoch as i32) < this_phase.start_timestamp {continue}
                if let Some(end_timestamp) = this_phase.end_timestamp {
                    if (epoch as i32) > end_timestamp {continue}
                }
                found_phase = true;
                // msg!("phase found {:?}", this_phase);
                msg!("epoch {}", epoch);

                match unlock_proto::PhaseType::from_i32(this_phase.phase_type).unwrap() {
                    unlock_proto::PhaseType::Public => {
                        // msg!("Public mint phase");
                    },
                    unlock_proto::PhaseType::WhitelistTokenLimited => {
                        msg!("Phase limit per wl token");
                    },
                    unlock_proto::PhaseType::WhitelistTokenInf => {
                        let wl_associated_token_account = next_account_info(account_info_iter)?;
                        let wl_token_mint = next_account_info(account_info_iter)?;
                        let wl_pda = next_account_info(account_info_iter)?;
                        let wl_id = next_account_info(account_info_iter)?;
                        let nft_deposit = next_account_info(account_info_iter)?;
                        let nft_deposit_associated = next_account_info(account_info_iter)?;

                        // check_owner(wl_associated_token_account, &spl_token::id())?;
                        if !cmp_pubkeys(wl_associated_token_account.owner, &spl_token::id()) {
                            return Err(ProgramError::InvalidArgument)
                        }
                        let unpacked_associated_acc = Box::new(spl_token::state::Account::unpack_unchecked(&wl_associated_token_account.data.borrow())?);
                        if !cmp_pubkeys(&unpacked_associated_acc.owner, payer.key) || !&unpacked_associated_acc.is_initialized() {
                            return Err(ProgramError::InvalidArgument)
                        }

                        let whitelist_id = Pubkey::new(&this_phase.whitelist_id.unwrap());
                        check_wl_pda(
                            &wl_pda,
                            &mint_id,
                            &wl_token_mint.key,
                            &whitelist_id,
                            &msg.clone().wl_bump.unwrap(),
                            &program_id
                        )?;
                        if wl_pda.lamports() == 0 || wl_pda.owner != program_id {
                            msg!("No valid whitelist");
                            return Err(ProgramError::InvalidArgument)
                        }
                        msg!("WL valid");
                        
                    },
                    unlock_proto::PhaseType::WhitelistTokenBurn => {
                        // msg!("Phase wl token burn");
                    },
                    unlock_proto::PhaseType::WhitelistTokenTake => {
                        let wl_associated_token_account = next_account_info(account_info_iter)?;
                        let wl_token_mint = next_account_info(account_info_iter)?;
                        let wl_pda = next_account_info(account_info_iter)?;
                        let wl_id = next_account_info(account_info_iter)?;
                        let nft_deposit = next_account_info(account_info_iter)?;
                        let nft_deposit_associated = next_account_info(account_info_iter)?;

                        if !cmp_pubkeys(wl_associated_token_account.owner, &spl_token::id()) {
                            return Err(ProgramError::InvalidArgument)
                        }
                        let unpacked_associated_acc = Box::new(spl_token::state::Account::unpack_unchecked(&wl_associated_token_account.data.borrow())?);

                        if !cmp_pubkeys(&unpacked_associated_acc.owner, payer.key) || !&unpacked_associated_acc.is_initialized() {
                            return Err(ProgramError::InvalidArgument)
                        }

                        let whitelist_id = Pubkey::new(&this_phase.whitelist_id.unwrap());
                        check_wl_pda(
                            &wl_pda,
                            &mint_id,
                            &wl_token_mint.key,
                            &whitelist_id,
                            &msg.clone().wl_bump.unwrap(),
                            &program_id
                        )?;
                        msg!("{}",wl_pda.owner);
                        msg!("{}",program_id);
                        msg!("{}",wl_pda.lamports());
                        if cmp_pubkeys(wl_pda.owner, program_id) || wl_pda.lamports() == 0 {
                            msg!("No valid whitelist");
                            return Err(ProgramError::InvalidArgument)
                        }

                        // This will fail if account is not present, exausting computational units for the transaction
                        if nft_deposit_associated.lamports() == 0 && nft_deposit_associated.data_is_empty() {
                            invoke(
                                &create_associated_token_account(
                                    &payer.key,
                                    &Pubkey::new(&mint_config.nft_deposit),
                                    &wl_token_mint.key,
                                ),
                                &[
                                    payer.clone(),
                                    nft_deposit_associated.clone(),
                                    nft_deposit.clone(),
                                    wl_token_mint.clone(),
                                    system_program.clone(),
                                    token_program.clone(),
                                    rent_program.clone(),
                                    associated_token_program.clone(),
                                ],
                            )?;
                        }
                                               
                        invoke(
                            &transfer(
                                &token_program.key,
                                &wl_associated_token_account.key,
                                &nft_deposit_associated.key,
                                &payer.key,
                                &[&payer.key],
                                1,
                            )?,
                            &[
                                wl_associated_token_account.clone(),
                                nft_deposit_associated.clone(),
                                payer.clone(),
                            ],
                        )?;
                        msg!("WL Token transferred");
                    },
                    _ => return Err(UnlockError::PhaseTypeDecodeError.into()), // this should never hit
                }

                if found_phase {
                    break
                }
            }
            if !found_phase { return Err(UnlockError::PhaseNotFound.into()) }

            sol_log_compute_units();
            let mint_id_data = mint_id.data.borrow();
            let mint_data_part = &mint_id_data[((mint_config.nft_amount + 1) * 4) as usize..];
            let current_mint_data_offset_start_ = u32::from_le_bytes(array_ref!(mint_id_data, (this_count * 4) as usize, 4).clone());
            let current_mint_data_offset_end_ = u32::from_le_bytes(array_ref!(mint_id_data, ((this_count + 1) * 4) as usize, 4).clone());

            let this_bytes = &mint_data_part[current_mint_data_offset_start_ as usize..current_mint_data_offset_end_ as usize];
            let this_nft_decoded = unlock_proto::NftData::decode(this_bytes).map_err(|_|return UnlockError::InstructionDecodeError)?;
            // msg!("Pay for mint");

            if !cmp_pubkeys(&Pubkey::new(&mint_config.sol_deposit), sol_deposit.key) {
                return Err(ProgramError::InvalidArgument)
            }

            pay(payer, sol_deposit, system_program, mint_config.nft_price_lamports)?;

            let mint_account_size = spl_token::state::Mint::LEN;
            let rent = Rent::get()?;

            // creating mint account
            // msg!("Creating Mint Account");
            invoke(
                &create_account(
                    payer.key,
                    mint_account.key,
                    rent.minimum_balance(mint_account_size),
                    mint_account_size as u64,
                    &spl_token::id(),
                ),
                &[
                    payer.clone(),
                    mint_account.clone(),
                    system_program.clone(),
                    rent_program.clone()
                ],
            )?;
        
            // creating new mint
            // msg!("Creating New Mint.");
            invoke(
                &initialize_mint(
                    &spl_token::id(),
                    mint_account.key,
                    &mint_config_pda_created,
                    Some(&mint_id.key),
                    0,
                )?,
                &[
                    rent_program.clone(),
                    mint_account.clone(),
                    // &spl_token::id(),
                    token_program.clone(),
                ],
            )?;

            // Creating Associated Account
            // msg!("Creating Associated Account.");
            invoke(
                &create_associated_token_account(
                    payer.key,
                    payer.key,
                    mint_account.key,
                ),
                &[
                    payer.clone(),
                    user_associated_token_address.clone(),
                    mint_account.clone(),
                    system_program.clone(),
                    token_program.clone(),
                    rent_program.clone(),
                    associated_token_program.clone(),
                ],
            )?;

            // msg!("Minting Token To Associated Account");
            invoke_signed(
                &mint_to(
                    &spl_token::id(),
                    &mint_account.key,
                    &user_associated_token_address.key,
                    &mint_config_pda.key,
                    &[&payer.key, &mint_config_pda.key],
                    1,
                )?,
                &[
                    token_program.clone(),
                    mint_account.clone(),
                    user_associated_token_address.clone(),
                    payer.clone(),
                    token_program.clone(),
                    mint_config_pda.clone(),
                ],
                &[mint_config_signer_seeds],
            )?;
            // msg!("creators");

            let mut creators_vec = vec![];
            for config_creator in mint_config.creators.clone() {
                creators_vec.push(
                    mpl_token_metadata::state::Creator {
                        address: Pubkey::new(&config_creator.address),
                        verified: false,
                        share: config_creator.share.clone() as u8,
                    }
                )
            }

            // metadata v1
            // invoke_signed(
            //     &create_metadata_accounts(
            //         token_metadata_program.key.clone(),
            //         token_metadata_account.key.clone(),
            //         mint_account.key.clone(),
            //         mint_config_pda.key.clone(),
            //         payer.key.clone(),
            //         mint_id.key.clone(),
            //         "mintsv2".into(),
            //         mint_config.symbol,
            //         "https://custom_uri".into(),
            //         Some(creators_vec),
            //         mint_config.seller_fee_basis_points as u16,
            //         false,
            //         true,
            //     ),
            //     accounts,
            //     &[mint_config_signer_seeds],
            // )?;

            invoke_signed(
                &create_metadata_accounts_v2(
                    token_metadata_program.key.clone(),
                    token_metadata_account.key.clone(),
                    mint_account.key.clone(),
                    mint_config_pda.key.clone(),
                    payer.key.clone(),
                    mint_id.key.clone(),
                    this_nft_decoded.name.clone().into(),
                    String::from_utf8(mint_config.symbol.clone()).unwrap(),
                    this_nft_decoded.uri.into(),
                    Some(creators_vec),
                    mint_config.seller_fee_basis_points as u16,
                    false,
                    true,
                    None,
                    None,
                ),
                accounts,
                &[mint_config_signer_seeds],
            )?;

            // msg!("NFT minted!");
            // msg!("{}", this_nft_decoded.name);


            // increment mint counter
            sol_log_compute_units();
            mint_config.counter = mint_config.counter + 1;
            let mut new_mintconfig_bytes = vec![];
            mint_config.encode(&mut new_mintconfig_bytes).unwrap();
            let mint_config_len = (new_mintconfig_bytes.len() as u16).to_le_bytes();
            let mut final_bytes: Vec<u8> = mint_config_len.to_vec();
            final_bytes.extend(new_mintconfig_bytes.as_slice());
            let mut mint_config_data = mint_config_pda.data.borrow_mut();
            let write_result = mint_config_data.write(final_bytes.as_slice())?;
            
            msg!("write result {}, buffer length {}", &write_result, &mint_config_bytes.len());
        },
        unlock_proto::ContractInstruction::PauseMint => /*9*/ {

            let _payer = next_account_info(account_info_iter)?;
            let mint_id = next_account_info(account_info_iter)?; // also the storage of the config, has to sign and owned by this program
            let mint_config_pda = next_account_info(account_info_iter)?;

            if !mint_id.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            if mint_id.owner != program_id {
                return Err(ProgramError::IncorrectProgramId);
            }

            let (mint_config_pda_derived, _mint_config_pda_bump) = 
                Pubkey::find_program_address(&[MINT_CONFIG, &mint_id.key.to_bytes()], program_id);

            if mint_config_pda.key != &mint_config_pda_derived {
                msg!("Mint config");
                return Err(ProgramError::IncorrectProgramId);
            }

            let mut mint_config: Box<unlock_proto::MintConfig> = {
                let mint_config_data = &mint_config_pda.data.borrow();
                // let mint_config_data = &mint_config_pda.data.
                let mint_config_len = u16::from_le_bytes(array_ref![mint_config_data, 0, 2].clone());
                let mint_config_bytes = &mint_config_data[2..(mint_config_len + 2) as usize];
                let mint_config = unlock_proto::MintConfig::decode(mint_config_bytes)
                    .map_err(|_| return UnlockError::MintConfigDecodeError)?;
                Box::new(mint_config)
            };

            if mint_config.pause_mint == false {
                mint_config.pause_mint = true;
                msg!("Mint paused.")  
            } else {
                mint_config.pause_mint = false;
                msg!("Mint unpaused.")  
            }
            
            let mut new_mintconfig_bytes = vec![];
            mint_config.encode(&mut new_mintconfig_bytes).unwrap();
            let mint_config_len = (new_mintconfig_bytes.len() as u16).to_le_bytes();
            let mut final_bytes: Vec<u8> = mint_config_len.to_vec();
            final_bytes.extend(new_mintconfig_bytes.as_slice());
            let mut mint_config_data = mint_config_pda.data.borrow_mut();
            let write_result = mint_config_data.write(final_bytes.as_slice())?;

            if write_result < final_bytes.as_slice().len() {
                return Err(ProgramError::AccountDataTooSmall);
            }

            
        },
        unlock_proto::ContractInstruction::AdminCreateMainConfig => {
            let admin_account = next_account_info(account_info_iter)?;
            let main_config_pda = next_account_info(account_info_iter)?;
            let system_program = next_account_info(account_info_iter)?;
            let rent = Rent::get()?;

            assert_eq!(admin_account.key, &ADMIN_ACCOUNT);
            if !admin_account.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            sol_log_compute_units();

            let (main_config_pda_derived, main_config_pda_bump) = Pubkey::find_program_address(
                &[MAIN_CONFIG_PDA_SEED], program_id);
            if main_config_pda.key != &main_config_pda_derived {
                return Err(ProgramError::IncorrectProgramId);
            }

            msg!("pda {}", main_config_pda_derived);
            let main_config = msg.contract_main_config_bytes.unwrap();
            let pda_seeds: &[&[u8]] = &[MAIN_CONFIG_PDA_SEED, &[main_config_pda_bump]];

            if main_config_pda.data_is_empty() && main_config_pda.lamports() == 0 {
                msg!("Create main config account.");
                create_pda(
                    admin_account, 
                    main_config_pda,
                    system_program,
                    program_id, 
                    rent.minimum_balance(main_config.len()), 
                    main_config.len() as u64,
                    // &[&[&MAIN_CONFIG_PDA_SEED[..], &[main_config_pda_bump]]]
                    &[pda_seeds]
                )?;
            }

            let config_data = MainConfig::try_from_slice(&main_config_pda.data.borrow_mut());
            let mut config_data = main_config_pda.data.borrow_mut().to_vec();
            config_data.write(&main_config) = &main_config;
            let mut data = main_config_pda.data.borrow_mut();

            let write_result = data.write(main_config.as_slice())?;
            msg!("write result {}, buffer length {}", &write_result, &main_config.len());

            msg!("Created main config");
            
        },
        unlock_proto::ContractInstruction::AdminReadMainConfig => {
            let admin_account = next_account_info(account_info_iter)?;
            let main_config_pda = next_account_info(account_info_iter)?;

            assert_eq!(admin_account.key, &ADMIN_ACCOUNT);
            if !admin_account.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let config_data = &main_config_pda.data.borrow().to_vec();
            let main_config = unlock_proto::ContractMainConfig::decode(config_data.as_slice()).unwrap();
            msg!("{:#?}", main_config);
            sol_log_compute_units();

        },
        unlock_proto::ContractInstruction::AdminUpdateMainConfig => {
            let admin_account = next_account_info(account_info_iter)?;
            let main_config_pda = next_account_info(account_info_iter)?;
            assert_eq!(admin_account.key, &ADMIN_ACCOUNT);
            sol_log_compute_units();
            
        },
        unlock_proto::ContractInstruction::AdminDeleteMainConfig => {
            let admin_account = next_account_info(account_info_iter)?;
            let main_config_pda = next_account_info(account_info_iter)?;
            assert_eq!(admin_account.key, &ADMIN_ACCOUNT);
            if !admin_account.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let (main_config_pda_derived, _main_config_pda_bump) = Pubkey::find_program_address(
                &[MAIN_CONFIG_PDA_SEED], program_id);
            if main_config_pda.key != &main_config_pda_derived {
                return Err(ProgramError::IncorrectProgramId);
            }

            // msg!("pda {}", main_config_pda_derived);
            sol_log_compute_units();

            let mut data = main_config_pda.data.borrow_mut();
            data.fill(0);
            let admin_account_lamports = admin_account.lamports();
            **admin_account.lamports.borrow_mut() = admin_account_lamports
                .checked_add(main_config_pda.lamports())
                .unwrap();
            **main_config_pda.lamports.borrow_mut() = 0;
        },
        _ => return Err(UnlockError::InstructionDecodeError.into()),

    }
    
    Ok(())
}

pub fn pay<'a>(
    funding_account: &AccountInfo<'a>, 
    deposit_account: &AccountInfo<'a>, 
    system_program: &AccountInfo<'a>,
    lamports: u64,
) -> ProgramResult {

    invoke(
        &system_instruction::transfer(
            &funding_account.key,
            &deposit_account.key,
            lamports,
        ),
        &[
            funding_account.clone(), 
            deposit_account.clone(),
            system_program.clone(),
        ]
    )?;
    Ok(())
}

// pub fn create_pda<'a>(
//     payer: &AccountInfo<'a>, 
//     pda: &AccountInfo<'a>,
//     system_program: &AccountInfo<'a>,
//     owner: &Pubkey,
//     rent: u64,
//     space: u64,
//     seed: &[&[&[u8]]],
// ) -> ProgramResult {
//     invoke_signed(
//         &create_account(
//             payer.key,
//             &pda.key,
//             rent,
//             space,
//             owner,
//         ),
//         &[
//             payer.clone(),
//             pda.clone(),
//             system_program.clone(),
//         ],
//         seed,
//     )?;
//     Ok(())
// }

// pub fn check_owner(account: &AccountInfo, owner: &Pubkey) -> ProgramResult {
//     if account.owner != owner {
//         Err(ProgramError::IllegalOwner)
//     } else {
//         Ok(())
//     }
// }

// #[inline(never)]
// pub fn unpack_account<T: Pack>(account_info: &AccountInfo,) -> Result<T, ProgramError> {
//     let account: T = T::unpack_unchecked(&account_info.data.borrow())?;
//     Ok(account)
// }

// #[inline(never)]
// pub fn check_unpacked_initialized(account: &spl_token::state::Account) -> ProgramResult {
//     if !account.is_initialized(){
//         Err(ProgramError::UninitializedAccount)
//     } else {
//         Ok(())
//     }
// }

// #[inline(never)]
// pub fn check_unpacked_owner(account: &spl_token::state::Account, owner: &Pubkey) -> ProgramResult {
//     if &account.owner != owner {
//         Err(ProgramError::IllegalOwner)
//     } else {
//         Ok(())
//     }
// }

/// Checks two pubkeys for equality in a computationally cheap way using sol_memcmp
pub fn cmp_pubkeys(puba: &Pubkey, pubb: &Pubkey) -> bool {
    sol_memcmp(puba.as_ref(), pubb.as_ref(), PUBKEY_BYTES) == 0
}

#[inline(never)]
pub fn check_wl_pda(
    wl_pda: &AccountInfo,
    mint_id: &AccountInfo,
    wl_mint: &Pubkey,
    wl_id: &Pubkey,
    wl_bump: &Vec<u8>,
    program_id: &Pubkey,

) -> ProgramResult {

    // let wl_pda_signer_seeds: &[&[_]] = &[
    //     b"wlist",
    //     &wl_mint.to_bytes(),
    //     &wl_id,
    //     &wl_bump,
    // ];
    let wl_pda_signer_seeds: &[&[_]] = &[
        b"wlist",
        &mint_id.key.to_bytes(),
        &wl_id.to_bytes(),
        &wl_mint.to_bytes(),
        &wl_bump,
    ];

    // msg!("{:?}", wl_pda_signer_seeds);
    let wl_pda_created = Pubkey::create_program_address(
        wl_pda_signer_seeds, 
        &program_id
    )?;

    if !cmp_pubkeys(wl_pda.key, &wl_pda_created) {
        msg!("added {}", wl_pda.key);
        msg!("created {}", wl_pda_created);
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

// #[inline(never)]
// fn check_marker_pda(
//     wl_pda: &AccountInfo,
//     mint_id: &AccountInfo,
//     wl_token_mint: &Pubkey,
//     wl_id: &Pubkey,
//     wl_bump: Vec<u8>,
//     program_id: &Pubkey,
// ) -> ProgramResult {


//     let seeds_vec = vec![
//         b"wlist".to_vec(),
//         mint_id.key.to_bytes().to_vec(),
//         wl_token_mint.to_bytes().to_vec(),
//     ];

//     let signer_seeds_vec = seeds_vec
//         .iter()
//         .map(|seed| seed.as_slice())
//         .collect::<Vec<_>>();

//     let wl_pda_created = Pubkey::create_program_address(
//         signer_seeds_vec.as_slice(), 
//         &program_id
//     )?;

//     if &wl_pda_created != wl_pda.key || wl_pda.owner != program_id || wl_pda.lamports() == 0 {
//         msg!("Marker account invalid");
//         return Err(UnlockError::InvalidPda.into())
//     } else {
//         return Ok(())
//     }

// }


// fn write_account_data<'a>(
//     program: &mut AccountInfo<'a>,
//     program_data_offset: usize,
//     bytes: &[u8],
// ) -> Result<(), InstructionError> {
//     let data = program.data.borrow_mut();
//     let write_offset = program_data_offset.saturating_add(bytes.len());
//     if data.len() < write_offset || (program_data_offset..write_offset).len() != bytes.len() {
        
//         return Err(InstructionError::AccountDataTooSmall);
//     }
//     data.get_mut(program_data_offset..write_offset)
//         .ok_or(InstructionError::AccountDataTooSmall)?
//         .copy_from_slice(bytes);
//     Ok(())
// }