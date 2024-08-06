// use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use std::mem::replace;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, anyhow};

use arrayref::array_ref;
use clap::{Arg, Command};
use prost::Message;
// use solana_client::rpc_client::{RpcClient};
use solana_client::nonblocking::rpc_client::RpcClient;
// use solana_client::rpc_client;
use solana_client::rpc_config::RpcTransactionConfig;
// use solana_sdk::account::ReadableAccount;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::signature::Signature;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
// use solana_sdk::sysvar::recent_blockhashes;
use solana_sdk::{sysvar};
use solana_sdk::transaction::Transaction;
use solana_sdk::commitment_config::CommitmentConfig;
// use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
// use solana_sdk::native_token::{LAMPORTS_PER_SOL, Sol};
use solana_sdk::signer::keypair::{read_keypair_file, Keypair};
use solana_sdk::system_program;
use solana_sdk::feature_set::spl_token_v3_3_0_release;
use solana_transaction_status::{UiTransactionEncoding, EncodedConfirmedTransactionWithStatusMeta};
use serde::{Deserialize, /*Serialize*/};
use spl_token_v3_3_0_release as spl_token;

use futures::StreamExt;
use futures::stream::FuturesUnordered;

use spl_associated_token_account::{
    get_associated_token_address, 
};

use unlock_mintinstructions::unlock_proto;
#[allow(dead_code, unused_variables, unused_features)]

pub const PROGRAM_KEY: &str = "CvS3N5Fv17ysJ2oDECUFMtHy84Eja4ppAvfLgfUKFNZL";
// const MAIN_CONFIG_PDA_SEED: &[u8; 11] = b"main_config";
// const MINT_AUTH_PDA_SEED: &[u8; 9] = b"mint_auth";

#[tokio::main]
async fn main() -> Result<()>{

    let matches = Command::new("Mint cli by bergabman")
        .version("0.1")
        .author("bergabman")
        .about("Set up mint, and communicate with the contract on chain.")
        .arg(Arg::new("key")
            .short('k')
            .long("key")
            .takes_value(true))
        .arg(Arg::new("cmd")
            .short('c')
            .long("cmd")
            .takes_value(true))
        .arg(Arg::new("mid")
            // .short('c')
            .long("mid")
            .takes_value(true))
        .arg(Arg::new("rpc")
            .short('r')
            .long("rpc")
            .takes_value(true))
        .arg(Arg::new("mint_config_path")
            .long("mc")
            .takes_value(true))
        .arg(Arg::new("mint_data_path")
            .long("md")
            .takes_value(true))
        .arg(Arg::new("ata")
            .long("ata")
            .takes_value(true))
        .arg(Arg::new("atam")
            .long("atam")
            .takes_value(true))
        .arg(Arg::new("wlid")
            .long("wlid")
            .takes_value(true))
        .get_matches();
    // GIVE WARNING AT MINT DATA READ AND OPERATIONS// CREATE A NEW MINT

    let keypair_path = matches.value_of("key").ok_or(anyhow!("Please provide a valid keyfile for payments."))?;
    let rpc_url = matches.value_of("rpc").unwrap_or("https://api.mainnet-beta.solana.com");
    let command = matches.value_of("cmd").ok_or(anyhow!("Invalid command argument."))?;
    let mint_id_from_file = matches.value_of("mid");
    let mint_config_path = matches.value_of("mint_config_path");
    let mint_data_path = matches.value_of("mint_data_path");
    let ata = matches.value_of("ata");
    let atam = matches.value_of("atam");
    // let berg_pubkey = Pubkey::from_str("bergXKRwwp1JEZXoSqRdJBYCw8N9rd1LtgnmLqrQePY")?;
    // let mint_program_pubkey = Pubkey::from_str("BtWvVHeRanSrFiqnXcsq4VC2qRGKZ8KyLY8dbSieTSWk")?; // before renaming contract
    // let first_mint_program_pubkey = Pubkey::from_str("67Y4vh72d5P8pHqta2oNN737YmhthcE2dY327cRU2sYp")?;
    // let my_keypair = read_keypair_from_file("/home/dev/.solana/mykey_1.json")?;
    let my_keypair = read_keypair_from_file(keypair_path)?;

    let cmd_parsed = command.parse::<i32>()?;

    let mut mint_id: Keypair = Keypair::new();
    if let Some(filename) =  mint_id_from_file {
        mint_id = read_keypair_from_file(filename)?;
        println!("Mint id read from file {}", mint_id.pubkey());
    } else {
        println!("Mint id generated {}", mint_id.pubkey());
        write_keypair_to_file(&mint_id, &mint_id.pubkey().to_string())?;
    }
    
    let rpc_client = rpc_client_create(rpc_url.into());
    // let balance = rpc_client.get_balance(&my_keypair.pubkey());

    let mint_config_parsed = load_mint_config(mint_config_path.unwrap())?;
    let mut mint_data_parsed = vec![];

    if cmd_parsed != 8 {
        mint_data_parsed = load_mint_data(mint_data_path.unwrap())?;
    }

    let mint_program_pubkey = Pubkey::from_str("3FHhWUE3is8NnHejveCs7Dv1XaRSstkUZVxamVZSL1ie")?;

    let mut call_contract = unlock_proto::CallContract::default();

    let (mint_config_pda_derived, mint_config_pda_bump) = Pubkey::find_program_address(
            &[b"mint_config", &mint_id.pubkey().to_bytes()], 
            &mint_program_pubkey
    );
    let (mint_counter_pda_derived, mint_counter_pda_bump) = Pubkey::find_program_address(
            &[b"mint_counter", &mint_id.pubkey().to_bytes()], 
            &mint_program_pubkey
    );

    let mut accounts = vec![];
    let mut instr_buf = vec![];

    let unlock_instr = unlock_proto::ContractInstruction::from_i32(cmd_parsed).unwrap();
    match unlock_instr {
        unlock_proto::ContractInstruction::CreateMintConfig /*0*/ => {
            // mint id keyfile, generated at mint setup, has to sign for mintconfig updates

            let mut mint_data_index: Vec<u32> = vec![0];
            let mut mint_data_bytes = vec![];
            for item in mint_data_parsed.clone() {
                let mint_data_proto = unlock_proto::NftData {
                    name: item.name,
                    uri: item.uri,
                };
                // encode to bytes
                let mut p_buf = vec![];
                mint_data_proto.encode(&mut p_buf).unwrap();
                let this_len = &p_buf.len();
                let new_len = mint_data_index.last().unwrap().saturating_add(*this_len as u32);
                mint_data_index.push(new_len);
                mint_data_bytes.extend(p_buf);
            }

            let mut mint_data_index_u8: Vec<u8> = vec![];
            for mint_index_u32 in mint_data_index {
                mint_data_index_u8.extend(mint_index_u32.to_le_bytes());
            }
            mint_data_index_u8.extend(mint_data_bytes.clone());
            println!("mint data len {}", mint_data_index_u8.len());

            let mut phases = vec![];
            for c_phase in mint_config_parsed.phases {
                phases.push(
                    unlock_proto::Phase {
                        phase_type: c_phase.phase_type,
                        start_timestamp: c_phase.start_timestamp,
                        end_timestamp: c_phase.end_timestamp,
                        whitelist_id: Some(Pubkey::from_str(&c_phase.whitelist_id.unwrap()).unwrap().to_bytes().to_vec()),
                        per_token_capacity: Some(c_phase.per_token_capacity.unwrap()),
                    }
                )
            }

            let mut creators = vec![];
            for creator in mint_config_parsed.creators {
                let mut nft_creator = unlock_proto::NftCreator::default();
                nft_creator.address = Pubkey::from_str(&creator.address).unwrap().to_bytes().to_vec();
                nft_creator.verified = false;
                nft_creator.share = creator.share;
                creators.push(nft_creator);
            }

            let mut mint_config = unlock_proto::MintConfig::default();
            mint_config.mint_id = mint_id.pubkey().to_bytes().to_vec();
            mint_config.mint_admin_pubkey = mint_id.pubkey().to_bytes().to_vec();
            mint_config.sol_deposit = Pubkey::from_str(&mint_config_parsed.sol_deposit).unwrap().to_bytes().to_vec();
            mint_config.nft_deposit = Pubkey::from_str(&mint_config_parsed.nft_deposit).unwrap().to_bytes().to_vec();
            mint_config.pause_mint = mint_config_parsed.pause_mint;
            mint_config.nft_amount = mint_data_parsed.len() as u32;
            mint_config.nft_price_lamports = mint_config_parsed.nft_price_lamports;
            mint_config.counter = mint_config_parsed.counter.unwrap();
            mint_config.upload_counter = 0;
            mint_config.phases = phases;
            mint_config.symbol = mint_config_parsed.symbol.unwrap().as_bytes().to_vec();
            mint_config.creators = creators;
            mint_config.seller_fee_basis_points = mint_config_parsed.seller_fee_basis_points.unwrap();
            mint_config.update_authority = Pubkey::from_str(&mint_config_parsed.update_authority).unwrap().to_bytes().to_vec();

            let mut mint_config_bytes = vec![];
            mint_config.clone().encode(&mut mint_config_bytes)?;


            let rent = rpc_client.get_minimum_balance_for_rent_exemption(mint_data_index_u8.len()).await?;
            let transaction = Transaction::new_signed_with_payer(
                &[system_instruction::create_account(
                    &my_keypair.pubkey(),
                    &mint_id.pubkey(),
                    rent,
                    mint_data_index_u8.len() as u64,
                    &mint_program_pubkey,
                )],
                Some(&my_keypair.pubkey()),
                &[&my_keypair, &mint_id],
                rpc_client.get_latest_blockhash().await?,
            );
            let sent_tx = rpc_client.send_and_confirm_transaction_with_spinner(&transaction).await
                .map_err(|e|return anyhow!("messed up {}", e.to_string()))?;

            let mut check = 0;
            loop {
                if let Some(tx_result) = rpc_client.get_signature_status(&sent_tx).await? {
                    tx_result.map_err(|e| return anyhow!("{}", e.to_string()))?;
                    println!("Mint_id {} account created with size {}", mint_id.pubkey(), &mint_data_index_u8.len());
                    // let tx_result = rpc_client.get_transaction(&sent_tx, UiTransactionEncoding::Json).await?.transaction.meta.unwrap();
                    // println!("{} logs {:#?}", sent_tx, tx_result.log_messages);
                    break
                } else {
                    if check < 10 {
                        check +=1
                    } else {
                        return Err(anyhow!("Failed to verify mint_id setup tx {}", &sent_tx))
                    }
                }
            }

            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));
            accounts.push(AccountMeta::new(mint_config_pda_derived, false));
            accounts.push(AccountMeta::new(mint_counter_pda_derived, false));
            accounts.push(AccountMeta::new_readonly(system_program::id(), false));

            call_contract.mint_config_bytes = Some(mint_config_bytes);
            call_contract.mint_config_pda_bump = Some(vec![mint_config_pda_bump]);
            
            call_contract.contract_instruction = unlock_proto::ContractInstruction::CreateMintConfig as i32;
            call_contract.encode(&mut instr_buf)?

        },
        unlock_proto::ContractInstruction::ReadMintConfig => /*1*/ {
            let mint_config_bytes_raw = rpc_client.get_account_data(&mint_config_pda_derived).await?;
            let mint_count_bytes_raw = rpc_client.get_account_data(&mint_counter_pda_derived).await?;
            
            let mint_config_len = u16::from_le_bytes(array_ref!(mint_config_bytes_raw, 0, 2).clone());
            let mint_config_bytes = &mint_config_bytes_raw[2..(mint_config_len+2) as usize];
            let mint_config_decoded = unlock_proto::MintConfig::decode(mint_config_bytes)?;
            let mint_count = u32::from_le_bytes(array_ref!(mint_count_bytes_raw, 0, 4).clone());

            println!("Available {}", mint_config_decoded.nft_amount);
            println!("Upload counter {}", mint_config_decoded.upload_counter);
            println!("Minted counter {}", mint_count);
        },
        unlock_proto::ContractInstruction::DeleteMintConfig => /*2*/ {
            println!("This operation will delete the mint config and mint data from chain. Are you sure you want to continue? [y,n]");
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .expect("Failed to read input");
        
            if answer != "y" || answer == "n" {
                println!("Exiting");
                return Ok(());
            }
            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));
            accounts.push(AccountMeta::new(mint_config_pda_derived, false));
            accounts.push(AccountMeta::new(mint_counter_pda_derived, false));
            call_contract.contract_instruction = unlock_proto::ContractInstruction::DeleteMintConfig as i32;
            call_contract.encode(&mut instr_buf)?
        },
        unlock_proto::ContractInstruction::CreateMintData => /*3*/ {
            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));

            call_contract.contract_instruction = unlock_proto::ContractInstruction::CreateMintData as i32;
            return Ok(()); // call ADD_MINT_DATA

        },
        unlock_proto::ContractInstruction::CreateMintWhitelist => /*4*/ {

            let wl_mints = read_file_to_vec("mint_whitelist.json")?;
            // let (wl_pda, wl_pda_bump) = Pubkey::find_program_address(
            //     &[b"wlist", &mint_id.pubkey().to_bytes()], 
            //     &mint_program_pubkey
            // );

            let mut wl_pdas = vec![];
            for phase in mint_config_parsed.phases {
                for wl_token_mint in wl_mints.clone() {

                    let mut wl_take_token = None;
                    let nft_deposit_pubkey = Pubkey::from_str(&mint_config_parsed.nft_deposit).unwrap();
                    if phase.phase_type == 5 {
                        let nft_deposit_associated_token_address = get_associated_token_address (
                            &nft_deposit_pubkey, 
                            &Pubkey::from_str(&wl_token_mint).unwrap()
                        );
                        wl_take_token = Some((nft_deposit_associated_token_address, nft_deposit_pubkey))
                    }
                    let wl_id = Pubkey::from_str(&phase.whitelist_id.as_ref().unwrap()).unwrap().to_bytes();
                    let wl_mint = Pubkey::from_str(&wl_token_mint).unwrap().to_bytes();
                    let wl_derive_seeds: &[&[u8]] = &[
                        b"wlist",
                        &mint_id.pubkey().to_bytes(),
                        &wl_id,
                        &wl_mint,
                    ];

                    let (wl_token_pda, wl_token_pda_bump) = Pubkey::find_program_address(
                        wl_derive_seeds, 
                        &mint_program_pubkey
                    );
                    wl_pdas.push((wl_token_pda, wl_token_pda_bump, wl_mint.to_vec(), wl_id.to_vec(), wl_take_token));
                }
            }

            let res = send_my_data(
                &rpc_client,
                &my_keypair,
                &mint_id,
                &mint_config_pda_derived,
                &mint_program_pubkey,
                None,
                Some(wl_pdas),
            ).await;
            println!("Failed tx count: {}", res);
            return Ok(());

        },
        unlock_proto::ContractInstruction::AddMintData => /*5*/ {

            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));
            accounts.push(AccountMeta::new(mint_config_pda_derived, false));

            call_contract.contract_instruction = unlock_proto::ContractInstruction::AddMintData as i32;
            let mut mint_data_encoded_vec = vec![];
            for item in mint_data_parsed.clone() {
                let mint_data_proto = unlock_proto::NftData {
                    name: item.name,
                    uri: item.uri,
                };
                let mut p_buf = vec![];
                mint_data_proto.encode(&mut p_buf).unwrap();
                mint_data_encoded_vec.push(p_buf.clone());
            }

            let res = send_my_data(
                &rpc_client,
                &my_keypair,
                &mint_id,
                &mint_config_pda_derived,
                &mint_program_pubkey,
                Some(&mint_data_encoded_vec),
                None,
            ).await;
            println!("Failed tx count: {}", res);
            return Ok(());
        },
        unlock_proto::ContractInstruction::ReadMintData => /*6*/ {
            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));
            accounts.push(AccountMeta::new(mint_config_pda_derived, false));

            call_contract.contract_instruction = unlock_proto::ContractInstruction::ReadMintData as i32;
            call_contract.encode(&mut instr_buf)?;
        },
        unlock_proto::ContractInstruction::DeleteMintData => todo!(),
        unlock_proto::ContractInstruction::Mint => {
            let associated_token_program_pubkey = spl_associated_token_account::id();
            let token_metadata_program_pubkey = metaplex_token_metadata::id();
            let token_program_pubkey = spl_token::id();
            let system_program_pubkey = system_program::id();
            let rent_sysvar_pubkey = sysvar::rent::id();
            let token_program_pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;

            let mut wl_user_associated_token_account = Pubkey::default();
            if let Some(ata) = ata {
                wl_user_associated_token_account = Pubkey::from_str(ata)?;
            } else {
                wl_user_associated_token_account = Pubkey::from_str("85BuXW955cwvgr7HstqziKDF8D8SpFwJzzkANNZs8hEb")?;
            }
            println!("wl ata {}", wl_user_associated_token_account);

            let mut wl_mint = Pubkey::new(&[0u8;32]);
            if let Some(atam) = atam {
                wl_mint = Pubkey::from_str(atam)?;
            } else {
                wl_mint = Pubkey::from_str("6qEKWAhB5aqsQmMUA3W5bD38ihQz7r7S9VaEuLRvrRhz")?;
            }

            println!("wl mint {}", wl_mint);

            let mut whitelist_id = Pubkey::from_str("CH3mzjw3vjPgjHATHuKBCKYNUTA7fgEm9o4Z5EQyZqAu")?;
            println!("wl whitelist {}", whitelist_id);

            let new_mint = Keypair::new();

            let new_mint_associated_token_address = get_associated_token_address (
                &my_keypair.pubkey(), 
                &new_mint.pubkey()
            );

            let new_mint_metadata_seeds = &[
                "metadata".as_bytes(),
                &token_metadata_program_pubkey.to_bytes(),
                &new_mint.pubkey().to_bytes()
            ];
            
            let (new_mint_metadata_key, _) = Pubkey::find_program_address(
                new_mint_metadata_seeds, 
                &token_metadata_program_pubkey
            );

            let wl_derive_seeds: &[&[u8]] = &[
                b"wlist",
                &mint_id.pubkey().to_bytes(),
                &whitelist_id.to_bytes(),
                &wl_mint.to_bytes(),
            ];

            let (wl_pda, wl_pda_bump) = Pubkey::find_program_address(
                wl_derive_seeds, 
                &mint_program_pubkey
            );

            let mint_counter_pda_derive_seeds: &[&[u8]] = &[
                b"mint_counter",
                &mint_id.pubkey().to_bytes(),
            ];
            let (mint_counter_pda_derived, _mint_counter_pda_bump) = Pubkey::find_program_address(
                mint_counter_pda_derive_seeds, 
                &mint_program_pubkey
            );

            let nft_deposit_associated_token_address = get_associated_token_address (
                &Pubkey::from_str(&mint_config_parsed.nft_deposit).unwrap(), 
                &wl_mint
            );
            println!("{}", nft_deposit_associated_token_address);
            
            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));                             // signer, writeable
            accounts.push(AccountMeta::new_readonly(mint_id.pubkey(), false));                      // not signer, readonly
            accounts.push(AccountMeta::new_readonly(mint_config_pda_derived, false));       // not signer, writable
            accounts.push(AccountMeta::new(mint_counter_pda_derived, false));               // not signer, writeable
            accounts.push(AccountMeta::new(Pubkey::from_str(&mint_config_parsed.sol_deposit).unwrap(), false));// not signer, writable

            accounts.push(AccountMeta::new(new_mint.pubkey(), true));                               // signer, writeable
            accounts.push(AccountMeta::new(new_mint_associated_token_address, false));      // not signer, writeable
            accounts.push(AccountMeta::new(new_mint_metadata_key, false));                   // not signer, writeable
            accounts.push(AccountMeta::new_readonly(rent_sysvar_pubkey, false));                    // not signer, readonly
            accounts.push(AccountMeta::new_readonly(token_program_pubkey, false));                  // not signer, readonly
            accounts.push(AccountMeta::new_readonly(token_metadata_program_pubkey, false));         // not signer, readonly
            accounts.push(AccountMeta::new_readonly(associated_token_program_pubkey, false));       // not signer, readonly
            accounts.push(AccountMeta::new_readonly(system_program_pubkey, false));                 // not signer, readonly

            accounts.push(AccountMeta::new(wl_user_associated_token_account, false)); // not signer, readonly
            accounts.push(AccountMeta::new_readonly(wl_mint, false));                       // not signer, readonly
            accounts.push(AccountMeta::new_readonly(wl_pda, false));                        // not signer, readonly
            accounts.push(AccountMeta::new_readonly(Pubkey::from_str(&mint_config_parsed.phases[0].clone().whitelist_id.unwrap()).unwrap(), false));                        // not signer, readonly
            accounts.push(AccountMeta::new(Pubkey::from_str(&mint_config_parsed.nft_deposit).unwrap(), false));// not signer, writable
            accounts.push(AccountMeta::new(nft_deposit_associated_token_address, false));    // not signer, writable
 
 
            call_contract.contract_instruction = unlock_proto::ContractInstruction::Mint as i32;
            call_contract.mint_config_pda_bump = Some(vec![mint_config_pda_bump]);
            call_contract.wl_bump = Some(vec![wl_pda_bump]);
            call_contract.encode(&mut instr_buf)?;

            let transaction = Transaction::new_signed_with_payer(
                &[Instruction::new_with_bytes(
                    mint_program_pubkey,
                    &instr_buf.clone().as_slice(),
                    accounts,
                )],
                Some(&my_keypair.pubkey()),
                &[&my_keypair, &new_mint],
                rpc_client.get_latest_blockhash().await?,
            );

            let sent_tx = rpc_client.send_and_confirm_transaction_with_spinner(&transaction).await
                .map_err(|e|return anyhow!("messed up mint {:#?}", e))?;

            let mut check = 0;
            loop {
                if let Some(tx_result) = rpc_client.get_signature_status(&sent_tx).await? {
                    tx_result.map_err(|e| return anyhow!("failed to mint....\n{:?}", e))?;
                    let tx_result = rpc_client.get_transaction(&sent_tx, UiTransactionEncoding::Json).await?.transaction.meta.unwrap();
                    println!("{} logs {:#?}", sent_tx, tx_result.log_messages);
                    break
                } else {
                    if check < 10 {
                        check +=1
                    } else {
                        return Err(anyhow!("Failed to verify mint tx"))
                    }
                }
            }
            return Ok(());
        },
        unlock_proto::ContractInstruction::PauseMint => {
            println!("This operation will pause the mint. Are you sure you want to continue? [y,n]");
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .expect("Failed to read input");
        
            println!("{}",answer);
            if answer.replace("\n", "") != "y" || answer == "n" {
                println!("Exiting");
                return Ok(());
            }
            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            accounts.push(AccountMeta::new(mint_id.pubkey(), true));
            accounts.push(AccountMeta::new(mint_config_pda_derived, false));

            call_contract.contract_instruction = unlock_proto::ContractInstruction::PauseMint as i32;
            call_contract.mint_config_pda_bump = Some(vec![mint_config_pda_bump]);

            call_contract.encode(&mut instr_buf)?

        },
        
        unlock_proto::ContractInstruction::AdminCreateMainConfig => {

            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            // accounts.push(AccountMeta::new(main_config_pda_derived, false));
            accounts.push(AccountMeta::new_readonly(system_program::id(), false));

            let mut main_config = unlock_proto::ContractMainConfig::default();
            main_config.contract_admin_pubkeys = vec![
                "CvS3N5Fv17ysJ2oDECUFMtHy84Eja4".into(),
                "CvS3N5Fv17ysJ2oDECUFMtHy84Eja4".into(),
                "CvS3N5Fv17ysJ2oDECUFMtHy84Eja4".into(),
                ];
            main_config.item1 = "item 1 sring".into();
            main_config.item2 = "item 2 sring".into();
            
            let mut main_config_bytes = vec![];
            main_config.clone().encode(&mut main_config_bytes)?;
            call_contract.contract_main_config_bytes = Some(main_config_bytes);
            call_contract.contract_instruction = unlock_proto::ContractInstruction::AdminCreateMainConfig as i32;
            call_contract.encode(&mut instr_buf)?

        },
        unlock_proto::ContractInstruction::AdminUpdateMainConfig => todo!(),
        unlock_proto::ContractInstruction::AdminDeleteMainConfig => {

            accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
            // accounts.push(AccountMeta::new(main_config_pda_derived, false));
            call_contract.contract_instruction = unlock_proto::ContractInstruction::AdminDeleteMainConfig as i32;
            call_contract.encode(&mut instr_buf)?

        },
        unlock_proto::ContractInstruction::AdminReadMainConfig => {

            accounts.push(AccountMeta::new_readonly(my_keypair.pubkey(), true));
            // accounts.push(AccountMeta::new_readonly(main_config_pda_derived, false));
            call_contract.contract_instruction = unlock_proto::ContractInstruction::AdminReadMainConfig as i32;
            call_contract.encode(&mut instr_buf)?

        },
    }
    
    let transaction = Transaction::new_signed_with_payer(
        &[Instruction::new_with_bytes(
            mint_program_pubkey,
            &instr_buf.clone().as_slice(),
            accounts,
        )],
        Some(&my_keypair.pubkey()),
        &[&my_keypair, &mint_id],
        rpc_client.get_latest_blockhash().await?
    );

    let program_interact_tx = match rpc_client.send_and_confirm_transaction_with_spinner(&transaction).await {
        Ok(sig) => sig,
        Err(e) => {
            println!("transaction error {:#?}", e);
            return Err(anyhow!("messed up"))
        }
    };
    println!("transaction to {} sent. Transaction sig: {:#?}", mint_program_pubkey, program_interact_tx);
    let tx_result = rpc_client.get_transaction(&program_interact_tx, UiTransactionEncoding::Json).await?;
    let meta = tx_result.transaction.meta.unwrap();
    println!("{} logs {:#?}", program_interact_tx, meta.log_messages);

    Ok(())
}


pub fn read_keypair_from_file(path: &str) -> Result<Keypair> {
    let keypair = read_keypair_file(path)
        .map_err(|e| return anyhow!("Can't read keyfile\n {}", e.to_string()))?;
    Ok(keypair)
}

pub fn rpc_client_create(_url: String) -> RpcClient {
    // let url_mainnet = "https://api.mainnet-beta.solana.com".to_string();
    let url_devnet = "https://api.devnet.solana.com".to_string();
    let commitment_config = CommitmentConfig::finalized();
    let timeout = Duration::from_secs(50);
    RpcClient::new_with_timeout_and_commitment(
        url_devnet,
        timeout,
        commitment_config,
    )
}

// Loading mint data file.
pub fn load_mint_data(filename: &str) -> Result<Vec<NftData>> {
    let data_json = std::fs::read_to_string(filename)?;
    let data: Vec<NftData> = serde_json::from_str(&data_json)?;
    Ok(data)
}

// Loading mint config file.
pub fn load_mint_config(_filename: &str) -> Result<MintConfigFile> {
    let config_json = std::fs::read_to_string("mint_config.json")?;
    let config: MintConfigFile = serde_json::from_str(&config_json)?;
    Ok(config)
}

#[allow(dead_code, unused_variables, unused_features)]

#[derive(Debug, Deserialize, Default)]
pub struct MintConfigFile {
    mint_pubkey: Option<String>,
    mint_admin_pubkey: String,
    sol_deposit: String,
    nft_deposit: String,
    counter: Option<u32>,
    upload_counter: Option<u32>,
    pause_mint: bool,
    phases: Vec<MintPhase>,
    nft_amount: Option<u32>,
    nft_price_lamports: u64,
    symbol: Option<String>,
    creators: Vec<NftCreator>,
    seller_fee_basis_points: Option<u32>,
    update_authority: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MintPhase {
    phase_type: i32,
    start_timestamp: i32,
    end_timestamp: Option<i32>,
    whitelist_id: Option<String>,
    per_token_capacity: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NftData {
    name: String,
    uri: String
}

#[derive(Debug, Deserialize)]
pub struct NftCreator {
    address: String,
    share: u32,
}

fn write_keypair_to_file(keypair: &Keypair, filename: &str) -> Result<()> {

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(false)
        .open(format!("mint_id_keypair_{}.json", filename))?;
        
    // file.write_all(format!("{:?}", decoded).as_bytes())?;
    file.write_all(&format!("{:?}",keypair.to_bytes()).as_bytes())?;
    println!("keypair {:?}", keypair.to_bytes());
    Ok(())
}

async fn send_my_data(
    rpc_client: &RpcClient,
    my_keypair: &Keypair,
    mint_id: &Keypair,
    mint_config_pda: &Pubkey,
    mint_program_pubkey: &Pubkey,
    data: Option<&Vec<Vec<u8>>>,
    pdas: Option<Vec<(Pubkey, u8, Vec<u8>, Vec<u8>, Option<(Pubkey, Pubkey)>)>>,
) -> i32 {
    let mut send_results = vec![];
    let mut ftrs = FuturesUnordered::new();
    let mut added_counter = 0;
    let mut failed_counter = 0;
    let start = std::time::Instant::now();
    let max_conn = 7;
    
    if let Some(data) = data {
        for i in 0..max_conn { 
            if let Some(mint_data) = data.get(i) {
                ftrs.push(my_send_transaction_and_confirm(
                    &rpc_client,
                    my_keypair,
                    mint_id,
                    mint_config_pda,
                    mint_program_pubkey,
                    Some(mint_data.clone()),
                    None,
                    ));
                added_counter += 1;
            } else {
                break;
            }
        }
        while let Some(result) = ftrs.next().await {
            if let Some(mint_data) = data.get(added_counter) {
                if ftrs.len() < max_conn {
                    ftrs.push(my_send_transaction_and_confirm(
                        &rpc_client,
                        my_keypair,
                        mint_id,
                        mint_config_pda,
                        mint_program_pubkey,
                        Some(mint_data.clone()),
                        None,
                        ));
                    added_counter += 1;
                }
            }
    
            match result {
                Ok(tx) => {
                    send_results.push(tx);
                },
                Err(e) => {
                    let error_string = e.to_string();
                    println!("Error {}", error_string);
                    failed_counter +=1;
                }
            }
        }
    } 

    if let Some(pdas) = pdas {
        for i in 0..max_conn { 
            if let Some(pda) = pdas.get(i) {
                ftrs.push(my_send_transaction_and_confirm(
                    &rpc_client,
                    my_keypair,
                    mint_id,
                    mint_config_pda,
                    mint_program_pubkey,
                    None,
                    Some(pda.clone()),
                    ));
                added_counter += 1;
            } else {
                break;
            }
        }
        while let Some(result) = ftrs.next().await {
            if let Some(pda) = pdas.get(added_counter) {
                if ftrs.len() < max_conn {
                    ftrs.push(my_send_transaction_and_confirm(
                        &rpc_client,
                        my_keypair,
                        mint_id,
                        mint_config_pda,
                        mint_program_pubkey,
                        None,
                        Some(pda.clone()),
                        ));
                    added_counter += 1;
                }
            }
    
            match result {
                Ok(tx) => {
                    send_results.push(tx);
                },
                Err(e) => {
                    let error_string = e.to_string();
                    println!("Error {}", error_string);
                    failed_counter +=1;
                }
            }
        }
    }
    println!("Runtime {}s", start.elapsed().as_secs());
    
    failed_counter
}

async fn my_send_transaction_and_confirm(
    rpc_client: &RpcClient,
    my_keypair: &Keypair,
    mint_id: &Keypair,
    mint_config_pda: &Pubkey,
    mint_program_pubkey: &Pubkey,
    mint_data: Option<Vec<u8>>,
    pdas: Option<(Pubkey, u8, Vec<u8>, Vec<u8>, Option<(Pubkey, Pubkey)>)>,
) -> Result<String> {

    let mut instr_buf = vec![];
    let mut accounts = vec![];
    let mut call_contract = unlock_proto::CallContract::default();

    accounts.push(AccountMeta::new(my_keypair.pubkey(), true));
    accounts.push(AccountMeta::new(mint_id.pubkey(), true));

    if let Some(mint_data) = mint_data {
        accounts.push(AccountMeta::new(mint_config_pda.clone(), false));
        call_contract.contract_instruction = unlock_proto::ContractInstruction::AddMintData as i32;
        call_contract.mint_data_bytes = Some(mint_data);
        call_contract.encode(&mut instr_buf)?;
    }

    if let Some((pda, pda_bump, mint, wl_id, wl_take)) = pdas {

        
        accounts.push(AccountMeta::new(pda, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));

        call_contract.contract_instruction = unlock_proto::ContractInstruction::CreateMintWhitelist as i32;
        call_contract.wl_bump = Some(vec![pda_bump]);
        call_contract.wl_mint = Some(mint.clone());
        call_contract.wl_id = Some(wl_id);
        if let Some((ata_pubkey, deposit_pubkey)) = wl_take {
            println!("ata pubkey {}", ata_pubkey);
            println!("deposit pubkey {}", deposit_pubkey);
            println!("wl mint {}", Pubkey::new(&mint));
            accounts.push(AccountMeta::new(ata_pubkey, false));
            accounts.push(AccountMeta::new(Pubkey::new(&mint), false));
            accounts.push(AccountMeta::new(deposit_pubkey, false));
            accounts.push(AccountMeta::new_readonly(Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(), false));                  // not signer, readonly
            accounts.push(AccountMeta::new_readonly(sysvar::rent::id(), false));                  // not signer, readonly
            accounts.push(AccountMeta::new_readonly(spl_associated_token_account::id(), false));                  // not signer, readonly

            call_contract.wl_take_ata_create = Some(ata_pubkey.to_bytes().to_vec());
        }
        call_contract.encode(&mut instr_buf)?;
    }

    for _ in 0..10 {
        let transaction = Transaction::new_signed_with_payer(
            &[Instruction::new_with_bytes(
                mint_program_pubkey.clone(),
                &instr_buf.clone().as_slice(),
                accounts.clone(),
            )],
            Some(&my_keypair.pubkey()),
            &[my_keypair, mint_id],
            rpc_client.get_latest_blockhash().await?,
        );
    
        let program_interact_tx = match rpc_client.send_transaction(&transaction).await {
            Ok(sig) => sig,
            Err(e) => {
                println!("transaction error {:#?}", e);
                tokio::time::sleep(Duration::from_millis(1000)).await;
                continue;
                
            }
        };
        
        let tx_result = my_get_transaction(rpc_client, program_interact_tx).await?;
        if let Some(meta) = tx_result.transaction.meta {
            if let Some(err) = meta.err {
                return Err(anyhow!(err.to_string()));
            } else {
               return Ok(format!("{} ok", program_interact_tx));
            }
        }
    }

    // transaction failed to send 10 times, it's not gonna send anymore
    return Err(anyhow!("messed up"))
    
}

async fn my_get_transaction(rpc_client: &RpcClient, sign: Signature) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
    let transaction_config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
    };
    let mut try_counter = 0;
    let encoded_transaction = loop {
        if try_counter >=10 {
            return Err(anyhow!("Failed to get transaction status tx {}", &sign));
        }
        let trx = match rpc_client.get_transaction_with_config(&sign, transaction_config).await {
            Ok(transaction) => {
                println!("{} ok", sign);
                transaction
            },
            Err(_) => {
                // println!("solana api error {}", e.to_string());
                tokio::time::sleep(Duration::from_millis(1000)).await;
                try_counter += 1;
                continue;
            }
        };
        break(trx);
    };
    Ok(encoded_transaction)
}

fn read_file_to_vec(filename: &str) -> Result<Vec<String>> {

    let mut contents = Vec::new();
    if filename.ends_with(".json") {
        let contents_str = std::fs::read_to_string(filename)?;
        contents = serde_json::from_str(&contents_str)?;
    } else {
        let file = std::fs::File::open(filename)?;
        let buf_reader = BufReader::new(file).lines();
        for line in buf_reader {
            contents.push(line?);
        }
    }
    Ok(contents)
}