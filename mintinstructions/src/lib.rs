// Include the unlock protobuf module, which is generated from unlock_proto.proto
pub mod unlock_proto {
    include!(concat!(env!("OUT_DIR"), "/unlock_proto.rs"));
}

// /// Call contract instructions
// #[derive(Clone, PartialEq, ::prost::Message)]
// pub struct CallContract {
//     /// Size size = 2;
//     #[prost(string, tag="1")]
//     pub config_account_pubkey: ::prost::alloc::string::String,
// }
// #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
// #[repr(i32)]
// pub enum ContractInstructions {
//     Mint = 0,
//     AdminInitStorage = 1,
//     AdminDeleteStorage = 2,
// }
