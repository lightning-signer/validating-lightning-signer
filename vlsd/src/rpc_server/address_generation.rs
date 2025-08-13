use anyhow::Result;
use lightning_signer::bitcoin::bip32::{ChildNumber, DerivationPath};
use lightning_signer::bitcoin::Address;
use lightning_signer::hex;
use lightning_signer::node::Node;
use lightning_signer::util::status::Status;
use lightning_signer::wallet::Wallet;
use std::str::FromStr;

use super::model::{AddressInfo, AddressType};

// The default number of addresses to search for if no limit is specified.
pub const DEFAULT_GAP_LIMIT: u32 = 20;
// The default number of addresses to generate if not specified in request
pub const DEFAULT_ADDRESS_COUNT: u32 = 10;

/// Generates a list of addresses based on the provided types and
/// `count` with base derivation path set to `path` and starting from `start`.
///
/// This function creates addresses for external (receive) chains according to the
/// specified address types (BIPs).
pub fn generate_addresses(
    node: &Node,
    address_type: AddressType,
    start: u32,
    count: u32,
    path: &DerivationPath,
) -> Result<Vec<AddressInfo>, Status> {
    let mut addresses = Vec::new();

    for i in start..(start + count) {
        let extended_index = ChildNumber::from(i);
        let extended_path = path.extend(extended_index);
        let address_info = generate_single_address(node, &extended_path, address_type)?;
        addresses.push(address_info);
    }

    Ok(addresses)
}

/// Generates a single address for a given index and address type.
pub fn generate_single_address(
    node: &Node,
    path: &DerivationPath,
    addr_type: AddressType,
) -> Result<AddressInfo, Status> {
    let address = get_address_for_type(node, path, addr_type)?;
    let script_pubkey_hex = hex::encode(address.script_pubkey().as_bytes());

    Ok(AddressInfo {
        address: address.to_string(),
        path: path.to_string(),
        address_type: addr_type.clone(),
        script_pubkey: script_pubkey_hex,
    })
}

/// Verifies if an address belongs to the wallet, with discovery capabilities.
///
/// Searches through standard derivation paths for each address type
/// starting from `start` index up to the specified `limit` with base derivation path set to `path`.
pub fn verify_address_derivation(
    node: &Node,
    address_str: &str,
    start: u32,
    limit: u32,
    path: &DerivationPath,
) -> Result<Option<AddressInfo>, Status> {
    let address = Address::from_str(address_str)
        .map_err(|e| Status::invalid_argument(format!("invalid address: {}", e)))?
        .require_network(node.network())
        .map_err(|e| Status::invalid_argument(format!("address on wrong network: {}", e)))?;

    let addr_type: AddressType = address
        .address_type()
        .ok_or(Status::invalid_argument("valid address should be passed in request"))?
        .into();
    for i in start..(start + limit) {
        let extended_index = ChildNumber::from(i);
        let extended_path = path.extend(extended_index);
        if let Ok(address_info) = generate_single_address(node, &extended_path, addr_type) {
            if address_info.address == address_str {
                return Ok(Some(address_info));
            }
        }
    }

    Ok(None)
}

/// Helper to get a Bitcoin address from the node for a specific index and type.
fn get_address_for_type(
    node: &Node,
    derivation_path: &DerivationPath,
    addr_type: AddressType,
) -> Result<Address, Status> {
    match addr_type {
        AddressType::Wrapped => node.get_wrapped_address(&derivation_path),
        AddressType::Native => node.get_native_address(&derivation_path),
        AddressType::Taproot => node.get_taproot_address(&derivation_path),
    }
}
