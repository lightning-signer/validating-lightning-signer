const SERDE_SERIALIZE_HEX: &'static str = "#[serde(serialize_with = \"crate::util::as_hex\")]";
const SERDE_SERIALIZE_PAYMENT_STATUS: &'static str =
    "#[serde(serialize_with = \"crate::util::as_payment_status\")]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .type_attribute(".", "#[derive(serde::Serialize)]")
        .field_attribute("peer_node_id", SERDE_SERIALIZE_HEX)
        .field_attribute("channel_id", SERDE_SERIALIZE_HEX)
        .field_attribute("node_id", SERDE_SERIALIZE_HEX)
        .field_attribute("best_block_hash", SERDE_SERIALIZE_HEX)
        .field_attribute("payment_hash", SERDE_SERIALIZE_HEX)
        .field_attribute("Payment.status", SERDE_SERIALIZE_PAYMENT_STATUS)
        .compile(&["src/admin/admin.proto"], &["src/admin"])?;

    Ok(())
}
