fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .format(false)
        .type_attribute(".", "#[derive(serde::Serialize)]")
        // WARNING - we serialize *ALL* fields named "data" presuming they are Vec<u8>
        .field_attribute("data", "#[serde(serialize_with = \"crate::util::as_hex\")]")
        // All other protobuf "bytes" fields need to be listed below.
        .field_attribute(
            "ReadyChannelRequest.holder_shutdown_script",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "ReadyChannelRequest.counterparty_shutdown_script",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignChannelAnnouncementRequest.channel_announcement",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignNodeAnnouncementRequest.node_announcement",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignChannelUpdateRequest.channel_update",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignInvoiceRequest.data_part",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignMessageRequest.message",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "Transaction.raw_tx_bytes",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute("TxOut.pk_script", "#[serde(serialize_with = \"crate::util::as_hex\")]")
        .field_attribute(
            "InputDescriptor.redeem_script",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "OutputDescriptor.witscript",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "SignMutualCloseTxPhase2Request.counterparty_shutdown_script",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute(
            "HTLCInfo.payment_hash",
            "#[serde(serialize_with = \"crate::util::as_hex\")]",
        )
        .field_attribute("Outpoint.txid", "#[serde(serialize_with = \"crate::util::as_hex\")]")
        .field_attribute(
            "SignCounterpartyCommitmentTxRequest.payment_hashes",
            "#[serde(serialize_with = \"crate::util::as_hex_vec\")]",
        )
        .field_attribute(
            "ValidateHolderCommitmentTxRequest.payment_hashes",
            "#[serde(serialize_with = \"crate::util::as_hex_vec\")]",
        )
        .field_attribute(
            "SignHolderCommitmentTxRequest.payment_hashes",
            "#[serde(serialize_with = \"crate::util::as_hex_vec\")]",
        )
        .out_dir("src/grpc")
        .compile(&["src/grpc/remotesigner.proto"], &["src/grpc"])?;
    Ok(())
}
