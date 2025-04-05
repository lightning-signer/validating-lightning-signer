use alloc::vec::Vec;
use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::psbt::{Error, Input, Output, Psbt};
use serde_bolt::bitcoin;
use serde_bolt::io::{self, Read, Write};

#[derive(Debug)]
pub struct PsbtWrapper {
    pub inner: Psbt,
}

impl From<Psbt> for PsbtWrapper {
    fn from(value: Psbt) -> Self {
        Self { inner: value }
    }
}

impl Encodable for PsbtWrapper {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let buffer = self.inner.serialize();
        writer.write(&buffer)
    }
}

impl Decodable for PsbtWrapper {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(reader)
    }

    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let mut buffer = Vec::new();
        r.read_to_limit(&mut buffer, u64::MAX)?;
        let psbt = Psbt::deserialize(&buffer)
            .map_err(|_| encode::Error::ParseFailed("filed to parse the psbt"))?;
        Ok(Self { inner: psbt })
    }
}

/// A PSBT that streams input transactions one at a time instead of
/// holding them in memory.
///
/// The PSBT is still held in memory, but the input transactions
/// are summarized and then discarded.
///
/// `segwit_flags` is a vector of booleans indicating whether we know
/// that the TXO is segwit.
///
/// `psbt.input.witness_utxo` is populated if it is missing, and is otherwise
/// compared with the input transaction to ensure that it matches.
///
/// Note that if the witness flag is false, we didn't validate `witness_utxo`.
///
/// This is useful for the following use cases:
/// - in Lightning, where we must ensure that *all* outputs are segwit, or an attacker
/// might malleate the funding transaction ID.
/// - if we might statelessly sign different inputs at different times, and the attacker
/// might lie about different input amounts at different times (this is fixed in taproot).
#[derive(Debug)]
pub struct StreamedPSBT {
    /// The PSBT
    pub psbt: PsbtWrapper,
    /// For each input, whether we know that the TXO is segwit
    pub segwit_flags: Vec<bool>,
}

impl StreamedPSBT {
    pub fn new(psbt: Psbt) -> Self {
        let segwit_flags = Vec::new();
        Self { psbt: PsbtWrapper::from(psbt), segwit_flags }
    }

    pub fn psbt(&self) -> &Psbt {
        &self.psbt.inner
    }

    pub fn consensus_decode_global<R: Read + ?Sized>(r: &mut R) -> Result<Psbt, encode::Error> {
        // TODO ask rust-bitcoin to implement a more memory efficient serializer / deserializer
        let psbt = PsbtWrapper::consensus_decode_from_finite_reader(r)?;
        Ok(psbt.inner)
    }
}

impl Decodable for StreamedPSBT {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let mut global = Self::consensus_decode_global(r)?;
        Self::unsigned_tx_checks(&global)
            .map_err(|_| encode::Error::ParseFailed("txs checks fails"))?;

        let mut segwit_flags: Vec<bool> = Vec::with_capacity(global.unsigned_tx.input.len());

        let inputs: Vec<Input> = {
            let inputs_len: usize = global.unsigned_tx.input.len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for (ind, mut input) in global.inputs.into_iter().enumerate() {
                // take the non_witness_utxo from the input and summarize it
                if let Some(input_tx) = input.non_witness_utxo.take() {
                    let prevout = global.unsigned_tx.input[ind].previous_output;
                    // check if the input txid matched the psbt tx input txid
                    if input_tx.compute_txid() != prevout.txid {
                        return Err(encode::Error::ParseFailed("missing utxo"));
                    }
                    // check if the matching output exists
                    if input_tx.output.len() <= prevout.vout as usize {
                        return Err(encode::Error::ParseFailed("missing utxo"));
                    }
                    // check if the matching output is a witness output
                    let output = &input_tx.output[prevout.vout as usize];
                    if output.script_pubkey.is_witness_program() {
                        segwit_flags.push(true);
                    } else {
                        segwit_flags.push(false);
                    }

                    if let Some(ref txo) = input.witness_utxo {
                        // ensure that the witness utxo matches the output
                        if txo != output {
                            return Err(encode::Error::ParseFailed("missing utxo"));
                        }
                    } else {
                        input.witness_utxo = Some(output.clone());
                    }
                } else {
                    segwit_flags.push(false);
                }

                inputs.push(input);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = global.unsigned_tx.output.len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for o in global.outputs {
                outputs.push(o);
            }

            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(StreamedPSBT { psbt: PsbtWrapper { inner: global }, segwit_flags })
    }
}

impl StreamedPSBT {
    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(psbt: &Psbt) -> Result<(), Error> {
        for txin in &psbt.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(())
    }
}

impl Encodable for StreamedPSBT {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.psbt.consensus_encode(writer)
    }
}

#[cfg(test)]
mod tests {
    use crate::psbt::PsbtWrapper;

    use super::StreamedPSBT;
    use bitcoin::consensus::{deserialize, encode::serialize_hex};
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::psbt::{Input, Output, Psbt};
    use bitcoin::*;
    use core::str::FromStr;
    use lightning_signer::bitcoin::transaction::Version;
    use serde_bolt::bitcoin;
    use std::collections::BTreeMap;
    use txoo::bitcoin::absolute::Height;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (ScriptBuf::from(hex!($hex))));
    macro_rules! hex_psbt {
        ($s:expr) => {
            deserialize::<PsbtWrapper>(&<Vec<u8> as FromHex>::from_hex($s).unwrap())
        };
    }
    macro_rules! hex_streamed {
        ($s:expr) => {
            deserialize::<StreamedPSBT>(&<Vec<u8> as FromHex>::from_hex($s).unwrap())
        };
    }

    // non-segwit test vector from BIP-174
    #[test]
    fn valid_vector_1() {
        let input_tx = make_input_tx();

        let unserialized = make_psbt(input_tx);

        let base16str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";

        assert_eq!(serialize_hex(&PsbtWrapper { inner: unserialized.clone() }), base16str);
        assert_eq!(unserialized, hex_psbt!(base16str).unwrap().inner);
        let streamed = hex_streamed!(base16str).unwrap();
        assert_eq!(streamed.segwit_flags, vec![false]);
        assert_eq!(
            streamed.psbt.inner.inputs[0].witness_utxo,
            Some(TxOut {
                value: Amount::from_sat(200000000),
                script_pubkey: hex_script!("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"),
            })
        );
        assert_eq!(streamed.psbt.inner.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let unserialized = make_psbt(input_tx);

        assert!(unserialized.inputs[0].witness_utxo.is_none());
        let serialized = serialize_hex(&PsbtWrapper { inner: unserialized.clone() });
        let streamed = hex_streamed!(&serialized).unwrap();

        assert_eq!(streamed.segwit_flags, vec![true]);
        assert_eq!(
            streamed.psbt.inner.inputs[0].witness_utxo,
            Some(TxOut { value: Amount::from_sat(200000000), script_pubkey: output_script })
        );
        assert_eq!(streamed.psbt.inner.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit_with_utxo() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let mut unserialized = make_psbt(input_tx);
        unserialized.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(200000000),
            script_pubkey: output_script.clone(),
        });
        let serialized = serialize_hex(&PsbtWrapper { inner: unserialized.clone() });
        let streamed = hex_streamed!(&serialized).unwrap();

        assert_eq!(streamed.segwit_flags, vec![true]);
        assert_eq!(
            streamed.psbt.inner.inputs[0].witness_utxo,
            Some(TxOut { value: Amount::from_sat(200000000), script_pubkey: output_script })
        );
        assert_eq!(streamed.psbt.inner.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit_with_bad_utxo() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let mut unserialized = make_psbt(input_tx);
        unserialized.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(200000001),
            script_pubkey: output_script.clone(),
        });
        let serialized = serialize_hex(&PsbtWrapper { inner: unserialized.clone() });
        assert!(hex_streamed!(&serialized).is_err());
    }

    fn make_psbt(input_tx: Transaction) -> Psbt {
        let unserialized = Psbt {
            unsigned_tx: Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::Blocks(Height::from_consensus(1257139).unwrap()),
                input: vec![TxIn {
                    previous_output: OutPoint { txid: input_tx.compute_txid(), vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(99999699),
                        script_pubkey: hex_script!(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
                        ),
                    },
                    TxOut {
                        value: Amount::from_sat(100000000),
                        script_pubkey: hex_script!(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
                        ),
                    },
                ],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![Input { non_witness_utxo: Some(input_tx), ..Default::default() }],
            outputs: vec![Output { ..Default::default() }, Output { ..Default::default() }],
        };
        unserialized
    }

    fn make_input_tx() -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                    ).unwrap(),
                    vout: 1,
                },
                script_sig: hex_script!("160014be18d152a9b012039daf3da7de4f53349eecb985"),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&vec![
                    Vec::from_hex("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01").unwrap(),
                    Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").unwrap(),
                ]),
            },
                        TxIn {
                            previous_output: OutPoint {
                                txid: Txid::from_str(
                                    "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886",
                                ).unwrap(),
                                vout: 1,
                            },
                            script_sig: hex_script!("160014fe3e9ef1a745e974d902c4355943abcb34bd5353"),
                            sequence: Sequence::MAX,
                            witness: Witness::from_slice(&vec![
                                Vec::from_hex("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01").unwrap(),
                                Vec::from_hex("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3").unwrap(),
                            ]),
                        }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(200000000),
                    script_pubkey: hex_script!("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"),
                },
                TxOut {
                    value: Amount::from_sat(190303501938),
                    script_pubkey: hex_script!("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"),
                },
            ],
        }
    }
}
