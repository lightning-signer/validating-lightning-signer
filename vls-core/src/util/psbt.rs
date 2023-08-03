use crate::io::{Cursor, Read};
use crate::prelude::*;
use alloc::collections::{btree_map, BTreeMap};
use bitcoin::consensus::encode::MAX_VEC_SIZE;
use bitcoin::consensus::{encode, Decodable};
use bitcoin::psbt::{raw, Error, Input, Output, PartiallySignedTransaction};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::Transaction;

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

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
pub struct StreamedPSBT {
    /// The PSBT
    pub psbt: PartiallySignedTransaction,
    /// For each input, whether we know that the TXO is segwit
    pub segwit_flags: Vec<bool>,
}

impl StreamedPSBT {
    pub(crate) fn consensus_decode_global<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<PartiallySignedTransaction, encode::Error> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> =
            Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::consensus_decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSBT_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one unsigned transaction
                                if tx.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);

                                    // Manually deserialized to ensure 0-input
                                    // txs without witnesses are deserialized
                                    // properly.
                                    tx = Some(Transaction {
                                        version: Decodable::consensus_decode(&mut decoder)?,
                                        input: Decodable::consensus_decode(&mut decoder)?,
                                        output: Decodable::consensus_decode(&mut decoder)?,
                                        lock_time: Decodable::consensus_decode(&mut decoder)?,
                                    });

                                    if decoder.position() != vlen as u64 {
                                        return Err(encode::Error::ParseFailed("data not consumed entirely when explicitly deserializing"));
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into());
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into());
                            }
                        }
                        PSBT_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = ExtendedPubKey::decode(&pair.key.key)
                                    .map_err(|_| encode::Error::ParseFailed(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(encode::Error::ParseFailed(
                                        "Incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(&fingerprint[..]), derivation))
                                    .is_some()
                                {
                                    return Err(encode::Error::ParseFailed(
                                        "Repeated global xpub key",
                                    ));
                                }
                            } else {
                                return Err(encode::Error::ParseFailed(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSBT_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(encode::Error::ParseFailed(
                                            "Wrong global version value length (must be 4 bytes)",
                                        ));
                                    }
                                    version = Some(Decodable::consensus_decode(&mut decoder)?);
                                    // We only understand version 0 PSBTs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0.
                                    if version != Some(0) {
                                        return Err(encode::Error::ParseFailed(
                                            "PSBT versions greater than 0 are not supported",
                                        ));
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into());
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into());
                            }
                        }
                        PSBT_GLOBAL_PROPRIETARY => match proprietary
                            .entry(raw::ProprietaryKey::try_from(pair.key.clone())?)
                        {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(Error::DuplicateKey(pair.key).into()),
                        },
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(k) =>
                                return Err(Error::DuplicateKey(k.key().clone()).into()),
                        },
                    }
                }
                Err(encode::Error::Psbt(Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        if let Some(tx) = tx {
            let psbt = PartiallySignedTransaction {
                unsigned_tx: tx,
                version: version.unwrap_or(0),
                xpub: xpub_map,
                proprietary,
                unknown: unknowns,
                inputs: vec![],
                outputs: vec![],
            };
            Ok(psbt)
        } else {
            Err(Error::MustHaveUnsignedTx.into())
        }
    }
}

impl Decodable for StreamedPSBT {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let magic: [u8; 4] = Decodable::consensus_decode(r)?;

        if *b"psbt" != magic {
            return Err(Error::InvalidMagic.into());
        }

        if 0xff_u8 != u8::consensus_decode(r)? {
            return Err(Error::InvalidSeparator.into());
        }

        let mut global = Self::consensus_decode_global(r)?;
        Self::unsigned_tx_checks(&global)?;

        let mut segwit_flags: Vec<bool> = Vec::with_capacity(global.unsigned_tx.input.len());

        let inputs: Vec<Input> = {
            let inputs_len: usize = global.unsigned_tx.input.len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for ind in 0..inputs_len {
                let mut input: Input = Decodable::consensus_decode(r)?;

                // take the non_witness_utxo from the input and summarize it
                if let Some(input_tx) = input.non_witness_utxo.take() {
                    let prevout = global.unsigned_tx.input[ind].previous_output;
                    // check if the input txid matched the psbt tx input txid
                    if input_tx.txid() != prevout.txid {
                        return Err(Error::MissingUtxo.into());
                    }
                    // check if the matching output exists
                    if input_tx.output.len() <= prevout.vout as usize {
                        return Err(Error::MissingUtxo.into());
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
                            // TODO kinda overloading this error
                            return Err(Error::MissingUtxo.into());
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

            for _ in 0..outputs_len {
                outputs.push(Decodable::consensus_decode(r)?);
            }

            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(StreamedPSBT { psbt: global, segwit_flags })
    }
}

impl StreamedPSBT {
    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(psbt: &PartiallySignedTransaction) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use crate::util::psbt::StreamedPSBT;
    use bitcoin::consensus::{deserialize, encode::serialize_hex};
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::psbt::{Input, Output, PartiallySignedTransaction};
    use bitcoin::*;
    use std::collections::BTreeMap;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));
    macro_rules! hex_psbt {
        ($s:expr) => {
            deserialize::<PartiallySignedTransaction>(&<Vec<u8> as FromHex>::from_hex($s).unwrap())
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

        assert_eq!(serialize_hex(&unserialized), base16str);
        assert_eq!(unserialized, hex_psbt!(base16str).unwrap());
        let streamed = hex_streamed!(base16str).unwrap();
        assert_eq!(streamed.segwit_flags, vec![false]);
        assert_eq!(
            streamed.psbt.inputs[0].witness_utxo,
            Some(TxOut {
                value: 200000000,
                script_pubkey: hex_script!("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"),
            })
        );
        assert_eq!(streamed.psbt.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let unserialized = make_psbt(input_tx);

        assert!(unserialized.inputs[0].witness_utxo.is_none());
        let serialized = serialize_hex(&unserialized);
        let streamed = hex_streamed!(&serialized).unwrap();

        assert_eq!(streamed.segwit_flags, vec![true]);
        assert_eq!(
            streamed.psbt.inputs[0].witness_utxo,
            Some(TxOut { value: 200000000, script_pubkey: output_script })
        );
        assert_eq!(streamed.psbt.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit_with_utxo() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let mut unserialized = make_psbt(input_tx);
        unserialized.inputs[0].witness_utxo =
            Some(TxOut { value: 200000000, script_pubkey: output_script.clone() });
        let serialized = serialize_hex(&unserialized);
        let streamed = hex_streamed!(&serialized).unwrap();

        assert_eq!(streamed.segwit_flags, vec![true]);
        assert_eq!(
            streamed.psbt.inputs[0].witness_utxo,
            Some(TxOut { value: 200000000, script_pubkey: output_script })
        );
        assert_eq!(streamed.psbt.extract_tx(), unserialized.extract_tx());
    }

    #[test]
    fn segwit_with_bad_utxo() {
        let mut input_tx = make_input_tx();
        let output_script = hex_script!("0014be18d152a9b012039daf3da7de4f53349eecb985");
        input_tx.output[0].script_pubkey = output_script.clone();

        let mut unserialized = make_psbt(input_tx);
        unserialized.inputs[0].witness_utxo =
            Some(TxOut { value: 200000001, script_pubkey: output_script.clone() });
        let serialized = serialize_hex(&unserialized);
        assert!(hex_streamed!(&serialized).is_err());
    }

    fn make_psbt(input_tx: Transaction) -> PartiallySignedTransaction {
        let unserialized = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: PackedLockTime(1257139),
                input: vec![TxIn {
                    previous_output: OutPoint { txid: input_tx.txid(), vout: 0 },
                    script_sig: Script::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                output: vec![
                    TxOut {
                        value: 99999699,
                        script_pubkey: hex_script!(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
                        ),
                    },
                    TxOut {
                        value: 100000000,
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
            version: 1,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hex(
                        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                    ).unwrap(),
                    vout: 1,
                },
                script_sig: hex_script!("160014be18d152a9b012039daf3da7de4f53349eecb985"),
                sequence: Sequence::MAX,
                witness: Witness::from_vec(vec![
                    Vec::from_hex("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01").unwrap(),
                    Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").unwrap(),
                ]),
            },
                        TxIn {
                            previous_output: OutPoint {
                                txid: Txid::from_hex(
                                    "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886",
                                ).unwrap(),
                                vout: 1,
                            },
                            script_sig: hex_script!("160014fe3e9ef1a745e974d902c4355943abcb34bd5353"),
                            sequence: Sequence::MAX,
                            witness: Witness::from_vec(vec![
                                Vec::from_hex("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01").unwrap(),
                                Vec::from_hex("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3").unwrap(),
                            ]),
                        }],
            output: vec![
                TxOut {
                    value: 200000000,
                    script_pubkey: hex_script!("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"),
                },
                TxOut {
                    value: 190303501938,
                    script_pubkey: hex_script!("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"),
                },
            ],
        }
    }
}
