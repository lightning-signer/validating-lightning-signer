//! Validating Lightning Signer integration

use crate::util::Shutter;
use crate::{hex_utils, DynSigner, SpendableKeysInterface};
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{ecdh::SharedSecret, All, PublicKey, Scalar, Secp256k1};
use bitcoin::{Address, Network, Transaction, TxOut};
use lightning::ln::msgs::DecodeError;
use lightning::ln::msgs::UnsignedGossipMessage;
use lightning::ln::script::ShutdownScript;
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::sign::{Recipient, SpendableOutputDescriptor};
use lightning_signer::bitcoin::ScriptBuf;
use lightning_signer::lightning::ln::inbound_payment::ExpandedKey;
use lightning_signer::lightning_invoice::RawBolt11Invoice;
use lightning_signer::node::NodeConfig as SignerNodeConfig;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::simple_validator::{
    make_default_simple_policy, SimpleValidatorFactory,
};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::loopback::LoopbackSignerKeysInterface;
use lightning_signer::{bitcoin, lightning};
use log::info;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;
use vls_frontend::Frontend;
use vls_persist::kvv::redb::RedbKVVStore;
use vls_persist::kvv::{JsonFormat, KVVPersister};
use vls_proxy::nodefront::SignerFront;
use vls_proxy::vls_frontend;
use vls_proxy::vls_frontend::frontend::DummySourceFactory;

struct Adapter {
    inner: LoopbackSignerKeysInterface,
    sweep_address: Address,
}

impl SignerProvider for Adapter {
    type EcdsaSigner = DynSigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        self.inner.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        let inner = self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id);
        DynSigner { inner: Box::new(inner) }
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        let inner = self.inner.read_chan_signer(reader)?;

        Ok(DynSigner::new(inner))
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        self.inner.get_destination_script(channel_keys_id)
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        self.inner.get_shutdown_scriptpubkey()
    }
}

impl EntropySource for Adapter {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }
}

impl NodeSigner for Adapter {
    fn get_inbound_payment_key(&self) -> ExpandedKey {
        self.inner.get_inbound_payment_key()
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => panic!("phantom node not supported"),
        }
        Ok(self.inner.node_id.clone())
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        self.inner.ecdh(recipient, other_key, tweak)
    }

    fn sign_invoice(
        &self,
        raw_invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.inner.sign_invoice(raw_invoice, recipient)
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        self.inner.sign_gossip_message(msg)
    }

    fn sign_bolt12_invoice(
        &self,
        _invoice: &lightning::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        todo!()
    }
}

impl SpendableKeysInterface for Adapter {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        _secp_ctx: &Secp256k1<All>,
    ) -> anyhow::Result<Transaction> {
        let tx = self
            .inner
            .spend_spendable_outputs(
                descriptors,
                outputs,
                change_destination_script,
                feerate_sat_per_1000_weight,
            )
            .map_err(|()| anyhow::anyhow!("failed in spend_spendable_outputs"))?;
        info!("spend spendable {}", bitcoin::consensus::encode::serialize_hex(&tx));
        Ok(tx)
    }

    fn get_sweep_address(&self) -> Address {
        self.sweep_address.clone()
    }
}

pub(crate) fn make_signer(
    shutter: Shutter,
    network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
    bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);
    let signer_path = format!("{}/signer", ldk_data_dir);
    let persister = Arc::new(KVVPersister(RedbKVVStore::new(&signer_path), JsonFormat));
    let seed_persister = Arc::new(FileSeedPersister::new(&signer_path));

    // Create a lenient invoice validator
    let mut lenient_policy = make_default_simple_policy(Network::Testnet);
    let lenient_filter = PolicyFilter {
        rules: vec![FilterRule::new_warn("policy-commitment-htlc-routing-balance")],
    };
    lenient_policy.filter.merge(lenient_filter);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(lenient_policy));
    let starting_time_factory = ClockStartingTimeFactory::new();
    let clock = Arc::new(StandardClock());
    let trusted_oracle_pubkeys = vec![];
    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys,
    };
    // FIXME use Node directly - requires rework of LoopbackSignerKeysInterface in the vls crate
    let signer = Arc::new(MultiSigner::new(services));

    let source_factory = Arc::new(DummySourceFactory::new(ldk_data_dir, network));
    let frontend = Frontend::new(
        Arc::new(SignerFront { signer: Arc::clone(&signer), external_persist: None }),
        source_factory,
        bitcoin_rpc_url,
        shutter.signal,
    );
    frontend.start();

    if let Ok(node_id_hex) = fs::read_to_string(node_id_path.clone()) {
        let node_id = PublicKey::from_str(&node_id_hex).unwrap();
        assert!(signer.get_node(&node_id).is_ok());

        let manager = LoopbackSignerKeysInterface { node_id, signer };
        Box::new(Adapter { inner: manager, sweep_address })
    } else {
        let node_config = SignerNodeConfig {
            network,
            key_derivation_style: KeyDerivationStyle::Ldk,
            use_checkpoints: true,
            allow_deep_reorgs: false,
        };
        let (node_id, _seed) = signer.new_node(node_config, seed_persister).unwrap();
        fs::write(node_id_path, node_id.to_string()).expect("write node_id");
        let node = signer.get_node(&node_id).unwrap();

        let manager = LoopbackSignerKeysInterface { node_id, signer };

        let shutdown_scriptpubkey: ScriptBuf = manager.get_shutdown_scriptpubkey().unwrap().into();
        let shutdown_address = Address::from_script(&shutdown_scriptpubkey, network)
            .expect("shutdown script must be convertible to address");
        info!(
            "adding shutdown address {} to allowlist for {}",
            shutdown_address,
            hex_utils::hex_str(&node_id.serialize())
        );
        node.add_allowlist(&vec![shutdown_address.to_string()]).expect("add to allowlist");

        Box::new(Adapter { inner: manager, sweep_address })
    }
}
