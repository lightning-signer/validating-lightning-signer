#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Script;
    use lightning::ln::chan_utils::ChannelPublicKeys;
    use test_env_log::test;

    use crate::channel::channel_nonce_to_id;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));

    fn check_basepoints(basepoints: &ChannelPublicKeys) {
        assert_eq!(
            basepoints.funding_pubkey.serialize().to_vec().to_hex(),
            "02868b7bc9b6d307509ed97758636d2d3628970bbd3bd36d279f8d3cde8ccd45ae"
        );
        assert_eq!(
            basepoints.revocation_basepoint.serialize().to_vec().to_hex(),
            "02982b69bb2d70b083921cbc862c0bcf7761b55d7485769ddf81c2947155b1afe4"
        );
        assert_eq!(
            basepoints.payment_point.serialize().to_vec().to_hex(),
            "026bb6655b5e0b5ff80d078d548819f57796013b09de8085ddc04b49854ae1e483"
        );
        assert_eq!(
            basepoints.delayed_payment_basepoint.serialize().to_vec().to_hex(),
            "0291dfb201bc87a2da8c7ffe0a7cf9691962170896535a7fd00d8ee4406a405e98"
        );
        assert_eq!(
            basepoints.htlc_basepoint.serialize().to_vec().to_hex(),
            "02c0c8ff7278e50bd07d7b80c109621d44f895e216400a7e95b09f544eb3fafee2"
        );
    }

    #[test]
    fn ready_channel_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_ready_channel(&channel_id, |c| {
            let params = c.keys.get_channel_parameters();
            assert!(params.is_outbound_from_holder);
            assert_eq!(params.holder_selected_contest_delay, 6);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn ready_channel_not_exist_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);
        let status: Result<_, Status> =
            node.ready_channel(channel_id_x, None, make_test_channel_setup(), &vec![]);
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel does not exist: {}", &channel_id_x));
    }

    #[test]
    fn get_channel_basepoints_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let basepoints =
            node.with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints())).unwrap();

        check_basepoints(&basepoints);
    }

    #[test]
    fn ready_channel_dual_channelid_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        node.new_channel(Some(channel_id), Some(channel_nonce), &node).expect("new_channel");

        // Issue ready_channel w/ an alternate id.
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);
        node.ready_channel(channel_id, Some(channel_id_x), make_test_channel_setup(), &vec![])
            .expect("ready_channel");

        // Original channel_id should work with_ready_channel.
        let val = node.with_ready_channel(&channel_id, |_chan| Ok(42)).expect("u32");
        assert_eq!(val, 42);

        // Alternate channel_id should work with_ready_channel.
        let val_x = node.with_ready_channel(&channel_id_x, |_chan| Ok(43)).expect("u32");
        assert_eq!(val_x, 43);
    }

    #[test]
    fn with_ready_channel_not_exist_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);

        let status: Result<(), Status> = node.with_ready_channel(&channel_id_x, |_chan| Ok(()));
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "no such channel");
    }

    #[test]
    fn channel_stub_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        node.new_channel(Some(channel_id), Some(channel_nonce), &node).expect("new_channel");

        // with_ready_channel should return not ready.
        let result: Result<(), Status> = node.with_ready_channel(&channel_id, |_chan| {
            assert!(false); // shouldn't get here
            Ok(())
        });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel not ready: {}", TEST_CHANNEL_ID[0]),);

        let _: Result<(), Status> = node.with_channel_base(&channel_id, |base| {
            // get_per_commitment_point for the first commitment should work.
            let result = base.get_per_commitment_point(0);
            assert!(result.is_ok());

            // get_per_commitment_point for future commit_num should policy-fail.
            assert_failed_precondition_err!(
                base.get_per_commitment_point(1),
                "policy failure: channel stub can only return point for commitment number zero"
            );

            // get_per_commitment_secret never works for a stub.
            assert_failed_precondition_err!(
                base.get_per_commitment_secret(0),
                "policy failure: channel stub cannot release commitment secret"
            );

            Ok(())
        });

        let basepoints =
            node.with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints())).unwrap();
        // get_channel_basepoints should work.
        check_basepoints(&basepoints);

        // check_future_secret should work.
        let n: u64 = 10;
        let suggested = SecretKey::from_slice(
            hex_decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let correct = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n, &suggested))
            .unwrap();
        assert_eq!(correct, true);

        let notcorrect = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n + 1, &suggested))
            .unwrap();
        assert_eq!(notcorrect, false);
    }

    #[ignore] // Ignore this test while we allow extra NewChannel calls.
    #[test]
    fn node_new_channel_already_exists_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // Try and create the channel again.
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        let result = node.new_channel(Some(channel_id), Some(channel_nonce), &node);
        let err = result.err().unwrap();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel already exists: {}", TEST_CHANNEL_ID[0]));
    }

    #[test]
    fn ready_channel_already_ready_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // Trying to ready it again should fail.
        let result = node.ready_channel(channel_id, None, make_test_channel_setup(), &vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel already ready: {}", TEST_CHANNEL_ID[0]));
    }

    #[test]
    fn ready_channel_unknown_holder_shutdown_script() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        node.new_channel(Some(channel_id), Some(channel_nonce), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        let holder_shutdown_key_path = vec![];
        assert_failed_precondition_err!(
            node.ready_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path),
            "policy failure: validate_ready_channel: \
             holder_shutdown_script is not in wallet or allowlist"
        );
    }

    #[test]
    fn ready_channel_holder_shutdown_script_in_allowlist() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        node.new_channel(Some(channel_id), Some(channel_nonce), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        node.add_allowlist(&vec!["tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string()])
            .expect("added allowlist");
        let holder_shutdown_key_path = vec![];
        assert_status_ok!(node.ready_channel(
            channel_id,
            None,
            setup.clone(),
            &holder_shutdown_key_path
        ));
    }

    #[test]
    fn ready_channel_holder_shutdown_script_in_wallet() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        node.new_channel(Some(channel_id), Some(channel_nonce), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014b76dd61e41b5ef052af21cda3260888c070bb9af"));
        let holder_shutdown_key_path = vec![7];
        assert_status_ok!(node.ready_channel(
            channel_id,
            None,
            setup.clone(),
            &holder_shutdown_key_path
        ));
    }
}
