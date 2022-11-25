#[cfg(test)]
mod tests {
    use crate::channel::ChannelId;
    use bitcoin;
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Script;
    use lightning::ln::chan_utils::ChannelPublicKeys;
    use test_log::test;

    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));

    fn check_basepoints(basepoints: &ChannelPublicKeys) {
        let points = [
            basepoints.funding_pubkey,
            basepoints.revocation_basepoint,
            basepoints.payment_point,
            basepoints.delayed_payment_basepoint,
            basepoints.htlc_basepoint,
        ]
        .iter()
        .map(|p| p.serialize().to_vec().to_hex())
        .collect::<Vec<_>>();

        assert_eq!(
            points,
            vec![
                "038ad68f4825b5b9db24e274d79b26887b46a70b8a16a720d69e363c858cd7907e",
                "02662e5e76a56a9dca49130bfd6990d9fc71501c4b7d799d253bbd365b72ac72d8",
                "03ee671ff5bf6450b8b3cad584b49a68265978f9b2bd5f7ff144eb6972dd6bd35a",
                "022e399383d20b0157178d8927a102829ddedd12cea977527afce1d374dbedd553",
                "02e25506cc6c4b9f888d682487d3b8d969a56e13b623da743d9c9d56c763931c49"
            ]
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
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());
        let status: Result<_, Status> =
            node.ready_channel(channel_id_x.clone(), None, make_test_channel_setup(), &vec![]);
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
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");

        // Issue ready_channel w/ an alternate id.
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());
        node.ready_channel(
            channel_id.clone(),
            Some(channel_id_x.clone()),
            make_test_channel_setup(),
            &vec![],
        )
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
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

        let status: Result<(), Status> = node.with_ready_channel(&channel_id_x, |_chan| Ok(()));
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "no such channel");
    }

    #[test]
    fn channel_stub_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");

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
            hex_decode("2f87fef68f2bafdb3c6425921894af44da9a984075c70c7ba31ccd551b3585db")
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
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let result = node.new_channel(Some(channel_id), &node);
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
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        let holder_shutdown_key_path = vec![];
        let result = node.ready_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_failed_precondition_err!(
            result,
            "policy failure: validate_ready_channel: \
             holder_shutdown_script is not in wallet or allowlist"
        );
    }

    #[test]
    fn ready_channel_holder_shutdown_script_in_allowlist() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        node.add_allowlist(&vec!["tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string()])
            .expect("added allowlist");
        let holder_shutdown_key_path = vec![];
        let result = node.ready_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_status_ok!(result);
    }

    #[test]
    fn ready_channel_holder_shutdown_script_in_wallet() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014b76dd61e41b5ef052af21cda3260888c070bb9af"));
        let holder_shutdown_key_path = vec![7];
        let result = node.ready_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_status_ok!(result);
    }
}
