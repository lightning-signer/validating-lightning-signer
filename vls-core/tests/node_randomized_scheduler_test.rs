// Generate a test run from queues of random operations
#[test]
#[cfg(feature = "shuttle")]
fn test_node_with_random_operations() {
    use lightning_signer::channel::ChannelId;
    use lightning_signer::node::Node;
    use lightning_signer::util::status::Status;
    use lightning_signer::util::test_utils::make_node;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use shuttle::sync::{Arc, Mutex};
    use shuttle::thread;

    struct TestState {
        channel_ids: Mutex<Vec<ChannelId>>,
    }

    impl TestState {
        fn new() -> Self {
            TestState { channel_ids: Mutex::new(Vec::new()) }
        }

        fn add_channel(&self, channel_id: ChannelId) {
            let mut ids = self.channel_ids.lock().unwrap();
            ids.push(channel_id);
        }

        fn get_channel_id(&self, index: usize) -> Option<ChannelId> {
            let ids = self.channel_ids.lock().unwrap();
            ids.get(index).cloned()
        }

        fn remove_channel_id(&self, index: usize) -> Option<ChannelId> {
            let mut ids = self.channel_ids.lock().unwrap();
            if index < ids.len() {
                Some(ids.remove(index))
            } else {
                None
            }
        }

        fn channel_count(&self) -> usize {
            let ids = self.channel_ids.lock().unwrap();
            ids.len()
        }
    }

    // Operations to perform in threads
    #[derive(Clone, Debug)]
    enum Operation {
        CreateChannel,
        GetChannel(usize),
        ForgetChannel(usize),
        GetAllChannels,
    }

    fn perform_operation(
        node: &Arc<Node>,
        state: &Arc<TestState>,
        op: &Operation,
    ) -> Result<(), Status> {
        match op {
            Operation::CreateChannel => {
                let (channel_id, _) = node.new_channel_with_random_id(node)?;
                state.add_channel(channel_id);
                Ok(())
            }
            Operation::GetChannel(idx) => {
                let channel_count = state.channel_count();
                if channel_count > 0 {
                    let idx = idx % channel_count;
                    if let Some(channel_id) = state.get_channel_id(idx) {
                        let channel = node.get_channel(&channel_id)?;
                        // Simulate some work with the channel
                        let _lock = channel.lock().unwrap();
                    }
                }
                Ok(())
            }
            Operation::ForgetChannel(idx) => {
                let channel_count = state.channel_count();
                if channel_count > 0 {
                    let idx = idx % channel_count;
                    if let Some(channel_id) = state.remove_channel_id(idx) {
                        node.forget_channel(&channel_id)?;
                    }
                }
                Ok(())
            }
            Operation::GetAllChannels => {
                // Get all channels and hold the lock briefly
                let _channels = node.get_channels();
                Ok(())
            }
        }
    }

    // Number of operations per thread
    const OPS_PER_THREAD: usize = 32;
    // Number of threads
    const THREAD_COUNT: usize = 4;
    // Use a fixed seed for reproducibility
    const SEED: u64 = 12345;
    let mut rng = StdRng::seed_from_u64(SEED);

    // Generate all operations
    let thread_operations: Vec<Vec<Operation>> = (0..THREAD_COUNT)
        .map(|_| {
            // Generate random operations for this thread
            (0..OPS_PER_THREAD)
                .map(|_| {
                    let op_type = rng.gen_range(0..4);
                    match op_type {
                        0 => Operation::CreateChannel,
                        1 => Operation::GetChannel(rng.gen_range(0..5)),
                        2 => Operation::ForgetChannel(rng.gen_range(0..5)),
                        _ => Operation::GetAllChannels,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // Now use the pre-generated operations in the shuttle check
    shuttle::check_random(
        move || {
            let (_, node, _) = make_node();
            let node = Arc::new(node);
            let state = Arc::new(TestState::new());

            let mut handles = Vec::new();

            for (_, ops) in thread_operations.iter().enumerate() {
                let node_clone = node.clone();
                let state_clone = state.clone();
                let ops = ops.clone(); // Clone the operations for this thread

                let handle = thread::spawn(move || {
                    for op in &ops {
                        let _ = perform_operation(&node_clone, &state_clone, op);
                    }
                });

                handles.push(handle);
            }

            // Wait for all threads to complete
            for handle in handles {
                handle.join().unwrap();
            }
        },
        1000,
    );
}
