use lightning_signer::channel::{ChannelId, ChannelSlot, ChannelStub};
use lightning_signer::node::Node;

pub fn do_with_channel_stub<F: Fn(&ChannelStub) -> ()>(node: &Node, channel_id: &ChannelId, f: F) {
    let guard = node.channels();
    let slot = guard.get(&channel_id).unwrap().lock().unwrap();
    match &*slot {
        ChannelSlot::Stub(s) => f(&s),
        ChannelSlot::Ready(_) => panic!("expected channel stub"),
    }
}
