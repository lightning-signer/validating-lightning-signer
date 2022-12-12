use alloc::collections::BTreeMap as Map;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vls_protocol_signer::vls_protocol::msgs::Message;

const TRACKLEN: usize = 16;

pub struct Track {
    latest: u64,
    dspstr: String,
}

impl Track {
    fn new() -> Track {
        Track { latest: 0, dspstr: String::new() }
    }

    fn append(&mut self, c: char) {
        if self.dspstr.len() == TRACKLEN {
            self.dspstr.remove(0);
        }
        self.dspstr.push(c);
    }
}

pub(crate) struct Tracks {
    tracks: Map<u64, Track>,
}

impl Tracks {
    pub(crate) fn new() -> Tracks {
        Tracks { tracks: Map::new() }
    }

    pub(crate) fn add_message(
        &mut self,
        dbid: u64,
        seq: u64,
        msg: &Message,
        num_top: usize,
    ) -> Vec<String> {
        // Ensure the track for this dbid exists
        self.tracks.entry(dbid).or_insert(Track::new());

        // Update all of the tracks
        for (id, track) in self.tracks.iter_mut() {
            if id == &dbid {
                track.latest = seq;
                track.append(track_char(msg));
            } else {
                track.append('-');
            }
        }

        // Find the top (most recent) tracks
        let mut top: Vec<_> = self.tracks.iter().collect();
        top.sort_by_key(|item| u64::MAX - item.1.latest);
        top.truncate(num_top);

        // Sort by dbid so display is more "stable"
        top.sort_by_key(|item| item.0);

        // Format the output strings
        let mut output: Vec<_> = top
            .iter()
            .map(|item| format!("{:02} {: >len$}", item.0, item.1.dspstr, len = TRACKLEN))
            .collect();

        // Extend w/ blank strings
        output.resize(num_top, "".to_string());

        output
    }
}

fn track_char(msg: &Message) -> char {
    match msg {
        Message::HsmdInit(_m) => '0',
        Message::HsmdInit2(_m) => '0',
        Message::Ecdh(_m) => 'e',

        Message::SignNodeAnnouncement(_m) => 'n',
        Message::SignChannelAnnouncement(_m) => 'c',
        Message::SignChannelUpdate(_m) => 'u',
        Message::SignInvoice(_m) => 'i',
        Message::SignBolt12(_m) => 'i',
        Message::PreapproveInvoice(_m) => 'a',
        Message::PreapproveKeysend(_m) => 'k',
        Message::DeriveSecret(_m) => 'x',
        Message::SignMessage(_m) => 'm',
        Message::CheckFutureSecret(_m) => '~',

        Message::NewChannel(_m) => '+',
        Message::GetChannelBasepoints(_m) => 'b',
        Message::SignWithdrawal(_m) => 'w',

        Message::ReadyChannel(_m) => '(',
        Message::GetPerCommitmentPoint(_m) => 'p',
        Message::GetPerCommitmentPoint2(_m) => 'p',

        Message::SignRemoteCommitmentTx(_m) => 's',
        Message::SignRemoteCommitmentTx2(_m) => 's',
        Message::SignRemoteHtlcTx(_m) => 'h',
        Message::ValidateCommitmentTx(_m) => 'v',
        Message::ValidateCommitmentTx2(_m) => 'v',
        Message::ValidateRevocation(_m) => 'r',
        Message::SignMutualCloseTx(_m) => ')',
        Message::SignMutualCloseTx2(_m) => ')',

        Message::SignCommitmentTx(_m) => 'S',
        Message::SignLocalCommitmentTx2(_m) => 'S',
        Message::SignLocalHtlcTx(_m) => 'L',
        Message::SignDelayedPaymentToUs(_m) => 'D',
        Message::SignRemoteHtlcToUs(_m) => 'H',
        Message::SignPenaltyToUs(_m) => 'J',

        Message::TipInfo(_m) => 't',
        Message::ForwardWatches(_m) => 'f',
        Message::ReverseWatches(_m) => 'F',
        Message::AddBlock(_m) => 'b',
        Message::RemoveBlock(_m) => 'B',

        Message::Ping(_m) => '.',
        Message::Memleak(_m) => '_',
        Message::Unknown(_m) => '?',
        _m => '*',
    }
}
