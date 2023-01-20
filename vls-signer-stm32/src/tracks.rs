use alloc::collections::BTreeMap as Map;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vls_protocol_signer::vls_protocol::msgs::Message;

const TRACKLEN: usize = 16;

pub struct Track {
    latest: u64,
    dspstr: String,
    last: char,
    count: usize,
}

impl Track {
    fn new() -> Track {
        Track { latest: 0, dspstr: String::new(), last: '\0', count: 0 }
    }

    fn update(&mut self, seq: u64, c: char) -> bool {
        self.latest = seq;

        // Update the last and repeat count
        let count0 = self.count;
        if c == self.last {
            self.count += 1;
        } else {
            self.last = c;
            self.count = 1
        }

        if self.count < 3 {
            // Not much repeating, just normal ...
            self.append(c);
            true
        } else {
            // the new string
            let str1 = format!("{}*{}", c, self.count); // the new string

            // the old string
            let str0 =
                if self.count == 3 { format!("{}{}", c, c) } else { format!("{}*{}", c, count0) };

            // Replace the old group
            self.dspstr.replace_range(self.dspstr.len() - str0.len().., &str1);

            // Trim to fit from the front
            while self.dspstr.len() > TRACKLEN {
                self.dspstr.remove(0);
            }

            // shift if we added a digit
            str0.len() < str1.len()
        }
    }

    fn append(&mut self, c: char) {
        self.dspstr.push(c);
        while self.dspstr.len() > TRACKLEN {
            self.dspstr.remove(0);
        }
    }

    fn shift(&mut self) {
        self.last = '\0';
        self.count = 0;
        self.append('-');
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

        // Update the target track, maybe shift everything
        if self.tracks.get_mut(&dbid).unwrap().update(seq, track_char(msg)) {
            for (id, track) in self.tracks.iter_mut() {
                if id != &dbid {
                    track.shift();
                }
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
        Message::HsmdInit(_m) => '@',
        Message::HsmdInit2(_m) => '%',
        Message::NodeInfo(_m) => '#',
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
        Message::SignWithdrawal(_m) => 'W',

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
        Message::GetHeartbeat(_m) => '^',

        Message::Ping(_m) => '.',
        Message::Memleak(_m) => '_',
        Message::Unknown(_m) => '?',
        _m => '*',
    }
}
