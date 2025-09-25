use alloc::collections::BTreeMap as Map;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vls_protocol_signer::vls_protocol::msgs::Message;

const TRACKLEN: usize = 15;

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
        // Determine which track the received message should be displayed on.
        // Many messages are sent in a channel specific context (dbid != 0) and
        // should be displayed on the corresponding track. Messages from the
        // master which do not have a channel specific nature are shown on track
        // 0. Finally, some messages are sent by the master (lightnind) but are
        // logically operating on a specific channel. They should be displayed
        // on the channel-specific track.
        let applied_dbid = if dbid == 0 {
            match msg {
                Message::NewChannel(m) => m.dbid,
                Message::ForgetChannel(m) => m.dbid,
                Message::GetChannelBasepoints(m) => m.dbid,
                Message::SignCommitmentTx(m) => m.dbid,
                Message::SignAnyDelayedPaymentToUs(m) => m.dbid,
                Message::SignAnyRemoteHtlcToUs(m) => m.dbid,
                Message::SignAnyPenaltyToUs(m) => m.dbid,
                Message::SignAnyLocalHtlcTx(m) => m.dbid,
                Message::SignAnyChannelAnnouncement(m) => m.dbid,
                Message::SignAnchorspend(m) => m.dbid,
                _ => dbid,
            }
        } else {
            dbid
        };

        // Ensure the track for this applied_dbid exists
        self.tracks.entry(applied_dbid).or_insert(Track::new());

        // Update the target track, maybe shift everything
        if self.tracks.get_mut(&applied_dbid).unwrap().update(seq, track_char(msg)) {
            for (id, track) in self.tracks.iter_mut() {
                if id != &applied_dbid {
                    track.shift();
                }
            }
        }

        // Find the top (most recent) tracks
        let mut top: Vec<_> = self.tracks.iter().collect();
        top.sort_by_key(|item| u64::MAX - item.1.latest);
        top.truncate(num_top);

        // Sort by applied_dbid so display is more "stable"
        top.sort_by_key(|item| item.0);

        // Format the output strings
        let mut output: Vec<_> = top
            .iter()
            .map(|item| format!("{:03} {: >len$}", item.0, item.1.dspstr, len = TRACKLEN))
            .collect();

        // Extend w/ blank strings
        output.resize(num_top, "".to_string());

        output
    }
}

fn track_char(msg: &Message) -> char {
    match msg {
        Message::HsmdDevPreinit(_m) => '%',
        Message::HsmdDevPreinit2(_m) => '%',
        Message::HsmdInit(_m) => '@',
        Message::HsmdInit2(_m) => '@',
        Message::NodeInfo(_m) => '#',
        Message::Ecdh(_m) => 'e',
        Message::CheckPubKey(_m) => '=',

        Message::SignNodeAnnouncement(_m) => 'n',
        Message::SignChannelAnnouncement(_m) => 'c',
        Message::SignAnyChannelAnnouncement(_m) => 'c',
        Message::SignChannelUpdate(_m) => 'u',
        Message::SignInvoice(_m) => 'i',
        Message::SignBolt12(_m) => 'i',
        Message::SignBolt12V2(_m) => 'i',
        Message::PreapproveInvoice(_m) => 'a',
        Message::PreapproveKeysend(_m) => 'k',
        Message::DeriveSecret(_m) => 'x',
        Message::SignMessage(_m) => 'm',
        Message::CheckFutureSecret(_m) => '~',

        Message::NewChannel(_m) => '+',
        Message::ForgetChannel(_m) => '-',
        Message::GetChannelBasepoints(_m) => 'b',
        Message::SignWithdrawal(_m) => 'W',

        Message::SetupChannel(_m) => '(',
        Message::GetPerCommitmentPoint(_m) => 'p',
        Message::GetPerCommitmentPoint2(_m) => 'p',
        Message::CheckOutpoint(_m) => '?',
        Message::LockOutpoint(_m) => '!',

        Message::SignRemoteCommitmentTx(_m) => '<',
        Message::SignRemoteCommitmentTx2(_m) => '<',
        Message::SignRemoteHtlcTx(_m) => 'h',
        Message::SignLocalHtlcTx2(_m) => 'h',
        Message::ValidateCommitmentTx(_m) => '{',
        Message::ValidateCommitmentTx2(_m) => '{',
        Message::RevokeCommitmentTx(_m) => '}',
        Message::ValidateRevocation(_m) => '>',
        Message::SignMutualCloseTx(_m) => ')',
        Message::SignMutualCloseTx2(_m) => ')',

        Message::SignCommitmentTx(m) => {
            if m.tx.0.lock_time.to_consensus_u32() == 0 {
                ')' // really a SignMutualCloseTx
            } else {
                'S'
            }
        }
        Message::SignLocalCommitmentTx2(_m) => 'S',
        Message::SignLocalHtlcTx(_m) => 'L',
        Message::SignAnyLocalHtlcTx(_m) => 'L',
        Message::SignDelayedPaymentToUs(_m) => 'D',
        Message::SignAnyDelayedPaymentToUs(_m) => 'D',
        Message::SignRemoteHtlcToUs(_m) => 'H',
        Message::SignAnyRemoteHtlcToUs(_m) => 'H',
        Message::SignPenaltyToUs(_m) => '^',
        Message::SignAnyPenaltyToUs(_m) => '^',
        Message::SignAnchorspend(_m) => '&',
        Message::SignHtlcTxMingle(_m) => 'g',

        Message::SignSpliceTx(_m) => '|',

        Message::TipInfo(_m) => '<',
        Message::GetHeartbeat(_m) => 'B',
        Message::ForwardWatches(_m) => '[',
        Message::BlockChunk(_m) => ':',
        Message::AddBlock(_m) => ']',
        Message::ReverseWatches(_m) => '{',
        Message::RemoveBlock(_m) => '}',
        Message::SignerError(_m) => 'o',

        Message::Ping(_m) => '.',
        Message::Memleak(_m) => '_',
        Message::Unknown(_m) => ' ',

        // we shouldn't see any of these
        Message::Pong(_)
        | Message::HsmdDevPreinitReply(_)
        | Message::HsmdInitReplyV2(_)
        | Message::HsmdInitReplyV4(_)
        | Message::HsmdInit2Reply(_)
        | Message::ClientHsmFd(_)
        | Message::ClientHsmFdReply(_)
        | Message::NodeInfoReply(_)
        | Message::SignInvoiceReply(_)
        | Message::SignWithdrawalReply(_)
        | Message::EcdhReply(_)
        | Message::MemleakReply(_)
        | Message::CheckFutureSecretReply(_)
        | Message::SignMessageReply(_)
        | Message::SignBolt12Reply(_)
        | Message::SignBolt12V2Reply(_)
        | Message::PreapproveInvoiceReply(_)
        | Message::PreapproveKeysendReply(_)
        | Message::DeriveSecretReply(_)
        | Message::CheckPubKeyReply(_)
        | Message::SignChannelUpdateReply(_)
        | Message::SignChannelAnnouncementReply(_)
        | Message::SignAnyChannelAnnouncementReply(_)
        | Message::SignNodeAnnouncementReply(_)
        | Message::GetPerCommitmentPointReply(_)
        | Message::GetPerCommitmentPoint2Reply(_)
        | Message::SetupChannelReply(_)
        | Message::CheckOutpointReply(_)
        | Message::LockOutpointReply(_)
        | Message::ValidateCommitmentTxReply(_)
        | Message::RevokeCommitmentTxReply(_)
        | Message::ValidateRevocationReply(_)
        | Message::SignCommitmentTxWithHtlcsReply(_)
        | Message::SignCommitmentTxReply(_)
        | Message::SignTxReply(_)
        | Message::SignAnchorspendReply(_)
        | Message::SignHtlcTxMingleReply(_)
        | Message::NewChannelReply(_)
        | Message::ForgetChannelReply(_)
        | Message::GetChannelBasepointsReply(_)
        | Message::TipInfoReply(_)
        | Message::ForwardWatchesReply(_)
        | Message::ReverseWatchesReply(_)
        | Message::BlockChunkReply(_)
        | Message::AddBlockReply(_)
        | Message::RemoveBlockReply(_)
        | Message::GetHeartbeatReply(_)
        | Message::SignGossipMessage(_)
        | Message::SignGossipMessageReply(_) => {
            panic!("{:?} invalid in this context", msg);
        }
    }
}
