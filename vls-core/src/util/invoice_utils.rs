use core::convert::TryFrom;
use core::str::FromStr;

use crate::invoice::*;
use crate::prelude::*;
use crate::util::status::{invalid_argument, Status};

impl FromStr for Invoice {
    type Err = Status;
    fn from_str(invstr: &str) -> Result<Self, Self::Err> {
        // Try BOLT-12 first, if that fails try BOLT-11 ...
        let maybe_bolt12 = WrappedBolt12Invoice::from_str(invstr);
        match maybe_bolt12 {
            Ok(bolt12) => Ok(Invoice::Bolt12(bolt12.0)),
            Err(bolt12err) => {
                let bolt11_raw = invstr.parse::<bolt11::SignedRawInvoice>().map_err(|e| {
                    Status::invalid_argument(format!(
                        "invoice not bolt12: {:?} and not bolt11: {:?}",
                        bolt12err, e
                    ))
                })?;
                Ok(Invoice::try_from(bolt11_raw)?)
            }
        }
    }
}

// This is BOLT-11 only
impl TryFrom<bolt11::SignedRawInvoice> for Invoice {
    type Error = Status;
    fn try_from(bolt11_raw: bolt11::SignedRawInvoice) -> Result<Self, Self::Error> {
        // This performs all semantic checks and signature check
        let bolt11 = bolt11::Invoice::from_signed(bolt11_raw)
            .map_err(|e| invalid_argument(e.to_string()))?;
        Ok(Invoice::Bolt11(bolt11))
    }
}

// Cribbed from rust-lightning/lightning/src/offers/parse.rs because
// LDK doesn't facilitate bech32 encoding/decoding of bolt12::Invoice

use bitcoin::bech32;
use bitcoin::bech32::FromBase32;

use crate::lightning::offers::parse::ParseError;

struct WrappedBolt12Invoice(bolt12::Invoice);

impl FromStr for WrappedBolt12Invoice {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<WrappedBolt12Invoice, <WrappedBolt12Invoice as FromStr>::Err> {
        const BECH32_HRP: &'static str = "lni";

        // Offer encoding may be split by '+' followed by optional whitespace.
        let encoded = match s.split('+').skip(1).next() {
            Some(_) => {
                for chunk in s.split('+') {
                    let chunk = chunk.trim_start();
                    if chunk.is_empty() || chunk.contains(char::is_whitespace) {
                        return Err(ParseError::InvalidContinuation);
                    }
                }

                let s: String = s.chars().filter(|c| *c != '+' && !c.is_whitespace()).collect();
                Bech32String::Owned(s)
            }
            None => Bech32String::Borrowed(s),
        };

        let (hrp, data) = bech32::decode_without_checksum(encoded.as_ref())?;

        if hrp != BECH32_HRP {
            return Err(ParseError::InvalidBech32Hrp);
        }

        let data = Vec::<u8>::from_base32(&data)?;
        Ok(WrappedBolt12Invoice(bolt12::Invoice::try_from(data)?))
    }
}

// Used to avoid copying a bech32 string not containing the continuation character (+).
enum Bech32String<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl<'a> AsRef<str> for Bech32String<'a> {
    fn as_ref(&self) -> &str {
        match self {
            Bech32String::Borrowed(s) => s,
            Bech32String::Owned(s) => s,
        }
    }
}
