use crate::invoice::*;
use crate::prelude::*;
use crate::util::status::{invalid_argument, Status};
use bitcoin::bech32::primitives::decode::UncheckedHrpstring;
use bitcoin::bech32::{Fe32, Fe32IterExt};
use core::str::FromStr;
use lightning::ln::msgs::DecodeError;
use lightning::offers::parse::Bolt12ParseError;

const BECH32_HRP: &'static str = "lni";

impl FromStr for Invoice {
    type Err = Status;
    fn from_str(invstr: &str) -> Result<Self, Self::Err> {
        // Try BOLT-12 first, if that fails try BOLT-11 ...
        let maybe_bolt12 = WrappedBolt12Invoice::from_str(invstr);
        match maybe_bolt12 {
            Ok(bolt12) => Ok(Invoice::Bolt12(bolt12.0)),
            Err(bolt12err) => {
                let bolt11_raw = invstr.parse::<bolt11::SignedRawBolt11Invoice>().map_err(|e| {
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
impl TryFrom<bolt11::SignedRawBolt11Invoice> for Invoice {
    type Error = Status;
    fn try_from(bolt11_raw: bolt11::SignedRawBolt11Invoice) -> Result<Self, Self::Error> {
        // This performs all semantic checks and signature check
        let bolt11 = bolt11::Bolt11Invoice::from_signed(bolt11_raw)
            .map_err(|e| invalid_argument(e.to_string()))?;
        Ok(Invoice::Bolt11(bolt11))
    }
}

// Cribbed from rust-lightning/lightning/src/offers/parse.rs because
// LDK doesn't facilitate bech32 encoding/decoding of bolt12::Invoice

struct WrappedBolt12Invoice(bolt12::Bolt12Invoice);

impl FromStr for WrappedBolt12Invoice {
    type Err = Bolt12ParseError;

    fn from_str(s: &str) -> Result<WrappedBolt12Invoice, Bolt12ParseError> {
        // Offer encoding may be split by '+' followed by optional whitespace.
        let encoded = match s.split('+').skip(1).next() {
            Some(_) => {
                for chunk in s.split('+') {
                    let chunk = chunk.trim_start();
                    if chunk.is_empty() || chunk.contains(char::is_whitespace) {
                        return Err(Bolt12ParseError::InvalidContinuation);
                    }
                }

                let s: String = s.chars().filter(|c| *c != '+' && !c.is_whitespace()).collect();
                Bech32String::Owned(s)
            }
            None => Bech32String::Borrowed(s),
        };

        // No checksum, because this is not human input
        let hrp_string = UncheckedHrpstring::new(encoded.as_ref())
            .map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

        if hrp_string.hrp().as_str() != BECH32_HRP {
            return Err(Bolt12ParseError::InvalidBech32Hrp);
        }

        let data = hrp_string
            .data_part_ascii()
            .into_iter()
            .map(|c| Fe32::from_char_unchecked(*c))
            .fes_to_bytes()
            .collect::<Vec<_>>();

        Ok(WrappedBolt12Invoice(bolt12::Bolt12Invoice::try_from(data)?))
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
