use core::convert::TryFrom;
use core::str::FromStr;

use crate::invoice::*;
use crate::prelude::*;
use crate::util::status::{invalid_argument, Status};

impl FromStr for Invoice {
    type Err = Status;
    fn from_str(invstr: &str) -> Result<Self, Self::Err> {
        // TODO - add BOLT12
        let bolt11_raw = invstr
            .parse::<bolt11::SignedRawInvoice>()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Invoice::try_from(bolt11_raw)?)
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
