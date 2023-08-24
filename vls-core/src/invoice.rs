use core::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

use lightning::ln::PaymentHash;

pub use lightning::offers::invoice as bolt12;
pub use lightning_invoice as bolt11;

use crate::prelude::*;

/// Generic invoice methods for both BOLT-11 and BOLT-12 invoices.
pub trait InvoiceAttributes {
    /// The hash of the invoice, as a unique ID
    fn invoice_hash(&self) -> [u8; 32];
    /// The payment hash of the invoice
    fn payment_hash(&self) -> PaymentHash;
    /// Invoiced amount
    fn amount_milli_satoshis(&self) -> u64;
    /// Description
    fn description(&self) -> String;
    /// Payee's public key
    fn payee_pub_key(&self) -> PublicKey;
    /// Timestamp of the payment, as duration since the UNIX epoch
    fn duration_since_epoch(&self) -> Duration;
    /// Expiry, as duration since the timestamp
    fn expiry_duration(&self) -> Duration;
}

/// A BOLT11 or BOLT12 invoice
#[derive(Clone, Debug)]
pub enum Invoice {
    /// A BOLT11 Invoice and its raw invoice hash
    Bolt11(bolt11::Bolt11Invoice),
    /// A BOLT12 Invoice
    Bolt12(bolt12::Bolt12Invoice),
}

impl InvoiceAttributes for Invoice {
    fn invoice_hash(&self) -> [u8; 32] {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.signable_hash(),
            Invoice::Bolt12(bolt12) => bolt12.signable_hash(),
        }
    }

    fn payment_hash(&self) -> PaymentHash {
        match self {
            Invoice::Bolt11(bolt11) => PaymentHash(bolt11.payment_hash().as_inner().clone()),
            Invoice::Bolt12(bolt12) => bolt12.payment_hash(),
        }
    }

    fn amount_milli_satoshis(&self) -> u64 {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.amount_milli_satoshis().unwrap_or(0),
            Invoice::Bolt12(bolt12) => bolt12.amount_msats(),
        }
    }

    fn description(&self) -> String {
        match self {
            Invoice::Bolt11(bolt11) => match bolt11.description() {
                bolt11::Bolt11InvoiceDescription::Direct(d) => d.to_string(),
                bolt11::Bolt11InvoiceDescription::Hash(h) => format!("hash: {:?}", h),
            },
            Invoice::Bolt12(bolt12) => bolt12.description().0.to_string(),
        }
    }

    fn payee_pub_key(&self) -> PublicKey {
        match self {
            Invoice::Bolt11(bolt11) => bolt11
                .payee_pub_key()
                .map(|p| p.clone())
                .unwrap_or_else(|| bolt11.recover_payee_pub_key()),
            Invoice::Bolt12(bolt12) => bolt12.signing_pubkey(),
        }
    }

    fn duration_since_epoch(&self) -> Duration {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.duration_since_epoch(),
            Invoice::Bolt12(bolt12) => bolt12.created_at(),
        }
    }

    fn expiry_duration(&self) -> Duration {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.expiry_time(),
            Invoice::Bolt12(bolt12) => bolt12.relative_expiry(),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hashes::hex::ToHex;

    use crate::invoice::{Invoice, InvoiceAttributes};
    use crate::util::status::Code;

    #[test]
    fn test_bolt11_encoded() {
        // from https://github.com/lightning/bolts/blob/master/11-payment-encoding.md#examples
        //
        // Please make a donation of any amount using payment_hash
        // 0001020304050607080900010203040506070809000102030405060708090102 to me
        // @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
        let invoice = Invoice::from_str("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql").expect("invoice");
        assert_eq!(invoice.amount_milli_satoshis(), 0);
        assert_eq!(
            invoice.payment_hash().0.to_hex(),
            "0001020304050607080900010203040506070809000102030405060708090102"
        );
        assert_eq!(
            invoice.payee_pub_key().to_string(),
            "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
        );
    }

    #[test]
    fn test_bolt12_encoded() {
        // captured from CLN "test_pay.py::test_fetchinvoice"
        //
        let invoice = Invoice::from_str("lni1qqgf8ene6trt4n9mmrejx50c6v30cq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqgzpg9hx6tdwpkx2gr5v4ehg93pqdwjkyvjm7apxnssu4qgwhfkd67ghs6n6k48v6uqczgt88p6tky965pqqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy84sggravpsmwr0rxjdwzvj3ltcg95eklxftgfw8njx2dd3v9eat2k8q8g6pxqrt543ryklhgf5uy89gzr46dnwhj9ux5744fmxhqxqjzeecwja3pwsxz392f64zmwkh5p9hygu8gvt3lpfrn7ehs53d6ylasgcyppwdr6pqypde4glecqn4h2ydg7e56xq3n0p0jxzpw9v89qw7n9encppxqt037qqx2s4d5007pqgecutjv9x6gr793gqsc2svc9a2k3l62klfcny8ca8z60eptrhahvy9aypymralep23vvvkw3pcqqqqqqqqqqqqqqq2qqqqqqqqqqqqqwjfvkl43fqqqqqqzjqgepvjh02sg8u5wx8nat9vgux9cvr8fe9c337706k08xrnl03dmwaglxr46yglz4qzq4syyp462c3jt0m5y6wzrj5pp6axehtez7r20265antsrqfpvuu8fwcsh0sgzm7pttfeuz5snjhmks67afze5klpew503kn98x4zt24dcsurm9wch699ucgw9sh5ww85gu2fy598hdne0gp5msx0shu4kqqc9z6hhk7").expect("invoice");
        assert_eq!(invoice.amount_milli_satoshis(), 2);
        assert_eq!(
            invoice.payment_hash().0.to_hex(),
            "fca38c79f565623862e1833a725c463ef3f5679cc39fdf16eddd47cc3ae888f8"
        );
        assert_eq!(
            invoice.payee_pub_key().to_string(),
            "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d"
        );
    }

    #[test]
    // BOLT-12 recurrence is not supported yet
    fn test_bolt12_recurrence() {
        // captured from CLN "test_pay.py::test_fetchinvoice"
        //
        assert_invalid_argument_err!(
            Invoice::from_str("lni1qqg239qhp9zd4tnv4exlh74gmlq6yq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqgppg88yetrw4e8y6twvus8getnwstzzq3dygmzpg6e53ll0aavg37gt3rvjg762vufygdqq4xprs0regcatydqyqpu2qsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzr6cyypc97ywxgyjmc72gxh466uf8lyr7akfmvtn4ye4efqpscxx8g5vzj26qzsfsq3dygmzpg6e53ll0aavg37gt3rvjg762vufygdqq4xprs0regcatypt8spm8wcafuwyh24nfkctvcxmyruamsljh638ec306na7327zutcpqt0vv5neq5504nacs6cy7c39atn2ldrtecldj36tjw8nq0z69e3jkqpj9n43mjrkctxjqg07amjelrlq0zyth3gv28cmju6eumg3pqqyqr2klccnuv2h6xnkymss284z2sy0sm7w5gwqqqqqqqqqqqqqqqzsqqqqqqqqqqqqr5jt9hav2gqqqqqq5szxgt8ndznqzwagyrehhzcerrnk2p5evccgrct2cdjhk5tyz02wa9lleaf879hlhcx6a2spqxczzq3dygmzpg6e53ll0aavg37gt3rvjg762vufygdqq4xprs0regcatxeqgepv7d50qsxyts2muqhwhyphg6z096dzvkj80am0f3rhm65fsycx0890807t53cmzwqppu00p25vrua6fctshty9a6hjt4sfzpqp8v4crq4pvqe75"),
            "invoice not bolt12: Decode(UnknownRequiredFeature) \
             and not bolt11: Bech32Error(InvalidChecksum)");
    }
}
