use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Serialize a message with a type prefix, in BOLT style
#[proc_macro_derive(SerBolt)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl SerBolt for #ident {
            fn as_vec(&self) -> Vec<u8> {
                let message_type = Self::TYPE;
                let mut buf = message_type.to_be_bytes().to_vec();
                let mut val_buf = to_vec(&self).expect("serialize");
                buf.append(&mut val_buf);
                buf
            }
        }

        impl DeBolt for #ident {
            fn from_vec(mut ser: Vec<u8>) -> Result<Self> {
                let reader = &mut ser;
                let message_type = read_u16(reader)?;
                if message_type != Self::TYPE {
                    return Err(Error::UnexpectedType(message_type));
                }
                from_vec_no_trailing(reader)
            }
        }
    };
    output.into()
}
