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
    };
    output.into()
}
