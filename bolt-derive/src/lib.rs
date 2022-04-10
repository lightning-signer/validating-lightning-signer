use proc_macro::{self, TokenStream};
use proc_macro2::Ident;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, DataEnum, Type};

/// Serialize a message with a type prefix, in BOLT style
#[proc_macro_derive(SerBolt)]
pub fn derive_ser_bolt(input: TokenStream) -> TokenStream {
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

#[proc_macro_derive(ReadMessage)]
pub fn derive_read_message(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);
    let vs_ts = match data {
        Data::Enum(DataEnum{ variants, ..}) => {
            variants.iter()
                .filter(|v| v.ident != "Unknown")
                .map(|v|
                    {
                        let vident = v.ident.clone();
                        let mut fields = v.fields.iter();
                        let field = fields.next().expect(format!("must have exactly one field in {}", vident).as_str());
                        if fields.next().is_some() {
                            panic!("must have exactly one field in {}", vident);
                        }
                        (vident, field.ty.clone())
                    }
                ).collect::<Vec<_>>()
        }
        _ => unimplemented!()
    };

    let (vs, ts): (Vec<Ident>, Vec<Type>) = vs_ts.into_iter().unzip();
    println!("{}", vs.len());

    let output = quote! {
        impl #ident {
            fn read_message(mut data: &mut Vec<u8>, message_type: u16) -> Result<Message> {
                let message = match message_type {
                    #(#vs::TYPE => Message::#ts(from_vec_no_trailing(&mut data)?)),*,
                    _ => Message::Unknown(Unknown { message_type, data: data.clone() }),
                };
                Ok(message)
            }
        }
    };

    output.into()
}
