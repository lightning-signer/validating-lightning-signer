use proc_macro::{self, TokenStream};
use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Error, Fields};

/// Serialize a message with a type prefix, in BOLT style
#[proc_macro_derive(SerBolt, attributes(message_id))]
pub fn derive_ser_bolt(input: TokenStream) -> TokenStream {
    let input1 = input.clone();
    let DeriveInput { ident, attrs, .. } = parse_macro_input!(input1);
    let message_id = attrs
        .into_iter()
        .filter(|a| a.path.is_ident("message_id"))
        .next()
        .map(|a| a.tokens)
        .unwrap_or_else(|| {
            Error::new(ident.span(), "missing message_id attribute").into_compile_error()
        });

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
            const TYPE: u16 = #message_id;
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
    let mut vs = Vec::new();
    let mut ts = Vec::new();
    let mut error: Option<Error> = None;

    if let Data::Enum(DataEnum { variants, .. }) = data {
        for v in variants {
            if v.ident == "Unknown" {
                continue;
            };
            let vident = v.ident.clone();
            let field = extract_single_type(&vident, &v.fields);
            match field {
                Ok(f) => {
                    vs.push(vident);
                    ts.push(f);
                }
                Err(e) => match error.as_mut() {
                    None => error = Some(e),
                    Some(o) => o.combine(e),
                },
            }
        }
    } else {
        unimplemented!()
    }

    if let Some(error) = error {
        return error.into_compile_error().into();
    }

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

fn extract_single_type(vident: &Ident, fields: &Fields) -> Result<TokenStream2, Error> {
    let mut fields = fields.iter();
    let field =
        fields.next().ok_or_else(|| Error::new(vident.span(), "must have exactly one field"))?;
    if fields.next().is_some() {
        return Err(Error::new(vident.span(), "must have exactly one field"));
    }
    Ok(field.ty.clone().into_token_stream())
}
