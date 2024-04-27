use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens};
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Error, Fields, Lit, Type};

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

            fn name(&self) -> &'static str {
                stringify!(#ident)
            }
        }

        impl DeBolt for #ident {
            const TYPE: u16 = #message_id;
            fn from_vec(mut ser: Vec<u8>) -> Result<Self> {
                let mut cursor = serde_bolt::io::Cursor::new(&ser);
                let message_type = cursor.read_u16_be()?;
                if message_type != Self::TYPE {
                    return Err(Error::UnexpectedType(message_type));
                }
                let res = Decodable::consensus_decode(&mut cursor)?;
                if cursor.position() as usize != ser.len() {
                    return Err(Error::TrailingBytes(cursor.position() as usize - ser.len(), Self::TYPE));
                }
                Ok(res)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(SerBoltTlvOptions, attributes(tlv_tag))]
pub fn derive_ser_bolt_tlv(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = &input.ident;

    let mut encode_entries: Vec<(u64, proc_macro2::TokenStream)> = Vec::new();
    let mut decode_entries: Vec<(u64, proc_macro2::TokenStream)> = Vec::new();
    let mut decode_temp_declarations: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut decode_fields: Vec<proc_macro2::TokenStream> = Vec::new();

    // traverse the fields, build the needed lists
    if let Data::Struct(data_struct) = &input.data {
        if let Fields::Named(fields_named) = &data_struct.fields {
            for field in fields_named.named.iter() {
                let field_name = field.ident.as_ref().unwrap();
                let field_type = &field.ty;
                let var_name = format_ident!("{}", field_name);

                if let Some(attr) = field.attrs.iter().find(|a| a.path.is_ident("tlv_tag")) {
                    match attr.parse_meta() {
                        Ok(syn::Meta::NameValue(meta_name_value)) => {
                            if let Lit::Int(lit_int) = meta_name_value.lit {
                                let tlv_tag = lit_int
                                    .base10_parse::<u64>()
                                    .expect("tlv_tag should be a valid u64");
                                encode_entries.push((
                                    tlv_tag,
                                    quote! {
                                        (#tlv_tag, self.#var_name.as_ref().map(|f| crate::model::SerBoltTlvWriteWrap(f)), option),
                                    },
                                ));
                                decode_entries.push((
                                    tlv_tag,
                                    quote! {
                                        (#tlv_tag, #var_name, option),
                                    },
                                ));
                                let inner_type = unwrap_option(field_type).expect("Option type expected");
                                decode_temp_declarations.push(quote! {
                                    let mut #var_name: Option<crate::model::SerBoltTlvReadWrap<#inner_type>> = None;
                                });
                                decode_fields.push(quote! {
                                    #var_name: #var_name.map(|w| w.0),
                                });
                            } else {
                                eprintln!("Warning: `tlv_tag` attribute value must be an integer.");
                            }
                        }
                        _ => eprintln!("Failed to parse `tlv_tag` attribute."),
                    }
                } else {
                    eprintln!("Warning: Missing `tlv_tag` attribute for field `{}`.", field_name);
                }
            }
        }
    }

    // sort the entries into ascending order
    encode_entries.sort_by_key(|entry| entry.0);
    decode_entries.sort_by_key(|entry| entry.0);
    let sorted_encode_entries: Vec<_> = encode_entries.iter().map(|(_tag, ts)| ts).collect();
    let sorted_decode_entries: Vec<_> = decode_entries.iter().map(|(_tag, ts)| ts).collect();

    // generate the output
    let output = quote! {
        impl Encodable for #ident {
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let mut mw = crate::util::MeasuredWriter::wrap(w);
                lightning::encode_tlv_stream!(&mut mw, {
                    #( #sorted_encode_entries )*
                });
                Ok(mw.len())
            }
        }

        impl Decodable for #ident {
            fn consensus_decode<R: io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
                #(#decode_temp_declarations)*
                (|| -> core::result::Result<_, _> {
                    lightning::decode_tlv_stream!(r, {
                        #( #sorted_decode_entries )*
                    });
                    Ok(())
                })()
                    .map_err(|_e| bitcoin::consensus::encode::Error::ParseFailed(
                        "decode_tlv_stream failed"))?;
                Ok(Self { #(#decode_fields)* })
            }
        }
    };

    output.into()
}

fn unwrap_option(field_type: &Type) -> Option<&Type> {
    if let syn::Type::Path(syn::TypePath { path, .. }) = &field_type {
        if path.segments.len() == 1 && path.segments[0].ident == "Option" {
            if let syn::PathArguments::AngleBracketed(args) = &path.segments[0].arguments {
                if let Some(syn::GenericArgument::Type(ty)) = args.args.first() {
                    return Some(ty)
                }
            }
        }
    }
    None
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
            }
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
            fn read_message<R: Read + ?Sized>(mut reader: &mut R, message_type: u16) -> Result<Message> {
                let message = match message_type {
                    #(#vs::TYPE => Message::#ts(Decodable::consensus_decode(reader)?)),*,
                    _ => Message::Unknown(Unknown { message_type }),
                };
                Ok(message)
            }

            pub fn inner(&self) -> alloc::boxed::Box<&dyn SerBolt> {
                match self {
                    #(#ident::#vs(inner) => alloc::boxed::Box::new(inner)),*,
                    _ => alloc::boxed::Box::new(&UNKNOWN_PLACEHOLDER),
                }
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
