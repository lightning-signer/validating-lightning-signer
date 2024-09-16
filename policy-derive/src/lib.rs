use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derives a new struct and a merge function for a given struct.
/// The new struct has the same fields as the original, but each field is wrapped in an `Option`.
/// See generated `merge` and `resolve_defaults` functions for more information.
#[proc_macro_derive(Optionized)]
pub fn derive_optionized(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = &ast.ident;

    let fields: Vec<_> = match &ast.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields
                .named
                .iter()
                .map(|field| {
                    let field_name = field.ident.clone().unwrap();
                    let field_type = &field.ty;
                    (field_name, field_type)
                })
                .collect(),
            _ => return quote! {
                compile_error!("SimplePolicyMerge can only be derived for structs with named fields");
            }.into(),
        },
        _ => return quote! {
            compile_error!("SimplePolicyMerge can only be derived for structs");
        }.into(),
    };

    let optionized_struct_name = format_ident!("Optionized{}", struct_name);
    let optionized_fields = fields.iter().map(|(field_name, field_type)| {
        quote! {
            pub #field_name: ::core::option::Option<#field_type>
        }
    });
    let optionized_struct = quote! {
        /// An optionized version of #struct_name.
        /// Each field is wrapped in an Option.
        /// See [merge] and [resolve_defaults] for more information.
        #[derive(Deserialize, Debug, Default, Clone)]
        #[allow(missing_docs)]
        pub struct #optionized_struct_name {
            #(#optionized_fields),*
        }
    };

    let merge_impl = generate_merge_function(&optionized_struct_name, &fields);
    let resolve_defaults_function =
        generate_resolve_defaults_function(&optionized_struct_name, &fields);
    let new_function = generate_new_function(&optionized_struct_name, &fields);

    let expanded = quote! {
        #optionized_struct
        #new_function
        #merge_impl
        #resolve_defaults_function
    };

    expanded.into()
}

/// Generates a merge function for the given struct.
/// The merge function takes another instance of the struct as input,
/// and for each field, if the input has a `Some` value for that field, it sets the field in `self` to that value.
fn generate_merge_function(
    struct_name: &proc_macro2::Ident,
    fields: &[(proc_macro2::Ident, &syn::Type)],
) -> proc_macro2::TokenStream {
    let field_assignments = fields.iter().map(|(field_name, _)| {
        quote! {
            if let Some(val) = other.#field_name {
                self.#field_name = Some(val);
            }
        }
    });
    quote! {
        /// Implementation of the merge function
        impl #struct_name {
            /// merge function
            pub fn merge(&mut self, other: Self) {
                #(#field_assignments)*
            }
        }
    }
}

fn generate_resolve_defaults_function(
    struct_name: &proc_macro2::Ident,
    fields: &[(proc_macro2::Ident, &syn::Type)],
) -> proc_macro2::TokenStream {
    let binding = struct_name.to_string();
    let original_struct_name = binding.trim_start_matches("Optionized");
    let original_struct_ident = format_ident!("{}", original_struct_name);

    let field_assignments = fields.iter().map(|(field_name, _)| {
        quote! {
            #field_name: self.#field_name.clone().unwrap_or(defaults.#field_name),
        }
    });
    quote! {
        impl #struct_name {
            /// Apply defaults to fields in self that are None and return a new instance of the original struct
            pub fn resolve_defaults(self, defaults: #original_struct_ident) -> #original_struct_ident {
                #original_struct_ident {
                    #(#field_assignments)*
                }
            }
        }
    }
}

fn generate_new_function(
    struct_name: &proc_macro2::Ident,
    fields: &[(proc_macro2::Ident, &syn::Type)],
) -> proc_macro2::TokenStream {
    let field_initializations = fields.iter().map(|(field_name, _)| {
        quote! {
            #field_name: None
        }
    });
    quote! {
        impl #struct_name {
            /// Create a new #struct_name with all fields set to None
            pub fn new() -> Self {
                Self {
                    #(#field_initializations),*
                }
            }
        }
    }
}
