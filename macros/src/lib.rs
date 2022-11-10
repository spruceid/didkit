use std::collections::HashMap;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::{Pair, Punctuated};
use syn::{
    parse_macro_input, FnArg, Ident, ItemFn, Lit, MetaNameValue, Pat, PatIdent, PatType, Token,
};

struct Args {
    wrap: String,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Self> {
        let vars = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;

        let attrs: HashMap<String, String> = vars
            .into_pairs()
            .map(Pair::into_tuple)
            .map(
                |(MetaNameValue { path, lit, .. }, _)| match path.get_ident() {
                    Some(ident) => (
                        ident.to_string(),
                        match lit {
                            Lit::Str(lit) => lit.value(),
                            _ => todo!(),
                        },
                    ),
                    None => todo!(),
                },
            )
            .collect();

        Ok(Args {
            wrap: attrs
                .get("wrap")
                .ok_or_else(|| {
                    syn::Error::new(input.span(), "Expected `wrap` property in attribute macro")
                })?
                .to_owned(),
        })
    }
}

#[proc_macro_attribute]
pub fn c_export(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let mut input_fn = parse_macro_input!(input as ItemFn);

    let internal = format_ident!("f");
    let name = input_fn.sig.ident.to_owned();
    let args = input_fn.sig.inputs.to_owned();
    input_fn.sig.ident = internal.to_owned();

    let Args { wrap } = parse_macro_input!(metadata as Args);
    let wrap = format_ident!("{}", wrap);

    let call_args = args
        .to_owned()
        .into_pairs()
        .map(Pair::into_tuple)
        .map(|(arg, _)| match arg {
            FnArg::Typed(PatType { pat, .. }) => match *pat {
                Pat::Ident(PatIdent { ident, .. }) => ident,
                _ => todo!(),
            },
            _ => todo!(),
        })
        .collect::<Vec<Ident>>();

    TokenStream::from(quote! {
        #[no_mangle]
        pub extern "C" fn #name( #args ) -> *const c_char {
            #input_fn

            #wrap( #internal( #(#call_args),* ) )
        }
    })
}

#[proc_macro_attribute]
pub fn java_export(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let mut input_fn = parse_macro_input!(input as ItemFn);

    let internal = format_ident!("f");
    let name = input_fn.sig.ident.to_owned();
    let args: Punctuated<FnArg, Token![,]> =
        input_fn.sig.inputs.to_owned().into_iter().skip(1).collect();
    input_fn.sig.ident = internal.to_owned();

    let Args { wrap } = parse_macro_input!(metadata as Args);
    let wrap = format_ident!("{}", wrap);

    let call_args = args
        .to_owned()
        .into_pairs()
        .map(Pair::into_tuple)
        .map(|(arg, _)| match arg {
            FnArg::Typed(PatType { pat, .. }) => match *pat {
                Pat::Ident(PatIdent { ident, .. }) => ident,
                _ => todo!(),
            },
            _ => todo!(),
        })
        .collect::<Vec<Ident>>();

    TokenStream::from(quote! {
        #[no_mangle]
        pub extern "system" fn #name(env: JNIEnv, _class: JClass, #args ) -> jstring {
            #input_fn

            #wrap(&env, #internal(&env, #(#call_args),* ) )
        }


    })
}
