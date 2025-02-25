extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{parse_macro_input, FnArg, ItemFn, Pat, PatIdent, Signature, Type, parse::Parse, parse::ParseStream, LitStr, Ident, Token, Error, punctuated::Punctuated};

struct MacroArgs {
    resource: LitStr,
    config_param: Option<Ident>,
}

impl Parse for MacroArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let resource = input.parse::<LitStr>()?;
        
        let config_param = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            Some(input.parse::<Ident>()?)
        } else {
            None
        };
        
        Ok(MacroArgs {
            resource,
            config_param,
        })
    }
}

/// Macro to wrap a function with authorization token request logic
///
/// This macro will request an authorization token for a given resource
/// before executing the wrapped function. It supports both synchronous
/// and asynchronous functions.
///
/// # Example
///
/// ```
/// use hessra_macros::request_authorization;
///
/// // With client config parameter
/// #[request_authorization("my-resource", client_config)]
/// async fn protected_function(client_config: &HessraClientConfig) {
///     // This function will be called after token is obtained
/// }
///
/// // Without client config parameter (will create new client)
/// #[request_authorization("my-resource")]
/// async fn simple_protected_function(base_url: &str, mtls_cert: &str, mtls_key: &str, server_ca: &str) {
///     // This function will be called after token is obtained
/// }
/// ```
#[proc_macro_attribute]
pub fn request_authorization(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as MacroArgs);
    let input = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input.sig.ident;
    let fn_args = &input.sig.inputs;
    let fn_generics = &input.sig.generics;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_vis = &input.vis;
    
    let is_async = input.sig.asyncness.is_some();
    let resource = &args.resource;
    
    // Check if the function has parameters needed for client config
    let has_config_param = args.config_param.is_some();
    let config_param = args.config_param;
    
    // Create parameter list for the forwarding call
    let args: Vec<_> = fn_args.iter().filter_map(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return Some(ident);
            }
        }
        None
    }).collect();
    
    let expanded = if is_async {
        if has_config_param {
            // Use the provided client config parameter
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Request a token for the resource using the provided client config
                    let resource = #resource.to_string();
                    let token = #config_param.request_token(resource)
                        .await
                        .expect("Failed to request authorization token");
                    
                    // Call the original function
                    #fn_body
                }
            }
        } else {
            // Create a new client from function parameters
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Create a new client from parameters
                    // Assume the function has parameters: base_url, port (optional), mtls_cert, mtls_key, server_ca
                    let client = hessra_sdk::HessraClient::builder()
                        .base_url(base_url)
                        .protocol(hessra_sdk::Protocol::Http1)
                        .mtls_cert(mtls_cert)
                        .mtls_key(mtls_key)
                        .server_ca(server_ca)
                        .build()
                        .expect("Failed to build Hessra client");
                    
                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = client.request_token(resource)
                        .await
                        .expect("Failed to request authorization token");
                    
                    // Call the original function
                    #fn_body
                }
            }
        }
    } else {
        // For synchronous functions
        if has_config_param {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token request
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
                    
                    // Request a token for the resource using the provided client config
                    let resource = #resource.to_string();
                    let token = rt.block_on(#config_param.request_token(resource))
                        .expect("Failed to request authorization token");
                    
                    // Call the original function
                    #fn_body
                }
            }
        } else {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token request
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
                    
                    // Create a new client from parameters
                    // Assume the function has parameters: base_url, port (optional), mtls_cert, mtls_key, server_ca
                    let client = hessra_sdk::HessraClient::builder()
                        .base_url(base_url)
                        .protocol(hessra_sdk::Protocol::Http1)
                        .mtls_cert(mtls_cert)
                        .mtls_key(mtls_key)
                        .server_ca(server_ca)
                        .build()
                        .expect("Failed to build Hessra client");
                    
                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = rt.block_on(client.request_token(resource))
                        .expect("Failed to request authorization token");
                    
                    // Call the original function
                    #fn_body
                }
            }
        }
    };
    
    TokenStream::from(expanded)
}

/// Macro to wrap a function with authorization verification logic
///
/// This macro will verify an authorization token for a given resource
/// before executing the wrapped function. It supports both synchronous
/// and asynchronous functions.
///
/// # Example
///
/// ```
/// use hessra_macros::authorize;
///
/// // With client config parameter
/// #[authorize("my-resource", client_config)]
/// async fn protected_function(token: String, client_config: &HessraClient) {
///     // This function will be called if token is valid
/// }
///
/// // Without client config parameter (will create new client)
/// #[authorize("my-resource")]
/// async fn simple_protected_function(token: String, base_url: &str, mtls_cert: &str, mtls_key: &str, server_ca: &str) {
///     // This function will be called if token is valid
/// }
/// ```
#[proc_macro_attribute]
pub fn authorize(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as MacroArgs);
    let input = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input.sig.ident;
    let fn_args = &input.sig.inputs;
    let fn_generics = &input.sig.generics;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_vis = &input.vis;
    
    let is_async = input.sig.asyncness.is_some();
    let resource = &args.resource;
    
    // Check if the function has a dedicated client config parameter
    let has_config_param = args.config_param.is_some();
    let config_param = args.config_param;
    
    // Find the token parameter
    let token_param = fn_args.iter().find_map(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                if ident == "token" {
                    return Some(ident);
                }
            }
        }
        None
    });
    
    let token_ident = match token_param {
        Some(ident) => ident,
        None => {
            return syn::Error::new_spanned(
                &input.sig,
                "The function must have a 'token' parameter to use the authorize macro",
            )
            .to_compile_error()
            .into();
        }
    };
    
    let expanded = if is_async {
        if has_config_param {
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Verify the token for the specified resource using provided client config
                    let resource = #resource.to_string();
                    let verification_result = #config_param.verify_token(#token_ident.clone(), resource).await;
                    
                    match verification_result {
                        Ok(_) => {
                            // Token is valid, proceed with the function
                            #fn_body
                        },
                        Err(e) => {
                            // Token is invalid, return an error
                            panic!("Authorization failed: {}", e);
                        }
                    }
                }
            }
        } else {
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Create a new client from parameters
                    // Assume the function has parameters: base_url, port (optional), mtls_cert, mtls_key, server_ca
                    let client = hessra_sdk::HessraClient::builder()
                        .base_url(base_url)
                        .protocol(hessra_sdk::Protocol::Http1)
                        .mtls_cert(mtls_cert)
                        .mtls_key(mtls_key)
                        .server_ca(server_ca)
                        .build()
                        .expect("Failed to build Hessra client");
                    
                    // Verify the token for the specified resource
                    let resource = #resource.to_string();
                    let verification_result = client.verify_token(#token_ident.clone(), resource).await;
                    
                    match verification_result {
                        Ok(_) => {
                            // Token is valid, proceed with the function
                            #fn_body
                        },
                        Err(e) => {
                            // Token is invalid, return an error
                            panic!("Authorization failed: {}", e);
                        }
                    }
                }
            }
        }
    } else {
        // For synchronous functions
        if has_config_param {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token verification
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
                    
                    // Verify the token for the specified resource using provided client config
                    let resource = #resource.to_string();
                    let verification_result = rt.block_on(#config_param.verify_token(#token_ident.clone(), resource));
                    
                    match verification_result {
                        Ok(_) => {
                            // Token is valid, proceed with the function
                            #fn_body
                        },
                        Err(e) => {
                            // Token is invalid, return an error
                            panic!("Authorization failed: {}", e);
                        }
                    }
                }
            }
        } else {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token verification
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
                    
                    // Create a new client from parameters
                    // Assume the function has parameters: base_url, port (optional), mtls_cert, mtls_key, server_ca
                    let client = hessra_sdk::HessraClient::builder()
                        .base_url(base_url)
                        .protocol(hessra_sdk::Protocol::Http1)
                        .mtls_cert(mtls_cert)
                        .mtls_key(mtls_key)
                        .server_ca(server_ca)
                        .build()
                        .expect("Failed to build Hessra client");
                    
                    // Verify the token for the specified resource
                    let resource = #resource.to_string();
                    let verification_result = rt.block_on(client.verify_token(#token_ident.clone(), resource));
                    
                    match verification_result {
                        Ok(_) => {
                            // Token is valid, proceed with the function
                            #fn_body
                        },
                        Err(e) => {
                            // Token is invalid, return an error
                            panic!("Authorization failed: {}", e);
                        }
                    }
                }
            }
        }
    };
    
    TokenStream::from(expanded)
}
