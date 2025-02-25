extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, FnArg, Ident, ItemFn, LitStr, Pat,
    PatIdent, Token,
};

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
/// async fn protected_function(client_config: &HessraConfig) {
///     // This function will be called after token is obtained
/// }
///
/// // Using global configuration
/// #[request_authorization("my-resource")]
/// async fn simple_protected_function() {
///     // This function will be called after token is obtained using global config
/// }
///
/// // With individual connection parameters
/// #[request_authorization("my-resource")]
/// async fn custom_protected_function(base_url: &str, mtls_cert: &str, mtls_key: &str, server_ca: &str) {
///     // This function will be called after token is obtained using provided parameters
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

    // Check if any of the function parameters can be used for client config
    let has_base_url_param = fn_args.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return ident == "base_url";
            }
        }
        false
    });

    // Create parameter list for the forwarding call
    let _args: Vec<_> = fn_args
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    return Some(ident);
                }
            }
            None
        })
        .collect();

    let expanded = if is_async {
        if has_config_param {
            // Use the provided client config parameter
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Create client from the provided configuration
                    let client = #config_param.create_client()
                        .expect("Failed to create Hessra client from configuration");

                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = client.request_token(resource)
                        .await
                        .expect("Failed to request authorization token");

                    // Call the original function
                    #fn_body
                }
            }
        } else if has_base_url_param {
            // Create a new client from function parameters
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Create a temporary configuration from parameters
                    let config = hessra_sdk::HessraConfig::new(
                        base_url,
                        None, // default port
                        hessra_sdk::Protocol::Http1,
                        mtls_cert,
                        mtls_key,
                        server_ca
                    );

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from parameters");

                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = client.request_token(resource)
                        .await
                        .expect("Failed to request authorization token");

                    // Call the original function
                    #fn_body
                }
            }
        } else {
            // Use global configuration
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Get the global configuration
                    let config = hessra_sdk::get_default_config()
                        .or_else(|| hessra_sdk::try_load_default_config().as_ref())
                        .expect("No Hessra configuration found. Set a default configuration or provide parameters.");

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from global configuration");

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

                    // Create client from the provided configuration
                    let client = #config_param.create_client()
                        .expect("Failed to create Hessra client from configuration");

                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = rt.block_on(client.request_token(resource))
                        .expect("Failed to request authorization token");

                    // Call the original function
                    #fn_body
                }
            }
        } else if has_base_url_param {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token request
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

                    // Create a temporary configuration from parameters
                    let config = hessra_sdk::HessraConfig::new(
                        base_url,
                        None, // default port
                        hessra_sdk::Protocol::Http1,
                        mtls_cert,
                        mtls_key,
                        server_ca
                    );

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from parameters");

                    // Request a token for the resource
                    let resource = #resource.to_string();
                    let token = rt.block_on(client.request_token(resource))
                        .expect("Failed to request authorization token");

                    // Call the original function
                    #fn_body
                }
            }
        } else {
            // Use global configuration
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token request
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

                    // Get the global configuration
                    let config = hessra_sdk::get_default_config()
                        .or_else(|| hessra_sdk::try_load_default_config().as_ref())
                        .expect("No Hessra configuration found. Set a default configuration or provide parameters.");

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from global configuration");

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
/// async fn protected_function(token: String, client_config: &HessraConfig) {
///     // This function will be called if token is valid
/// }
///
/// // Using global configuration
/// #[authorize("my-resource")]
/// async fn simple_protected_function(token: String) {
///     // This function will be called if token is valid using global config
/// }
///
/// // With individual connection parameters
/// #[authorize("my-resource")]
/// async fn custom_protected_function(token: String, base_url: &str, mtls_cert: &str, mtls_key: &str, server_ca: &str) {
///     // This function will be called if token is valid using provided parameters
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

    // Check if any of the function parameters can be used for client config
    let has_base_url_param = fn_args.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return ident == "base_url";
            }
        }
        false
    });

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
                    // Create client from the provided configuration
                    let client = #config_param.create_client()
                        .expect("Failed to create Hessra client from configuration");

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
        } else if has_base_url_param {
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Create a temporary configuration from parameters
                    let config = hessra_sdk::HessraConfig::new(
                        base_url,
                        None, // default port
                        hessra_sdk::Protocol::Http1,
                        mtls_cert,
                        mtls_key,
                        server_ca
                    );

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from parameters");

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
        } else {
            // Use global configuration
            quote! {
                #fn_vis #fn_generics async fn #fn_name(#fn_args) #fn_output {
                    // Get the global configuration
                    let config = hessra_sdk::get_default_config()
                        .or_else(|| hessra_sdk::try_load_default_config().as_ref())
                        .expect("No Hessra configuration found. Set a default configuration or provide parameters.");

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from global configuration");

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

                    // Create client from the provided configuration
                    let client = #config_param.create_client()
                        .expect("Failed to create Hessra client from configuration");

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
        } else if has_base_url_param {
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token verification
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

                    // Create a temporary configuration from parameters
                    let config = hessra_sdk::HessraConfig::new(
                        base_url,
                        None, // default port
                        hessra_sdk::Protocol::Http1,
                        mtls_cert,
                        mtls_key,
                        server_ca
                    );

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from parameters");

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
        } else {
            // Use global configuration
            quote! {
                #fn_vis #fn_generics fn #fn_name(#fn_args) #fn_output {
                    // Create a runtime for the asynchronous token verification
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

                    // Get the global configuration
                    let config = hessra_sdk::get_default_config()
                        .or_else(|| hessra_sdk::try_load_default_config().as_ref())
                        .expect("No Hessra configuration found. Set a default configuration or provide parameters.");

                    // Create client from the config
                    let client = config.create_client()
                        .expect("Failed to create Hessra client from global configuration");

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
