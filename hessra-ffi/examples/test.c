#include <stdio.h>
#include <stdlib.h>
#include "hessra_ffi.h"

// Sample PEM public key for testing
const char* SAMPLE_PEM_KEY = 
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGAUzRTY2LVRR8yzO+45XybYb4sQl\n"
    "fWzpanBaJK86c5ebg+UV4vhfR/0H4IzPpTaiHPEPH9Y6WZB0O0Ixb1u9vQ==\n"
    "-----END PUBLIC KEY-----\n";

// Sample token for testing
const char* SAMPLE_TOKEN = "token_data_here"; // Replace with a valid token

int main(int argc, char** argv) {
    HessraResult result;
    
    // Initialize the library
    result = hessra_init();
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to initialize Hessra: %s\n", error_message);
        hessra_string_free(error_message);
        return 1;
    }
    
    // Get the version
    const char* version = hessra_version();
    printf("Hessra version: %s\n", version);
    hessra_string_free((char*)version);
    
    // Create a configuration
    HessraConfig* config = NULL;
    result = hessra_config_new(&config);
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to create configuration: %s\n", error_message);
        hessra_string_free(error_message);
        return 1;
    }
    
    // Create a public key from string
    HessraPublicKey* public_key = NULL;
    result = hessra_public_key_from_string(SAMPLE_PEM_KEY, &public_key);
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to create public key: %s\n", error_message);
        hessra_string_free(error_message);
        hessra_config_free(config);
        return 1;
    }
    
    // Set the public key in the configuration
    result = hessra_config_set_public_key(config, public_key);
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to set public key in configuration: %s\n", error_message);
        hessra_string_free(error_message);
        hessra_public_key_free(public_key);
        hessra_config_free(config);
        return 1;
    }
    
    // Get the public key from the configuration
    HessraPublicKey* retrieved_key = NULL;
    result = hessra_config_get_public_key(config, &retrieved_key);
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to get public key from configuration: %s\n", error_message);
        hessra_string_free(error_message);
        hessra_public_key_free(public_key);
        hessra_config_free(config);
        return 1;
    }
    
    // Verify a token
    // Note: This will likely fail with the sample data but demonstrates the API
    printf("Attempting to verify token...\n");
    result = hessra_token_verify(SAMPLE_TOKEN, retrieved_key, "subject1", "resource1", "read");
    if (result != SUCCESS) {
        char* error_message = hessra_error_message(result);
        printf("Token verification result: %s (expected in this example)\n", error_message);
        hessra_string_free(error_message);
    } else {
        printf("Token verification succeeded.\n");
    }
    
    // Clean up
    hessra_public_key_free(public_key);
    hessra_public_key_free(retrieved_key);
    hessra_config_free(config);
    
    printf("Hessra FFI test completed successfully\n");
    return 0;
} 