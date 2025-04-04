#include <stdio.h>
#include <stdlib.h>
#include "hessra.h"

int main(int argc, char** argv) {
    HessraResult result;
    
    // Initialize the library
    result = hessra_init();
    if (result != HESSRA_SUCCESS) {
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
    HessraConfig config;
    result = hessra_config_new(&config);
    if (result != HESSRA_SUCCESS) {
        char* error_message = hessra_error_message(result);
        fprintf(stderr, "Failed to create configuration: %s\n", error_message);
        hessra_string_free(error_message);
        return 1;
    }
    
    // Clean up
    hessra_config_free(config);
    
    printf("Hessra FFI test completed successfully\n");
    return 0;
} 