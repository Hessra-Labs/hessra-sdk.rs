/**
 * @file hessra.h
 * @brief C interface for Hessra token verification and configuration
 */

#ifndef HESSRA_H
#define HESSRA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * @brief Result codes for Hessra functions
 */
typedef enum {
    HESSRA_SUCCESS = 0,
    HESSRA_ERROR_INVALID_TOKEN = 1,
    HESSRA_ERROR_INVALID_KEY = 2,
    HESSRA_ERROR_VERIFICATION_FAILED = 3,
    HESSRA_ERROR_CONFIG_INVALID = 4,
    HESSRA_ERROR_MEMORY = 5,
    HESSRA_ERROR_IO = 6,
    HESSRA_ERROR_INVALID_PARAMETER = 7,
    HESSRA_ERROR_UNKNOWN = 999,
} HessraResult;

/**
 * @brief Opaque handle to a Hessra public key
 */
typedef struct HessraPublicKey HessraPublicKey;

/**
 * @brief Opaque handle to a Hessra configuration
 */
typedef struct HessraConfig HessraConfig;

/**
 * @brief Initialize the Hessra library
 * @return Result code indicating success or failure
 */
HessraResult hessra_init(void);

/**
 * @brief Get the version string of the Hessra library
 * @return Version string (must be freed with hessra_string_free)
 */
const char* hessra_version(void);

/**
 * @brief Free a string allocated by the Hessra library
 * @param string String to free
 */
void hessra_string_free(char* string);

/**
 * @brief Get a human-readable error message for a result code
 * @param result Result code to get message for
 * @return Error message (must be freed with hessra_string_free)
 */
char* hessra_error_message(HessraResult result);

/**
 * @brief Verify a token against a public key
 * @param token_string String representation of the token
 * @param public_key Public key to verify against
 * @param subject Optional subject to check (can be NULL)
 * @param resource Optional resource to check (can be NULL)
 * @return Result code indicating success or failure
 */
HessraResult hessra_token_verify(
    const char* token_string,
    HessraPublicKey* public_key,
    const char* subject,
    const char* resource
);

/**
 * @brief Verify a token with service chain validation
 * @param token_string String representation of the token
 * @param public_key Public key to verify against
 * @param subject Optional subject to check (can be NULL)
 * @param resource Optional resource to check (can be NULL)
 * @param service_nodes_json JSON string containing service nodes configuration
 * @param component Optional component identifier (can be NULL)
 * @return Result code indicating success or failure
 */
HessraResult hessra_token_verify_service_chain(
    const char* token_string,
    HessraPublicKey* public_key,
    const char* subject,
    const char* resource,
    const char* service_nodes_json,
    const char* component
);

/**
 * @brief Create a new public key from a string
 * @param key_string PEM-encoded public key
 * @param out_key Output parameter for the created key
 * @return Result code indicating success or failure
 */
HessraResult hessra_public_key_from_string(
    const char* key_string,
    HessraPublicKey** out_key
);

/**
 * @brief Create a new public key from a file
 * @param file_path Path to a file containing a PEM-encoded public key
 * @param out_key Output parameter for the created key
 * @return Result code indicating success or failure
 */
HessraResult hessra_public_key_from_file(
    const char* file_path,
    HessraPublicKey** out_key
);

/**
 * @brief Free a public key
 * @param key Public key to free
 */
void hessra_public_key_free(HessraPublicKey* key);

/**
 * @brief Create a new empty configuration
 * @param out_config Output parameter for the created configuration
 * @return Result code indicating success or failure
 */
HessraResult hessra_config_new(HessraConfig** out_config);

/**
 * @brief Load configuration from a file
 * @param file_path Path to a configuration file
 * @param out_config Output parameter for the loaded configuration
 * @return Result code indicating success or failure
 */
HessraResult hessra_config_from_file(
    const char* file_path,
    HessraConfig** out_config
);

/**
 * @brief Free a configuration
 * @param config Configuration to free
 */
void hessra_config_free(HessraConfig* config);

/**
 * @brief Set public key in the configuration
 * @param config Configuration to set the public key in
 * @param key Public key to set
 * @return Result code indicating success or failure
 */
HessraResult hessra_config_set_public_key(
    HessraConfig* config,
    HessraPublicKey* key
);

/**
 * @brief Get public key from the configuration
 * @param config Configuration to get the public key from
 * @param out_key Output parameter for the retrieved public key
 * @return Result code indicating success or failure
 */
HessraResult hessra_config_get_public_key(
    HessraConfig* config,
    HessraPublicKey** out_key
);

#ifdef __cplusplus
}
#endif

#endif /* HESSRA_H */ 