#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Result type for Hessra FFI functions.
 */
typedef enum HessraResult {
  SUCCESS = 0,
  ERROR_INVALID_TOKEN = 1,
  ERROR_INVALID_KEY = 2,
  ERROR_VERIFICATION_FAILED = 3,
  ERROR_CONFIG_INVALID = 4,
  ERROR_MEMORY = 5,
  ERROR_IO = 6,
  ERROR_INVALID_PARAMETER = 7,
  ERROR_UNKNOWN = 999,
} HessraResult;

typedef struct ConfigHandle ConfigHandle;

typedef struct PublicKeyHandle PublicKeyHandle;

/**
 * Opaque type representing a Hessra public key
 */
typedef struct HessraPublicKey {
  struct PublicKeyHandle *_0;
} HessraPublicKey;

/**
 * Opaque type representing a Hessra configuration
 */
typedef struct HessraConfig {
  struct ConfigHandle *_0;
} HessraConfig;

/**
 * Version information for the Hessra FFI library
 */
const char *hessra_version(void);

/**
 * Free a string allocated by the Hessra library
 *
 * # Safety
 *
 * This function must only be called with a pointer that was previously returned by a
 * Hessra library function that returns a string (like `hessra_version`).
 * The pointer must not be null and must not have been freed before.
 * After this call, the pointer is invalid and should not be used.
 */
void hessra_string_free(char *string);

/**
 * Initialize the Hessra library.
 * This function should be called before using any other functions.
 */
enum HessraResult hessra_init(void);

/**
 * Create a new public key from a string
 */
enum HessraResult hessra_public_key_from_string(const char *key_string,
                                                struct HessraPublicKey **out_key);

/**
 * Create a new public key from a file
 */
enum HessraResult hessra_public_key_from_file(const char *file_path,
                                              struct HessraPublicKey **out_key);

/**
 * Free a public key
 *
 * # Safety
 *
 * This function must only be called with a valid HessraPublicKey that was previously created
 * by functions like `hessra_public_key_from_string` or `hessra_public_key_from_file`.
 * The key must not have been freed before. After this call, the key is invalid and should not be used.
 */
void hessra_public_key_free(struct HessraPublicKey *key);

/**
 * Create a new empty configuration
 */
enum HessraResult hessra_config_new(struct HessraConfig **out_config);

/**
 * Load configuration from a file
 */
enum HessraResult hessra_config_from_file(const char *file_path, struct HessraConfig **out_config);

/**
 * Free a configuration
 *
 * # Safety
 *
 * This function must only be called with a valid HessraConfig that was previously created
 * by functions like `hessra_config_new` or `hessra_config_from_file`.
 * The config must not have been freed before. After this call, the config is invalid and should not be used.
 */
void hessra_config_free(struct HessraConfig *config);

/**
 * Set public key in the configuration
 *
 * # Arguments
 *
 * * `config` - Configuration to set the public key in
 * * `key` - Public key to set
 *
 * # Returns
 *
 * Result code indicating success or failure
 */
enum HessraResult hessra_config_set_public_key(struct HessraConfig *config,
                                               struct HessraPublicKey *key);

/**
 * Get public key from the configuration
 *
 * # Arguments
 *
 * * `config` - Configuration to get the public key from
 * * `out_key` - Output parameter for the retrieved public key
 *
 * # Returns
 *
 * Result code indicating success or failure
 */
enum HessraResult hessra_config_get_public_key(struct HessraConfig *config,
                                               struct HessraPublicKey **out_key);

/**
 * Get a human-readable error message for a result code
 */
char *hessra_error_message(enum HessraResult result);

/**
 * Parse a token from a string and verify it
 */
enum HessraResult hessra_token_verify(const char *token_string,
                                      struct HessraPublicKey *public_key,
                                      const char *subject,
                                      const char *resource);

/**
 * Parse a token from a string with service chain validation
 */
enum HessraResult hessra_token_verify_service_chain(const char *token_string,
                                                    struct HessraPublicKey *public_key,
                                                    const char *subject,
                                                    const char *resource,
                                                    const char *service_nodes_json,
                                                    const char *component);
