#ifndef PACKDEV_SA_CONFIG_H_
#define PACKDEV_SA_CONFIG_H_

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>

#define SA_TABLE_IV 255

typedef enum {
    PACKDEV_ENCR_NULL          = RTE_CRYPTO_CIPHER_NULL,
    PACKDEV_ENCR_AES_128_CBC   = RTE_CRYPTO_CIPHER_AES_CBC,
    PACKDEV_ENCR_MAX           = RTE_CRYPTO_CIPHER_LIST_END
} packdev_encr_t;

typedef enum {
    PACKDEV_AUTH_NULL          = RTE_CRYPTO_AUTH_NULL,
    PACKDEV_AUTH_HMAC_MD5      = RTE_CRYPTO_AUTH_MD5_HMAC,
    PACKDEV_AUTH_HMAC_SHA1     = RTE_CRYPTO_AUTH_SHA1_HMAC,
    PACKDEV_AUTH_MAX
} packdev_auth_t;

struct sa_attr_t {
    uint32_t spi;
    uint32_t local_addr;
    uint32_t remote_addr;
};

struct sa_config_t {
    packdev_encr_t encr_algorithm;
    uint8_t encr_key[MAX_ENCR_KEY_LENGTH];

    packdev_auth_t auth_algorithm;
    uint8_t auth_key[MAX_AUTH_KEY_LENGTH];
};

typedef struct {
    uint32_t sa_id;
    uint32_t iv_length;
    uint32_t digest_length;

    struct sa_attr_t attr;
    struct rte_cryptodev_sym_session *session;
} packdev_sa_t;


void packdev_sa_config_init();

packdev_sa_t* packdev_sa_config_get(uint32_t sa_id);

struct rte_hash* packdev_sa_config_get_table();

#endif /* PACKDEV_SA_CONFIG_H_ */
