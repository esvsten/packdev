
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <glib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>

#include "packdev_common.h"
#include "packdev_crypto.h"
#include "packdev_sa_config.h"

#define SA_CONFIG_FILE "packdev_sa.conf"

struct rte_hash *global_sa_table;
struct rte_hash_parameters sa_table_params;

packdev_sa_t sas[MAX_NUM_OF_SAS];

static void add_sa_session(
        uint32_t sa_id,
        struct sa_config_t *config) {
    struct rte_crypto_sym_xform *init_xform;
    struct rte_crypto_sym_xform cipher_xform;
    struct rte_crypto_sym_xform auth_xform;
    memset(&cipher_xform, 0, sizeof(cipher_xform));
    cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher_xform.cipher.algo = config->encr_algorithm;
    cipher_xform.cipher.key.length = 16;
    cipher_xform.cipher.key.data =
        rte_malloc("crypto key", cipher_xform.cipher.key.length, 0);
    rte_memcpy(
            cipher_xform.cipher.key.data,
            config->encr_key,
            cipher_xform.cipher.key.length);
    cipher_xform.cipher.iv.offset = SYM_IV_OFFSET;
    cipher_xform.cipher.iv.length = sas[sa_id].iv_length;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    cipher_xform.next = NULL;

    memset(&auth_xform, 0, sizeof(auth_xform));
    auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    auth_xform.auth.algo = config->auth_algorithm;
    auth_xform.auth.key.length = 20;
    auth_xform.auth.key.data =
        rte_malloc("auth key", auth_xform.auth.key.length, 0);
    rte_memcpy(
            auth_xform.auth.key.data,
            config->auth_key,
            auth_xform.auth.key.length);
    auth_xform.auth.digest_length = sas[sa_id].digest_length;
    auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
    auth_xform.next = &cipher_xform;

    // for decryption, first perform auth, then decryption
    init_xform = &auth_xform;

    /* Create crypto session and initialize it for the crypto device. */
    packdev_crypto_dev_t* crypto_dev = packdev_crypto_get_device();
    sas[sa_id].session= rte_cryptodev_sym_session_create(crypto_dev->session_pool);
    if (sas[sa_id].session == NULL) {
        rte_exit(EXIT_FAILURE,
                "SA: Symmetric session could not be created\n");
    }

    if (rte_cryptodev_sym_session_init(
                crypto_dev->id,
                sas[sa_id].session,
                init_xform,
                crypto_dev->session_pool) < 0) {
        rte_exit(EXIT_FAILURE,
                "SA: Session could not be initialized\n");
    }

    uint32_t key = rte_jhash(&sas[sa_id].attr, sizeof(sas[sa_id].attr), SA_TABLE_IV);
    rte_hash_add_key_data(
            global_sa_table,
            &key,
            (void*)((uintptr_t)sa_id));
#if 0
    RTE_LOG(DEBUG, USER1, "SA: SPI=0x%08x\n", sas[sa_id].attr.spi);
    RTE_LOG(DEBUG, USER1, "SA: local_addr=0x%08x\n", sas[sa_id].attr.local_addr);
    RTE_LOG(DEBUG, USER1, "SA: remote_addr=0x%08x\n", sas[sa_id].attr.remote_addr);
#endif
    RTE_LOG(DEBUG, USER1, "SA: Added hash = 0x%08x\n", key);
}

static void add_sa(
        uint32_t sa_id,
        uint32_t spi,
        packdev_encr_t encr_alg,
        char *encr_key,
        packdev_auth_t auth_alg,
        char *auth_key,
        uint32_t local_addr,
        uint32_t remote_addr) {
    memset(&sas[sa_id], 0, sizeof(sas[sa_id]));
    sas[sa_id].attr.spi = spi;
    sas[sa_id].attr.local_addr = local_addr;
    sas[sa_id].attr.remote_addr = remote_addr;
    sas[sa_id].sa_id = sa_id;
    sas[sa_id].iv_length = 16;
    sas[sa_id].digest_length = 12;

    struct sa_config_t sa_config;
    sa_config.encr_algorithm = encr_alg;
    rte_memcpy(sa_config.encr_key, encr_key, strlen(encr_key));
    sa_config.auth_algorithm = auth_alg;
    rte_memcpy(sa_config.auth_key, auth_key, strlen(auth_key));

    add_sa_session(sa_id, &sa_config);
}

static void setup_sa_config() {
    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, SA_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", SA_CONFIG_FILE);
    }

    gsize num_sas = 0;
    gchar **sas = g_key_file_get_groups(gkf, &num_sas);
    for (guint index = 0; index < num_sas; index++) {
         gint sa_id = g_key_file_get_integer(gkf, sas[index], "sa_id", &error);
         gint spi = g_key_file_get_integer(gkf, sas[index], "spi", &error);
         packdev_encr_t encr_alg = PACKDEV_ENCR_NULL;
         gchar* alg = g_key_file_get_string(gkf, sas[index], "encr_alg", &error);
         if (strcmp(alg, "AES_128_CBC") == 0) {
             encr_alg = PACKDEV_ENCR_AES_128_CBC;
         }
         gchar* encr_key = g_key_file_get_string(gkf, sas[index], "encr_key", &error);
         packdev_auth_t auth_alg = PACKDEV_ENCR_NULL;
         alg = g_key_file_get_string(gkf, sas[index], "auth_alg", &error);
         if (strcmp(alg, "HMAC_SHA1") == 0) {
             auth_alg = PACKDEV_AUTH_HMAC_SHA1;
         }
         gchar* auth_key = g_key_file_get_string(gkf, sas[index], "auth_key", &error);
         gint local_addr;
         inet_pton(AF_INET, g_key_file_get_string(gkf, sas[index], "local_addr", &error),
                     &local_addr);
         gint remote_addr;
         inet_pton(AF_INET, g_key_file_get_string(gkf, sas[index], "remote_addr", &error),
                     &remote_addr);
         add_sa(sa_id, spi, encr_alg, encr_key, auth_alg, auth_key,
                 rte_bswap32(local_addr), rte_bswap32(remote_addr));
    }
}

void packdev_sa_config_init() {
    memset(&sa_table_params, 0, sizeof(sa_table_params));
    sa_table_params.name = "packdev-sa";
    sa_table_params.entries = MAX_NUM_OF_SAS;
    sa_table_params.key_len = sizeof(uint32_t);
    sa_table_params.hash_func = rte_jhash;
    sa_table_params.hash_func_init_val = 0;

    global_sa_table = rte_hash_create(&sa_table_params);
    if (global_sa_table == NULL) {
        rte_exit(EXIT_FAILURE, "SA: Could not create hash table!!!\n");
    }

    setup_sa_config();
}

packdev_sa_t* packdev_sa_config_get(uint32_t sa_id) {
    if (sa_id >= MAX_NUM_OF_SAS || sas[sa_id].attr.spi == 0) {
        return NULL;
    }

    return &sas[sa_id];
}

struct rte_hash* packdev_sa_config_get_table() {
    return global_sa_table;
}
