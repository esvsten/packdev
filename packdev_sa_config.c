
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>

#include "packdev_common.h"
#include "packdev_crypto.h"
#include "packdev_sa_config.h"

struct rte_hash *global_sa_table;
struct rte_hash_parameters sa_table_params;

packdev_sa_t sas[MAX_NUM_OF_SAS];

static void add_sa_session(uint32_t sa_id) {
    struct rte_crypto_sym_xform *init_xform;
    struct rte_crypto_sym_xform cipher;
    struct rte_crypto_sym_xform auth;
    memset(&cipher, 0, sizeof(cipher));
    cipher.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher.cipher.algo = sas[sa_id].config.encr_algorithm;
    cipher.cipher.key.data = sas[sa_id].config.encr_key;
    cipher.cipher.key.length = 16;
    cipher.cipher.iv.offset = SYM_IV_OFFSET;
    cipher.cipher.iv.length = sas[sa_id].config.iv_length;
    cipher.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    cipher.next = NULL;

    memset(&auth, 0, sizeof(auth));
    auth.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    auth.auth.algo = sas[sa_id].config.auth_algorithm;
    auth.auth.key.data = sas[sa_id].config.auth_key;
    auth.auth.key.length = 20;
    auth.auth.digest_length = sas[sa_id].config.digest_length;
    auth.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
    auth.next = &cipher;

    // for encryption, first perform auth, then decryption
    init_xform = &auth;

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
    RTE_LOG(DEBUG, USER1, "SA: Added hash = 0x%08x\n", key);
}

static void add_sa(
        uint32_t sa_id,
        uint32_t spi,
        uint32_t local_addr,
        uint32_t remote_addr) {
    char *encr_key = "aescbcencryption";
    //uint8_t encr_key[16] = {'a', 'e', 's', 'c', 'b', 'c', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n'};
    char *auth_key = "hmacsha1authenticati";
    //uint8_t auth_key[20] = {
    //    'h', 'm', 'a', 'c', 's', 'h', 'a', '1', 'a', 'u',
    //    't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i'};
    memset(&sas[sa_id], 0, sizeof(sas[sa_id]));
    sas[sa_id].attr.spi = spi;
    sas[sa_id].attr.local_addr = local_addr;
    sas[sa_id].attr.remote_addr = remote_addr;
    sas[sa_id].config.sa_id = sa_id;
    sas[sa_id].config.encr_algorithm = PACKDEV_ENCR_AES_128_CBC;
    memcpy(sas[sa_id].config.encr_key, encr_key, strlen(encr_key));
    sas[sa_id].config.iv_length = 16;
    sas[sa_id].config.auth_algorithm = PACKDEV_AUTH_HMAC_SHA1;
    memcpy(sas[sa_id].config.auth_key, auth_key, strlen(auth_key));
    sas[sa_id].config.digest_length = 12;

    add_sa_session(sa_id);
}

static void setup_sa_config() {
    uint32_t sa_id = 1;
    add_sa(sa_id++, 0xa, IPv4(10,0,0,2), IPv4(10,0,0,1));
    add_sa(sa_id++, 0x2, IPv4(192,168,1,1), IPv4(192,168,1,2));
    add_sa(sa_id++, 0x3, IPv4(192,168,2,1), IPv4(192,168,2,2));
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
