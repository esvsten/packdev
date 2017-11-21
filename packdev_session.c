
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

#include "packdev_common.h"
#include "packdev_session.h"

// TODO: Replace with rte_flow instead of rte_hash table
struct rte_hash *global_session_table;
struct rte_hash_parameters session_table_params;

static void add_session(
        uint32_t session_id,
        uint32_t src_addr,
        uint32_t dst_addr,
        uint32_t src_port,
        uint32_t dst_port) {
    ipv4_session_config_t session = {
        .src_addr = src_addr,
        .dst_addr = dst_addr,
        .src_port = src_port,
        .dst_port = dst_port,
    };

    uint32_t key = rte_jhash(&session, sizeof(session), SESSION_IV);
    rte_hash_add_key_data(
            global_session_table,
            &key,
            (void*)((uintptr_t)session_id));

    RTE_LOG(DEBUG, USER1, "Session: Added key = 0x%08x\n", key);
}

static void setup_session_config() {
    uint32_t session_id = 1;
    add_session(
            session_id++,
            IPv4(192,168,17,114),
            IPv4(192,168,0,2),
            10,
            11);
    add_session(
            session_id++,
            IPv4(192,168,0,1),
            IPv4(192,168,16,36),
            20,
            21);
    add_session(
            session_id++,
            IPv4(192,168,17,114),
            IPv4(192,168,16,36),
            47043,
            9995);
}

void packdev_session_init() {
    memset(&session_table_params, 0, sizeof(session_table_params));
    session_table_params.name = "packdev-session";
    session_table_params.entries = 500;
    session_table_params.key_len = sizeof(uint32_t);
    session_table_params.hash_func = rte_jhash;
    session_table_params.hash_func_init_val = 0;

    global_session_table = rte_hash_create(&session_table_params);
    if (global_session_table == NULL) {
        rte_exit(EXIT_FAILURE, "SESSION: Could not create hash table!!!\n");
    }

    setup_session_config();
}

struct rte_hash* packdev_session_get_table() {
    return global_session_table;
}
