
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
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_common.h>

#include "packdev_common.h"
#include "packdev_session.h"

#define SESSION_CONFIG_FILE "packdev_session.conf"

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
    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, SESSION_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", SESSION_CONFIG_FILE);
    }

    gsize num_sessions = 0;
    gchar **sessions = g_key_file_get_groups(gkf, &num_sessions);
    for (guint index = 0; index < num_sessions; index++) {
         gint session_id = g_key_file_get_integer(gkf, sessions[index], "session_id", &error);
         gint src_addr;
         inet_pton(AF_INET, g_key_file_get_string(gkf, sessions[index], "src_addr", &error),
                     &src_addr);
         gint dst_addr;
         inet_pton(AF_INET, g_key_file_get_string(gkf, sessions[index], "dst_addr", &error),
                     &dst_addr);
         gint src_port = g_key_file_get_integer(gkf, sessions[index], "src_port", &error);
         gint dst_port = g_key_file_get_integer(gkf, sessions[index], "dst_port", &error);
         add_session(session_id, rte_cpu_to_be_32(src_addr), rte_cpu_to_be_32(dst_addr), src_port, dst_port);
    }
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
