
#include <arpa/inet.h>
#include <glib.h>
#include <stdint.h>
#include <unistd.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lpm.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "sys/packdev_common.h"
#include "sys/packdev_config.h"

#include "fp/packdev_ipv4.h"

#include "cp/packdev_l3_config.h"

#define L3_CONFIG_FILE "packdev_l3.conf"
#define ROUTE_CONFIG_FILE "packdev_route.conf"

packdev_l3_if_t l3_if[MAX_NUM_L3_IFS];

#define NH_TABLE_IV 435
struct next_hop_attr_t nh[MAX_NUM_NEXT_HOPS];
struct rte_hash *global_nh_table;

struct rte_lpm *ipv4_routing_table;
packdev_route_t routes[MAX_NUM_ROUTES];

#if 0
static void parse_mac_addr_string(
        const char *mac_addr_str,
        uint8_t *mac_addr) {
    int values[ETHER_ADDR_LEN];

    int num_tokens =
        sscanf(mac_addr_str, "%x:%x:%x:%x:%x:%x%*c",
                &values[0], &values[1], &values[2],
                &values[3], &values[4], &values[5]);
    if (num_tokens == ETHER_ADDR_LEN) {
        for (uint8_t i = 0; i < num_tokens; ++i) {
            mac_addr[i] = (uint8_t) values[i];
        }
    }
}
#endif

static void add_l3_if(
        uint8_t if_id,
        struct l3_if_config_t *config) {
    RTE_LOG(INFO, USER1, "L3_IF: Add interface with l2_if_id(%u), mtu(%u)\n",
            config->l2_if_id, config->mtu);
    packdev_ipv4_print_addr(rte_be_to_cpu_32(config->ipv4.addr));

    memset(&l3_if[if_id], 0, sizeof(l3_if[if_id]));
    l3_if[if_id].if_id = if_id;
    l3_if[if_id].attr.l2_if_id = config->l2_if_id;
    l3_if[if_id].attr.mtu = config->mtu;
    l3_if[if_id].attr.ipv4.addr = rte_be_to_cpu_32(config->ipv4.addr);
    l3_if[if_id].attr.ipv4.prefix = config->ipv4.prefix;
}

static void init_l3_ifs() {
    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, L3_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", L3_CONFIG_FILE);
    }

    gsize num_l3_ifs = 0;
    gchar **l3_ifs = g_key_file_get_groups(gkf, &num_l3_ifs);
    for (guint index = 0; index < num_l3_ifs; index++) {
        struct l3_if_config_t config;
        gint if_id = g_key_file_get_integer(gkf, l3_ifs[index], "if_id", &error);
        config.l2_if_id = g_key_file_get_integer(gkf, l3_ifs[index], "l2_if_id", &error);
        config.mtu = g_key_file_get_integer(gkf, l3_ifs[index], "mtu", &error);
        inet_pton(AF_INET, g_key_file_get_string(gkf, l3_ifs[index], "ipv4_addr", &error),
                &config.ipv4.addr);
        config.ipv4.prefix = g_key_file_get_integer(gkf, l3_ifs[index], "ipv4_prefix", &error);
        add_l3_if(if_id, &config);
    }
}

static uint32_t get_free_nh_id() {
    for (uint32_t nh_id = 0; nh_id < MAX_NUM_NEXT_HOPS; ++nh_id) {
        if (nh[nh_id].nh_id == nh_id) {
            return nh_id;
        }
    }

    return MAX_NUM_NEXT_HOPS;
}

static uint32_t get_nh_id(struct next_hop_attr_t *nh) {
    uint32_t nh_id = MAX_NUM_NEXT_HOPS;
    uint32_t key = rte_jhash(nh, sizeof(*nh), NH_TABLE_IV);
    int lookup_result = rte_hash_lookup_data(
            global_nh_table,
            &key,
            (void**)(&nh_id));
    if (lookup_result >= 0) {
        return nh_id;
    }

    switch(lookup_result) {
    case -ENOENT:
        RTE_LOG(DEBUG, USER1, "NH: Key not found\n");
        break;
    case -EINVAL:
        RTE_LOG(DEBUG, USER1, "NH: Invalid hash parameter\n");
        break;
    default:
        RTE_LOG(DEBUG, USER1, "NH: Unexpected error on lookup (%d)\n", lookup_result);
        break;
    };
    return MAX_NUM_NEXT_HOPS;
}


static void add_route(
        uint32_t nw_addr,
        uint8_t nw_prefix,
        uint8_t distance,
        struct next_hop_attr_t next_hop) {
    (void)distance;
    RTE_LOG(DEBUG, USER1, "ROUTE: Add network (0x%08x/%u) with next hop (if=%u,addr=0x%08x)\n",
            nw_addr, nw_prefix, next_hop.l3_if_id, next_hop.gateway);
    packdev_ipv4_print_addr(nw_addr);
    packdev_ipv4_print_addr(next_hop.gateway);
    uint32_t nh_id = get_nh_id(&next_hop);
    if (nh_id == MAX_NUM_NEXT_HOPS) {
        nh_id = get_free_nh_id();
        nh[nh_id] = next_hop;
        nh[nh_id].nh_id = nh_id;

        uint32_t key = rte_jhash(&next_hop, sizeof(next_hop), NH_TABLE_IV);
        rte_hash_add_key_data(
                global_nh_table,
                &key,
                (void*)((uintptr_t)nh_id));
    }


    int ret = rte_lpm_add(ipv4_routing_table, nw_addr, nw_prefix, nh_id);
    if (ret < 0) {
        RTE_LOG(ERR, USER1, "ROUTE: Unable to add entry to routing table\n");
    }
}

static void init_routes() {
    struct rte_hash_parameters nh_table_params;
    memset(&nh_table_params, 0, sizeof(nh_table_params));
    nh_table_params.name = "packdev-nh";
    nh_table_params.entries = MAX_NUM_NEXT_HOPS;
    nh_table_params.key_len = sizeof(uint32_t);
    nh_table_params.hash_func = rte_jhash;
    nh_table_params.hash_func_init_val = 0;

    global_nh_table = rte_hash_create(&nh_table_params);
    if (global_nh_table == NULL) {
        rte_exit(EXIT_FAILURE, "ROUTE: Could not create hash table!!!\n");
    }

    struct rte_lpm_config config_ipv4;
    /* create the LPM table */
    config_ipv4.max_rules = MAX_NUM_ROUTES;
    config_ipv4.number_tbl8s = 256;
    config_ipv4.flags = 0;
    ipv4_routing_table = rte_lpm_create(
            "ipv4-rt-table",
            (int)rte_socket_id(),
            &config_ipv4);
    if (ipv4_routing_table == NULL) {
         rte_exit(EXIT_FAILURE,
                 "Unable to create the IPv4 routing table\n");
    }

    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, ROUTE_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", ROUTE_CONFIG_FILE);
    }

    gsize num_routes = 0;
    gchar **routes = g_key_file_get_groups(gkf, &num_routes);
    for (guint index = 0; index < num_routes; index++) {
        gint nw_addr;
        inet_pton(AF_INET, g_key_file_get_string(gkf, routes[index], "nw_addr", &error),
                &nw_addr);
        gint nw_prefix = g_key_file_get_integer(gkf, routes[index], "nw_prefix", &error);
        gint distance = g_key_file_get_integer(gkf, routes[index], "distance", &error);
        struct next_hop_attr_t nh;
        nh.l3_if_id = g_key_file_get_integer(gkf, routes[index], "nh_if", &error);
        gint nh_gw;
        inet_pton(AF_INET, g_key_file_get_string(gkf, routes[index], "nh_gw", &error),
                &nh_gw);
        nh.gateway = rte_be_to_cpu_32(nh_gw);
        add_route(rte_be_to_cpu_32(nw_addr), nw_prefix, distance, nh);
    }
}

void packdev_l3_config_init() {
    init_l3_ifs();
    init_routes();
}

packdev_l3_if_t* packdev_l3_config_get(uint8_t if_id) {
    if (if_id >= MAX_NUM_L3_IFS || l3_if[if_id].if_id != if_id) {
        return NULL;
    }

    return &l3_if[if_id];
}

packdev_l3_if_t* packdev_l3_config_get_using_ipv4_addr(
        uint32_t ipv4_addr) {
    for (uint8_t i = 0; i < MAX_NUM_L3_IFS; ++i) {
        if (l3_if[i].attr.ipv4.addr == ipv4_addr) {
            return &l3_if[i];
        }
    }

    return NULL;
}

struct next_hop_attr_t* packdev_l3_get_next_hop(
        uint32_t ipv4_dst_addr) {
    uint32_t nh_id = MAX_NUM_NEXT_HOPS;
    uint32_t lookup_result = rte_lpm_lookup(
            ipv4_routing_table,
            ipv4_dst_addr,
            &nh_id);
    if (lookup_result == 0) {
        RTE_LOG(DEBUG, USER1, "NH: get_nh() l3_if_id=%u ",
                nh[nh_id].l3_if_id);
        packdev_ipv4_print_addr(nh[nh_id].gateway);
        return &nh[nh_id];
    }

    switch(lookup_result) {
    case -ENOENT:
        RTE_LOG(DEBUG, USER1, "NH: Not found\n");
        packdev_ipv4_print_addr(ipv4_dst_addr);
        break;
    case -EINVAL:
        RTE_LOG(DEBUG, USER1, "NH: Invalid LPM lookup parameter\n");
        break;
    default:
        RTE_LOG(DEBUG, USER1, "NH: Unexpected error on lookup (%d)\n", lookup_result);
        break;
    };

    return NULL;
}
