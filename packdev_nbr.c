#include <stdint.h>
#include <unistd.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "packdev_common.h"
#include "packdev_config.h"
#include "packdev_nbr.h"
#include "packdev_eth.h"
#include "packdev_ipv4.h"

struct rte_hash *global_nbr_table;
struct rte_hash_parameters nbr_table_params;

packdev_nbr_t nbr[MAX_NUM_NBRS];

void packdev_nbr_init() {
    memset(&nbr_table_params, 0, sizeof(nbr_table_params));
    nbr_table_params.name = "packdev-nbr";
    nbr_table_params.entries = MAX_NUM_NBRS;
    nbr_table_params.key_len = sizeof(uint32_t);
    nbr_table_params.hash_func = rte_jhash;
    nbr_table_params.hash_func_init_val = 0;

    global_nbr_table = rte_hash_create(&nbr_table_params);
    if (global_nbr_table == NULL) {
        rte_exit(EXIT_FAILURE, "SA: Could not create hash table!!!\n");
    }

    for (uint32_t i = 0; i < MAX_NUM_NBRS; ++i) {
        nbr[i].state = PACKDEV_ARP_INVALID;
    }
}

static uint32_t get_free_nbr_id() {
    for (uint32_t i = 0; i < MAX_NUM_NBRS; ++i) {
        if (nbr[i].state == PACKDEV_ARP_INVALID) {
            return i;
        }
    }

    return MAX_NUM_NBRS;
}

static uint32_t get_nbr_id(uint32_t ipv4_addr) {
    uint32_t nbr_id = 0;
    uint32_t key = rte_jhash(&ipv4_addr, sizeof(ipv4_addr), NBR_TABLE_IV);
    int lookup_result = rte_hash_lookup_data(
            global_nbr_table,
            &key,
            (void**)(&nbr_id));
    if (lookup_result >= 0) {
        return nbr_id;
    }

    switch(lookup_result) {
    case -ENOENT:
        RTE_LOG(DEBUG, USER1, "NBR: Key not found\n");
        break;
    case -EINVAL:
        RTE_LOG(DEBUG, USER1, "NBR: Invalid hash parameter\n");
        break;
    default:
        RTE_LOG(DEBUG, USER1, "NBR: Unexpected error on lookup (%d)\n", lookup_result);
        break;
    };
    return MAX_NUM_NBRS;
}

void packdev_l2_nbr_add(
        uint32_t ipv4_addr,
        uint8_t mac_addr[ETHER_ADDR_LEN],
        uint32_t origin) {
    uint32_t nbr_id = get_nbr_id(ipv4_addr);
    if (nbr_id != MAX_NUM_NBRS) {
#if 0
        RTE_LOG(DEBUG, USER1,
                "NBR: Already existing IPv4 address(%u) ", nbr_id);
        packdev_ipv4_print_addr(ipv4_addr);
#endif
    } else {
        nbr_id = get_free_nbr_id();
        if (nbr_id == MAX_NUM_NBRS) {
            RTE_LOG(ERR, USER1,
                    "NBR: Exceeded maximum number of neighbors(%u)\n",
                    MAX_NUM_NBRS);
            return;
        }
    }

#if 0
    RTE_LOG(DEBUG, USER1, "NBR: add_mac ");
    packdev_ipv4_print_addr(ipv4_addr);
    struct ether_addr eth_addr;
    memcpy(eth_addr.addr_bytes, mac_addr, ETHER_ADDR_LEN);
    packdev_eth_print_addr(eth_addr);
#endif

    memset(&nbr[nbr_id], 0, sizeof(nbr[nbr_id]));
    nbr[nbr_id].nbr_id = nbr_id;
    nbr[nbr_id].ipv4_addr = ipv4_addr;
    nbr[nbr_id].origin = origin;
    nbr[nbr_id].state = PACKDEV_ARP_INCOMPLETE;
    memcpy(nbr[nbr_id].mac_addr, mac_addr, sizeof(nbr[nbr_id].mac_addr));

    uint32_t key = rte_jhash(&ipv4_addr, sizeof(ipv4_addr), NBR_TABLE_IV);
    rte_hash_add_key_data(
            global_nbr_table,
            &key,
            (void*)((uintptr_t)nbr_id));
}

packdev_nbr_t* packdev_l2_nbr_get(uint32_t ipv4_addr) {
    RTE_LOG(DEBUG, USER1, "NBR: get_nbr ");
    packdev_ipv4_print_addr(ipv4_addr);

    uint32_t nbr_id = get_nbr_id(ipv4_addr);
    if (nbr_id != MAX_NUM_NBRS) {
        struct ether_addr eth_addr;
        memcpy(eth_addr.addr_bytes, nbr[nbr_id].mac_addr, ETHER_ADDR_LEN);
        packdev_eth_print_addr(eth_addr);

        return &nbr[nbr_id];
    }
    return NULL;
}

void packdev_l2_nbr_set_state(
        uint32_t ipv4_addr,
        uint8_t mac_addr[ETHER_ADDR_LEN],
        uint32_t state) {
    uint32_t nbr_id = get_nbr_id(ipv4_addr);
    if (nbr_id != MAX_NUM_NBRS) {
#if 0
        RTE_LOG(DEBUG, USER1, "NBR: set_state ");
        packdev_ipv4_print_addr(ipv4_addr);
        struct ether_addr eth_addr;
        memcpy(eth_addr.addr_bytes, mac_addr, ETHER_ADDR_LEN);
        packdev_eth_print_addr(eth_addr);
#endif
        memcpy(nbr[nbr_id].mac_addr, mac_addr, sizeof(nbr[nbr_id].mac_addr));
        nbr[nbr_id].state = state;
    }
}

void packdev_l2_nbr_rem(
        uint32_t ipv4_addr) {
    uint32_t nbr_id = get_nbr_id(ipv4_addr);
    if (nbr_id != MAX_NUM_NBRS) {
        uint32_t key = rte_jhash(&nbr[nbr_id].ipv4_addr, sizeof(nbr[nbr_id].ipv4_addr), NBR_TABLE_IV);
        rte_hash_del_key(global_nbr_table, &key);
        nbr[nbr_id].state = PACKDEV_ARP_INVALID;
    }
}

struct rte_hash* packdev_l2_nbr_get_table() {
    return global_nbr_table;
}
