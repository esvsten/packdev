
#include <glib.h>
#include <stdint.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "packdev_common.h"
#include "packdev_config.h"
#include "packdev_l2_config.h"

#define L2_CONFIG_FILE "packdev_l2.conf"

packdev_l2_if_t l2_if[MAX_NUM_L2_IFS];

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

static void add_l2_if(
        uint8_t if_id,
        struct l2_if_config_t *config) {
    RTE_LOG(INFO, USER1, "L2_IF: Add interface with VLAN(%u), port(%u)\n",
            config->vlan_id, config->port_id);
    struct ether_addr mac_addr;
    memset(&l2_if[if_id], 0, sizeof(l2_if[if_id]));
    l2_if[if_id].if_id = if_id;
    l2_if[if_id].attr.vlan_id = config->vlan_id;
    l2_if[if_id].attr.port_id = config->port_id;
    rte_eth_macaddr_get(
            config->port_id,
            &mac_addr);
    memcpy(l2_if[if_id].attr.mac_addr, mac_addr.addr_bytes, sizeof(l2_if[if_id].attr.mac_addr));
}

void packdev_l2_config_init() {
    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, L2_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", L2_CONFIG_FILE);
    }

    gsize num_l2_ifs = 0;
    gchar **l2_ifs = g_key_file_get_groups(gkf, &num_l2_ifs);
    for (guint index = 0; index < num_l2_ifs; index++) {
        struct l2_if_config_t config;
        gint if_id = g_key_file_get_integer(gkf, l2_ifs[index], "if_id", &error);
        config.vlan_id = g_key_file_get_integer(gkf, l2_ifs[index], "vlan_id", &error);
        config.port_id = g_key_file_get_integer(gkf, l2_ifs[index], "port_id", &error);
        add_l2_if(if_id, &config);
    }
}

packdev_l2_if_t* packdev_l2_config_get(uint8_t if_id) {
    if (if_id >= MAX_NUM_L2_IFS || l2_if[if_id].if_id != if_id) {
        return NULL;
    }

    return &l2_if[if_id];
}

packdev_l2_if_t* packdev_l2_config_get_using_vlan_port(
        uint32_t vlan_id,
        uint32_t port_id) {
    for (uint8_t i = 0; i < MAX_NUM_L2_IFS; ++i) {
        if (l2_if[i].attr.vlan_id == vlan_id &&
                l2_if[i].attr.port_id == port_id) {
            return &l2_if[i];
        }
    }

    return NULL;
}
