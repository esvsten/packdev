#ifndef PACKDEV_L2_CONFIG_H_
#define PACKDEV_L2_CONFIG_H_

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

struct l2_if_attr_t {
    uint8_t mac_addr[6];
    uint32_t vlan_id;
    uint32_t port_id;
};

struct l2_if_config_t {
    uint32_t vlan_id;
    uint32_t port_id;
};

typedef struct {
    uint8_t if_id;

    struct l2_if_attr_t attr;
} packdev_l2_if_t;

void packdev_l2_config_init();

packdev_l2_if_t* packdev_l2_config_get(uint8_t if_id);

packdev_l2_if_t* packdev_l2_config_get_using_vlan_port(
        uint32_t vlan_id,
        uint32_t port_id);

#endif /* PACKDEV_L2_CONFIG_H_ */

