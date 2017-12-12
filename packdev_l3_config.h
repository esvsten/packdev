#ifndef PACKDEV_L3_CONFIG_H_
#define PACKDEV_L3_CONFIG_H_

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

typedef struct {
    uint32_t addr;
    uint32_t prefix;
}ipv4_addr_t ;

struct l3_if_attr_t {
    uint16_t l2_if_id;
    uint16_t mtu;
    ipv4_addr_t ipv4;
};

struct l3_if_config_t {
    uint16_t l2_if_id;
    uint16_t mtu;
    ipv4_addr_t ipv4;
};

typedef struct {
    uint8_t if_id;

    struct l3_if_attr_t attr;
} packdev_l3_if_t;

struct next_hop_attr_t {
    uint32_t nh_id;
    uint8_t l3_if_id;
    uint32_t gateway;
};

typedef struct {
    ipv4_addr_t network;
    struct next_hop_attr_t next_hop;
    uint8_t admin_distance;
} packdev_route_t;

void packdev_l3_config_init();

packdev_l3_if_t* packdev_l3_config_get(uint8_t if_id);

packdev_l3_if_t* packdev_l3_config_get_using_ipv4_addr(
        uint32_t ipv4_addr);

struct next_hop_attr_t* packdev_l3_get_next_hop(
        uint32_t ipv4_dst_addr);

#endif /* PACKDEV_L3_CONFIG_H_ */

