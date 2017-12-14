
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_debug.h>

#include "packdev_common.h"
#include "packdev_port.h"

#define ETH_PORT 1
#define VETH_PORT 2

uint8_t is_eth_port[MAX_NUM_OF_PORTS];
uint32_t veth_table[MAX_NUM_OF_PORTS];
uint32_t eth_table[MAX_NUM_OF_PORTS];

void packdev_config_init() {
    memset(&veth_table, 0, sizeof(veth_table));
    memset(&eth_table, 0, sizeof(eth_table));
}

void packdev_config_port_map(uint32_t eth_port_id, uint32_t veth_port_id) {
    veth_table[eth_port_id] = veth_port_id;
    eth_table[veth_port_id] = eth_port_id;

    is_eth_port[eth_port_id] = ETH_PORT;
    is_eth_port[veth_port_id] = VETH_PORT;
}

uint32_t packdev_config_get_veth_port_id(uint32_t eth_port_id) {
    return veth_table[eth_port_id];
}

uint32_t packdev_config_get_eth_port_id(uint32_t veth_port_id) {
    return eth_table[veth_port_id];
}

bool packdev_config_is_eth_port(uint32_t port_id) {
    return is_eth_port[port_id] == ETH_PORT;
}

bool packdev_config_is_veth_port(uint32_t port_id) {
    return is_eth_port[port_id] == VETH_PORT;
}
