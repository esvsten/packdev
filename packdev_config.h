#ifndef PACKDEV_CONFIG_H_
#define PACKDEV_CONFIG_H_

#include <netinet/in.h>
#include <stdbool.h>

#include <rte_mbuf.h>

void packdev_config_init();

void packdev_config_port_map(uint32_t eth_port_id, uint32_t veth_port_id);

uint32_t packdev_config_get_veth_port_id(uint32_t eth_port_id);

uint32_t packdev_config_get_eth_port_id(uint32_t veth_port_id);

bool packdev_config_is_eth_port(uint32_t port_id);

bool packdev_config_is_veth_port(uint32_t port_id);

# endif // PACKDEV_CONFIG_H_
