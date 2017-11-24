#ifndef PACKDEV_VLAN_H_
#define PACKDEV_VLAN_H_

#include <netinet/in.h>
#include <stdbool.h>

#include <rte_ether.h>

void packdev_vlan_process(
        struct rte_mbuf *packet,
        uint16_t port_id);

# endif // PACKDEV_VLAN_H_
