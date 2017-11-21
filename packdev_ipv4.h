#ifndef PACKDEV_IPV4_H_
#define PACKDEV_IPV4_H_

#include <netinet/in.h>
#include <stdbool.h>

#include <rte_ip.h>

void packdev_ipv4_process(
        struct rte_mbuf *packet,
        uint16_t port_id,
        bool inner_packet);

void packdev_ipv4_print_addr(uint32_t addr);

void packdev_ipv4_init();

# endif // PACKDEV_IPV4_H_
