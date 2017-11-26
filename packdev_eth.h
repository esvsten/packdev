#ifndef PACKDEV_ETH_H_
#define PACKDEV_ETH_H_

#include <rte_mbuf.h>
#include <rte_ether.h>

void packdev_eth_build(struct rte_mbuf *packet);

void packdev_eth_process(struct rte_mbuf *packet);

void packdev_eth_print_addr(struct ether_addr addr);

#endif /* PACKDEV_ETH_H_ */

