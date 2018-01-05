#ifndef PACKDEV_UDP_H_
#define PACKDEV_UDP_H_

#include <rte_mbuf.h>

void packdev_udp_process(struct rte_mbuf *packet);

#endif /* PACKDEV_UDP_H_ */
