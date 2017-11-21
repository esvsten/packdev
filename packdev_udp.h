#ifndef PACKDEV_UDP_H_
#define PACKDEV_UDP_H_

#include <rte_mbuf.h>

#include "packdev_session.h"

void packdev_udp_process(
        struct rte_mbuf *packet,
        uint16_t port_id);

#endif /* PACKDEV_UDP_H_ */
