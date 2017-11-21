#ifndef PACKDEV_ACL_H_
#define PACKDEV_ACL_H_

#include <rte_mbuf.h>

void packdev_acl_classify_bulk(
        uint32_t num_pkt,
        struct rte_mbuf *pkts[],
        uint32_t result[]);

uint32_t packdev_acl_classify(struct rte_mbuf *pkt);

#endif /* PACKDEV_ACL_H_ */
