#ifndef PACKDEV_IPV4_FLOW_H_
#define PACKDEV_IPV4_FLOW_H_

#include "rte_acl.h"

typedef enum {
    PACKDEV_FLOW_TYPE_INVALID,
    PACKDEV_FLOW_TYPE_ACL,
    PACKDEV_FLOW_TYPE_SPD,
    PACKDEV_FLOW_TYPE_SESSION,
    PACKDEV_FLOW_TYPE_MAX
} packdev_flow_type_t;

/*
 * Rule and trace formats definitions.
 */
enum {
    IPV4_PROTOCOL,
    SRC_IPV4_ADDRESS,
    DST_IPV4_ADDRESS,
    SRC_IPV4_PORT,
    DST_IPV4_PORT,
    IPV4_FIELDS_NUM
};

/*
 * That effectively defines order of IPv4 FLOW classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
    RTE_FLOW_IPV4_PROTO,
    RTE_FLOW_IPV4_SRC,
    RTE_FLOW_IPV4_DST,
    RTE_FLOW_IPV4_PORTS,
    RTE_FLOW_IPV4_NUM
};

struct rte_acl_field_def ipv4_flow_defs[IPV4_FIELDS_NUM];
RTE_ACL_RULE_DEF(ipv4_flow_rule, RTE_DIM(ipv4_flow_defs));

void packdev_ipv4_flow_init();

uint32_t packdev_ipv4_flow_classify(
        packdev_flow_type_t flow_type,
        struct rte_mbuf *packet);

#endif /* PACKDEV_IPV4_FLOW_H_ */
