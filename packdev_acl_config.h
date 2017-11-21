#ifndef PACKDEV_ACL_CONFIG_H_
#define PACKDEV_ACL_CONFIG_H_

#include "rte_acl.h"
#include "rte_ether.h"
#include "rte_ip.h"

typedef enum {
    PACKDEV_ACL_NO_MATCH,
    PACKDEV_ACL_ACCEPT,
    PACKDEV_ACL_DENY,
    ACL_RESULT_NUM
} packdev_acl_result_t;

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
 * That effectively defines order of IPv4 ACL classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
    RTE_ACL_IPV4_PROTO,
    RTE_ACL_IPV4_SRC,
    RTE_ACL_IPV4_DST,
    RTE_ACL_IPV4_PORTS,
    RTE_ACL_IPV4_NUM
};

struct rte_acl_field_def ipv4_acl_defs[IPV4_FIELDS_NUM];
RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_acl_defs));

void packdev_acl_config_init();
struct rte_acl_ctx* packdev_acl_config_get_context();

struct rte_acl_ctx* packdev_acl_setup_context(
        const char *table_name,
        uint32_t num_rules,
        const struct rte_acl_rule* rules);

struct acl_ipv4_rule packdev_acl_add_ipv4_rule(
        packdev_acl_result_t result,
        int32_t  priority,
        uint8_t  protocol,
        uint8_t  protocol_mask,
        uint32_t src_addr_begin,
        uint32_t src_addr_end,
        uint32_t dst_addr_begin,
        uint32_t dst_addr_end,
        uint16_t src_port_begin,
        uint16_t src_port_end,
        uint16_t dst_port_begin,
        uint16_t dst_port_end);

#endif /* PACKDEV_ACL_CONFIG_H_ */
