/*                        *
 * ACL configuration file *
 *                        */

#include <sys/types.h>

#include <rte_ether.h>
#include <rte_ip.h>

#include "packdev_common.h"
#include "packdev_acl_config.h"

static struct rte_acl_ctx *global_context;

/* Send in the pointer to the start of IPv4 header */
static void setup_acl_field_definitions() {
    ipv4_acl_defs[0].type = RTE_ACL_FIELD_TYPE_BITMASK;
    ipv4_acl_defs[0].size = sizeof(uint8_t);
    ipv4_acl_defs[0].field_index = IPV4_PROTOCOL;
    ipv4_acl_defs[0].input_index = RTE_ACL_IPV4_PROTO;
    ipv4_acl_defs[0].offset = offsetof(struct ipv4_hdr, next_proto_id);

    ipv4_acl_defs[1].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_acl_defs[1].size = sizeof(uint32_t);
    ipv4_acl_defs[1].field_index = SRC_IPV4_ADDRESS;
    ipv4_acl_defs[1].input_index = RTE_ACL_IPV4_SRC;
    ipv4_acl_defs[1].offset = offsetof(struct ipv4_hdr, src_addr);

    ipv4_acl_defs[2].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_acl_defs[2].size = sizeof(uint32_t);
    ipv4_acl_defs[2].field_index = DST_IPV4_ADDRESS;
    ipv4_acl_defs[2].input_index = RTE_ACL_IPV4_DST;
    ipv4_acl_defs[2].offset = offsetof(struct ipv4_hdr, dst_addr);

    ipv4_acl_defs[3].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_acl_defs[3].size = sizeof(uint16_t);
    ipv4_acl_defs[3].field_index = SRC_IPV4_PORT;
    ipv4_acl_defs[3].input_index = RTE_ACL_IPV4_PORTS;
    ipv4_acl_defs[3].offset = sizeof(struct ipv4_hdr);

    ipv4_acl_defs[4].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_acl_defs[4].size = sizeof(uint16_t);
    ipv4_acl_defs[4].field_index = DST_IPV4_PORT;
    ipv4_acl_defs[4].input_index = RTE_ACL_IPV4_PORTS;
    ipv4_acl_defs[4].offset = sizeof(struct ipv4_hdr) +
        sizeof(uint16_t);
}

struct rte_acl_ctx* packdev_acl_setup_context(
        const char *table_name,
        uint32_t num_rules,
        const struct rte_acl_rule* rules) {
    char name[RTE_ACL_NAMESIZE];
    strncpy(name, table_name, RTE_ACL_NAMESIZE);

    struct rte_acl_param acl_param;
    memset(&acl_param, 0, sizeof(acl_param));
    acl_param.name = name;
    acl_param.socket_id = SOCKET_ID_ANY;
    acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_acl_defs));
    acl_param.max_rule_num = MAX_ACL_RULES;

    struct rte_acl_ctx *context = rte_acl_create(&acl_param);
    if (context == NULL) {
        RTE_LOG(INFO, USER1, "Could not create ACL context: %s\n",
                rte_strerror(-rte_errno));
        rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
    }

    if (rte_acl_add_rules(context, rules, num_rules) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to add rules to ACL context\n");
    }

    struct rte_acl_config acl_build_param;
    memset(&acl_build_param, 0, sizeof(acl_build_param));
    acl_build_param.num_categories = MAX_ACL_CATEGORIES;
    acl_build_param.num_fields = RTE_DIM(ipv4_acl_defs);
    memcpy(acl_build_param.defs, ipv4_acl_defs, sizeof(ipv4_acl_defs));

    if (rte_acl_build(context, &acl_build_param) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to build ACL context\n");
    }

    rte_acl_dump(context);

    return context;
}

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
        uint16_t dst_port_end) {
    struct acl_ipv4_rule acl_rule = {
        .data = {
            .userdata = result,
            .category_mask = 1,
            .priority = priority,
        },
        // protocol
        .field[0] = {
            .value.u8 = protocol,
            .mask_range.u8 = protocol_mask,
        },
        // source address
        .field[1] = {
            .value.u32 = src_addr_begin,
            .mask_range.u32 = src_addr_end,
        },
        // destination address
        .field[2] = {
            .value.u32 = dst_addr_begin,
            .mask_range.u32 = dst_addr_end,
        },
        // source port
        .field[3] = {
            .value.u16 = src_port_begin,
            .mask_range.u16 = src_port_end,
        },
        // destination port
        .field[4] = {
            .value.u16 = dst_port_begin,
            .mask_range.u16 = dst_port_end,
        },
    };

    return acl_rule;
}

void packdev_acl_config_init() {
    /* Setup ACL fields */
    setup_acl_field_definitions();

    /* Add static ACL rules here */
    struct acl_ipv4_rule acl_rules[4];
    acl_rules[0] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 1 /* priority */,
            0, 0, // protocol
            0, 0, // source address
            IPv4(192,168,0,0), IPv4(192,168,0,255), // destination address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[1] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 2 /* priority */,
            0, 0, // protocol
            0, 0, // source address
            IPv4(192,168,1,0), IPv4(192,168,1,255), // destination address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[2] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 3 /* priority */,
            17, 0xff, // protocol
            IPv4(192,168,17,114), IPv4(192,168,17,114), // source address
            IPv4(192,168,16,36), IPv4(192,168,16,36), // source address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[3] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_DENY, 4 /* priority */,
            17, 0xff, // protocol
            IPv4(192,168,17,114), IPv4(192,168,17,114), // source address
            IPv4(192,168,16,36), IPv4(192,168,16,36), // source address
            46531, 46531, // source port
            0, 0xffff); // destination port

    global_context = packdev_acl_setup_context(
            "packdev-acl-ipv4",
            RTE_DIM(acl_rules),
            (const struct rte_acl_rule*)acl_rules);
}

struct rte_acl_ctx* packdev_acl_config_get_context() {
    return global_context;
}
