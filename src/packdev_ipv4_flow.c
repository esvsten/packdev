/*                        *
 * FLOW configuration file *
 *                        */

#include <glib.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <rte_ether.h>
#include <rte_ip.h>

#include "packdev_common.h"
#include "packdev_ipv4_flow.h"
#include "packdev_acl_config.h"
#include "packdev_spd_config.h"
#include "packdev_session.h"

#define FLOW_CONFIG_FILE "packdev_flow.conf"

static struct rte_acl_ctx *acl_context;
static struct rte_acl_ctx *spd_context;
static struct rte_acl_ctx *session_context;

/* Send in the pointer to the start of IPv4 header */
static void setup_flow_field_definitions() {
    ipv4_flow_defs[0].type = RTE_ACL_FIELD_TYPE_BITMASK;
    ipv4_flow_defs[0].size = sizeof(uint8_t);
    ipv4_flow_defs[0].field_index = IPV4_PROTOCOL;
    ipv4_flow_defs[0].input_index = RTE_FLOW_IPV4_PROTO;
    ipv4_flow_defs[0].offset = offsetof(struct ipv4_hdr, next_proto_id);

    ipv4_flow_defs[1].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_flow_defs[1].size = sizeof(uint32_t);
    ipv4_flow_defs[1].field_index = SRC_IPV4_ADDRESS;
    ipv4_flow_defs[1].input_index = RTE_FLOW_IPV4_SRC;
    ipv4_flow_defs[1].offset = offsetof(struct ipv4_hdr, src_addr);

    ipv4_flow_defs[2].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_flow_defs[2].size = sizeof(uint32_t);
    ipv4_flow_defs[2].field_index = DST_IPV4_ADDRESS;
    ipv4_flow_defs[2].input_index = RTE_FLOW_IPV4_DST;
    ipv4_flow_defs[2].offset = offsetof(struct ipv4_hdr, dst_addr);

    ipv4_flow_defs[3].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_flow_defs[3].size = sizeof(uint16_t);
    ipv4_flow_defs[3].field_index = SRC_IPV4_PORT;
    ipv4_flow_defs[3].input_index = RTE_FLOW_IPV4_PORTS;
    ipv4_flow_defs[3].offset = sizeof(struct ipv4_hdr);

    ipv4_flow_defs[4].type = RTE_ACL_FIELD_TYPE_RANGE;
    ipv4_flow_defs[4].size = sizeof(uint16_t);
    ipv4_flow_defs[4].field_index = DST_IPV4_PORT;
    ipv4_flow_defs[4].input_index = RTE_FLOW_IPV4_PORTS;
    ipv4_flow_defs[4].offset = sizeof(struct ipv4_hdr) +
        sizeof(uint16_t);
}

struct rte_acl_ctx* packdev_ipv4_flow_setup_context(
        const char *table_name,
        uint32_t max_num_rules,
        uint32_t num_rules,
        const struct rte_acl_rule* rules) {
    char name[RTE_ACL_NAMESIZE];
    strncpy(name, table_name, RTE_ACL_NAMESIZE);

    struct rte_acl_param flow_param;
    memset(&flow_param, 0, sizeof(flow_param));
    flow_param.name = name;
    flow_param.socket_id = SOCKET_ID_ANY;
    flow_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_flow_defs));
    flow_param.max_rule_num = max_num_rules;

    struct rte_acl_ctx *context = rte_acl_create(&flow_param);
    if (context == NULL) {
        RTE_LOG(INFO, USER1, "Could not create FLOW context: %s\n",
                rte_strerror(-rte_errno));
        rte_exit(EXIT_FAILURE, "Failed to create FLOW context\n");
    }

    if (rte_acl_add_rules(context, rules, num_rules) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to add rules to FLOW context\n");
    }

    struct rte_acl_config flow_build_param;
    memset(&flow_build_param, 0, sizeof(flow_build_param));
    flow_build_param.num_categories = MAX_ACL_CATEGORIES;
    flow_build_param.num_fields = RTE_DIM(ipv4_flow_defs);
    memcpy(flow_build_param.defs, ipv4_flow_defs, sizeof(ipv4_flow_defs));

    RTE_LOG(DEBUG, USER1, "FLOW: context(%s)\n", table_name);
    RTE_LOG(DEBUG, USER1, "      max_num_rules(%d)\n", max_num_rules);
    RTE_LOG(DEBUG, USER1, "      num_rules(%d)\n", num_rules);

    if (rte_acl_build(context, &flow_build_param) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to build FLOW context(%s)\n",
                table_name);
    }
    rte_acl_dump(context);

    return context;
}

struct ipv4_flow_rule packdev_ipv4_flow_add_ipv4_rule(
        uint32_t result,
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
#if 0
    RTE_LOG(DEBUG, USER1, "FLOW-CONFIG: add ipv4 rule:\n");
    RTE_LOG(DEBUG, USER1, " action:%u\n", result);
    RTE_LOG(DEBUG, USER1, " priority:%u\n", priority);
    RTE_LOG(DEBUG, USER1, " protocol:%u\n", protocol);
    RTE_LOG(DEBUG, USER1, " protocol_mask:%u\n", protocol_mask);
    RTE_LOG(DEBUG, USER1, " src_addr_begin:%u\n", src_addr_begin);
    RTE_LOG(DEBUG, USER1, " src_addr_end:%u\n", src_addr_end);
    RTE_LOG(DEBUG, USER1, " dst_addr_begin:%u\n", dst_addr_begin);
    RTE_LOG(DEBUG, USER1, " dst_addr_end:%u\n", dst_addr_end);
    RTE_LOG(DEBUG, USER1, " src_port_begin:%u\n", src_port_begin);
    RTE_LOG(DEBUG, USER1, " src_port_end:%u\n", src_port_end);
    RTE_LOG(DEBUG, USER1, " dst_port_begin:%u\n", dst_port_begin);
    RTE_LOG(DEBUG, USER1, " dst_port_end:%u\n", dst_port_end);
#endif
    struct ipv4_flow_rule flow_rule = {
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

    return flow_rule;
}

static uint32_t get_flow_type(const char *flow_type_string) {
    const char *acl_name = "ACL";
    const char *spd_name = "POLICY";
    const char *session_name = "SESSION";

    if (strncmp(acl_name, flow_type_string, strlen(acl_name)) == 0) {
        return PACKDEV_FLOW_TYPE_ACL;
    } else if (strncmp(spd_name, flow_type_string, strlen(spd_name)) == 0) {
        return PACKDEV_FLOW_TYPE_SPD;
    } else if (strncmp(session_name, flow_type_string, strlen(session_name)) == 0) {
        return PACKDEV_FLOW_TYPE_SESSION;
    }

    return PACKDEV_FLOW_TYPE_INVALID;
}

void packdev_ipv4_flow_init() {
    /* Setup FLOW fields */
    setup_flow_field_definitions();

    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, FLOW_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", FLOW_CONFIG_FILE);
    }

    gsize num_flows = 0;
    gchar **flows = g_key_file_get_groups(gkf, &num_flows);
    gsize num_acls = 0;
    struct ipv4_flow_rule acl_rules[num_flows];
    gsize num_policies = 0;
    struct ipv4_flow_rule policies[num_flows];
    gsize num_sessions = 0;
    struct ipv4_flow_rule sessions[num_flows];
    for (guint index = 0; index < num_flows; index++) {
         gint priority = g_key_file_get_integer(gkf, flows[index], "priority", &error);
         gint protocol = g_key_file_get_integer(gkf, flows[index], "protocol", &error);
         gint protocol_mask = g_key_file_get_integer(gkf, flows[index], "protocol_mask", &error);
         gint src_ip_addr_begin;
         inet_pton(AF_INET, g_key_file_get_string(gkf, flows[index], "src_ip_addr_begin", &error),
                     &src_ip_addr_begin);
         gint src_ip_addr_end;
         inet_pton(AF_INET, g_key_file_get_string(gkf, flows[index], "src_ip_addr_end", &error),
                     &src_ip_addr_end);
         gint dst_ip_addr_begin;
         inet_pton(AF_INET, g_key_file_get_string(gkf, flows[index], "dst_ip_addr_begin", &error),
                     &dst_ip_addr_begin);
         gint dst_ip_addr_end;
         inet_pton(AF_INET, g_key_file_get_string(gkf, flows[index], "dst_ip_addr_end", &error),
                     &dst_ip_addr_end);
         gint src_port_begin = g_key_file_get_integer(gkf, flows[index], "src_port_begin", &error);
         gint src_port_end = g_key_file_get_integer(gkf, flows[index], "src_port_end", &error);
         gint dst_port_begin = g_key_file_get_integer(gkf, flows[index], "dst_port_begin", &error);
         gint dst_port_end = g_key_file_get_integer(gkf, flows[index], "dst_port_end", &error);
         gchar *action = g_key_file_get_string(gkf, flows[index], "action", &error);

         packdev_flow_type_t flow_type = get_flow_type(flows[index]);
         uint32_t flow_action = 0;
         switch (flow_type) {
         case PACKDEV_FLOW_TYPE_ACL:
             flow_action = packdev_acl_get_action(action);
             acl_rules[num_acls++] = packdev_ipv4_flow_add_ipv4_rule(
                     flow_action, priority,
                     protocol, protocol_mask,
                     rte_cpu_to_be_32(src_ip_addr_begin),
                     rte_cpu_to_be_32(src_ip_addr_end),
                     rte_cpu_to_be_32(dst_ip_addr_begin),
                     rte_cpu_to_be_32(dst_ip_addr_end),
                     src_port_begin, src_port_end,
                     dst_port_begin, dst_port_end);
             break;
         case PACKDEV_FLOW_TYPE_SPD:
             flow_action = packdev_spd_get_action(action);
             policies[num_policies++] = packdev_ipv4_flow_add_ipv4_rule(
                     flow_action, priority,
                     protocol, protocol_mask,
                     rte_cpu_to_be_32(src_ip_addr_begin),
                     rte_cpu_to_be_32(src_ip_addr_end),
                     rte_cpu_to_be_32(dst_ip_addr_begin),
                     rte_cpu_to_be_32(dst_ip_addr_end),
                     src_port_begin, src_port_end,
                     dst_port_begin, dst_port_end);
             break;
         case PACKDEV_FLOW_TYPE_SESSION:
             flow_action = packdev_session_get_action(action);
             sessions[num_sessions++] = packdev_ipv4_flow_add_ipv4_rule(
                     flow_action, priority,
                     protocol, protocol_mask,
                     rte_cpu_to_be_32(src_ip_addr_begin),
                     rte_cpu_to_be_32(src_ip_addr_end),
                     rte_cpu_to_be_32(dst_ip_addr_begin),
                     rte_cpu_to_be_32(dst_ip_addr_end),
                     src_port_begin, src_port_end,
                     dst_port_begin, dst_port_end);
             break;
         default:
             RTE_LOG(ERR, USER1, "FLOW-CONFIG: Unknown flow type (%u)\n", flow_type);
             continue;
         }
    }

    g_key_file_free (gkf);

    acl_context = packdev_ipv4_flow_setup_context(
            ACL_CONTEXT_NAME,
            MAX_NUM_ACLS,
            num_acls,
            (const struct rte_acl_rule*)acl_rules);
    spd_context = packdev_ipv4_flow_setup_context(
            SPD_CONTEXT_NAME,
            MAX_NUM_POLICIES,
            num_policies,
            (const struct rte_acl_rule*)policies);
    session_context = packdev_ipv4_flow_setup_context(
            SESSION_CONTEXT_NAME,
            MAX_NUM_SESSIONS,
            num_sessions,
            (const struct rte_acl_rule*)sessions);
}

struct rte_acl_ctx* packdev_acl_config_get_context() {
    return acl_context;
}

struct rte_acl_ctx* packdev_spd_config_get_context() {
    return spd_context;
}

struct rte_acl_ctx* packdev_session_config_get_context() {
    return session_context;
}

static struct rte_acl_ctx* get_context(packdev_flow_type_t flow_type) {
    struct rte_acl_ctx* context = NULL;
    switch(flow_type) {
    case PACKDEV_FLOW_TYPE_ACL:
        context = acl_context;
        break;
    case PACKDEV_FLOW_TYPE_SPD:
        context = spd_context;
        break;
    case PACKDEV_FLOW_TYPE_SESSION:
        context = session_context;
        break;
    default:
        RTE_LOG(ERR, USER1, "FLOW-CLASSIFY: Unknown flow type (%u)\n", flow_type);
        break;
    }

    return context;
}

uint32_t packdev_ipv4_flow_classify(
        packdev_flow_type_t flow_type,
        struct rte_mbuf *packet) {
    uint32_t num_pkts = 1;
    uint32_t result = 0;
    const uint8_t *ipv4_offset = (const uint8_t*)MBUF_IPV4_HDR_PTR(packet);
    rte_acl_classify(
            get_context(flow_type),
            &ipv4_offset,
            &result,
            num_pkts,
            MAX_ACL_CATEGORIES);

    return result;
}
