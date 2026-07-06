#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <stdint.h>

#define MAX_RULES 64

typedef enum {RULE_ALLOW, RULE_DENY} rule_action_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    rule_action_t action;
} fw_rule_t;

typedef struct {
    fw_rule_t rules[MAX_RULES];
    int count;
    rule_action_t default_action;
} firewall_t;
