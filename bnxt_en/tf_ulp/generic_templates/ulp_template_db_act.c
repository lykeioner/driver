// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2014-2025 Broadcom
 * All rights reserved.
 */

#include "ulp_template_db_enum.h"
#include "ulp_template_db_field.h"
#include "ulp_template_struct.h"
#include "ulp_template_db_tbl.h"

/* Array for the act matcher list */
struct bnxt_ulp_act_match_info ulp_act_match_list[] = {
	[1] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DROP |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_RSS |
		BNXT_ULP_ACT_BIT_QUEUE |
		BNXT_ULP_ACT_BIT_POP_VLAN |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_SET_IPV4_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV4_DST |
		BNXT_ULP_ACT_BIT_SET_IPV6_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV6_DST |
		BNXT_ULP_ACT_BIT_SET_TP_SRC |
		BNXT_ULP_ACT_BIT_SET_TP_DST |
		BNXT_ULP_ACT_BIT_VXLAN_DECAP |
		BNXT_ULP_ACT_BIT_GENEVE_DECAP |
		BNXT_ULP_ACT_BIT_METER |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 1
	},
	[2] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_GOTO_CHAIN |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 1
	},
	[3] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_DROP |
		BNXT_ULP_ACT_BIT_POP_VLAN |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_VXLAN_DECAP |
		BNXT_ULP_ACT_BIT_GENEVE_DECAP |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_METER |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_ACT_BIT_GOTO_CHAIN |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 2
	},
	[4] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED |
		BNXT_ULP_ACT_BIT_SAMPLE |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 3
	},
	[5] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DELETE |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 3
	},
	[6] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_SET_IPV4_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV4_DST |
		BNXT_ULP_ACT_BIT_SET_IPV6_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV6_DST |
		BNXT_ULP_ACT_BIT_SET_TP_SRC |
		BNXT_ULP_ACT_BIT_SET_TP_DST |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 4
	},
	[7] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_RSS |
		BNXT_ULP_ACT_BIT_QUEUE |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 5
	},
	[8] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_METER_PROFILE |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 6
	},
	[9] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED_METER |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 6
	},
	[10] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DELETE |
		BNXT_ULP_ACT_BIT_METER_PROFILE |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 6
	},
	[11] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DELETE |
		BNXT_ULP_ACT_BIT_SHARED_METER |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 6
	},
	[12] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_UPDATE |
		BNXT_ULP_ACT_BIT_SHARED_METER |
		BNXT_ULP_FLOW_DIR_BITMASK_ING },
	.act_tid = 6
	},
	[13] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DROP |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_VF_TO_VF |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_SET_IPV4_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV4_DST |
		BNXT_ULP_ACT_BIT_SET_IPV6_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV6_DST |
		BNXT_ULP_ACT_BIT_SET_TP_SRC |
		BNXT_ULP_ACT_BIT_SET_TP_DST |
		BNXT_ULP_ACT_BIT_PUSH_VLAN |
		BNXT_ULP_ACT_BIT_SET_VLAN_PCP |
		BNXT_ULP_ACT_BIT_SET_VLAN_VID |
		BNXT_ULP_ACT_BIT_VXLAN_ENCAP |
		BNXT_ULP_ACT_BIT_GENEVE_ENCAP |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 7
	},
	[14] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_GOTO_CHAIN |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 7
	},
	[15] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_DROP |
		BNXT_ULP_ACT_BIT_SET_VLAN_PCP |
		BNXT_ULP_ACT_BIT_SET_VLAN_VID |
		BNXT_ULP_ACT_BIT_PUSH_VLAN |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_ACT_BIT_GOTO_CHAIN |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 8
	},
	[16] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_SET_IPV4_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV4_DST |
		BNXT_ULP_ACT_BIT_SET_IPV6_SRC |
		BNXT_ULP_ACT_BIT_SET_IPV6_DST |
		BNXT_ULP_ACT_BIT_SET_TP_SRC |
		BNXT_ULP_ACT_BIT_SET_TP_DST |
		BNXT_ULP_ACT_BIT_DEC_TTL |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 9
	},
	[17] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_ACT_BIT_SET_MAC_SRC |
		BNXT_ULP_ACT_BIT_SET_MAC_DST |
		BNXT_ULP_ACT_BIT_VXLAN_ENCAP |
		BNXT_ULP_ACT_BIT_GENEVE_ENCAP |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 10
	},
	[18] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_ACT_BIT_MULTIPLE_PORT |
		BNXT_ULP_ACT_BIT_VF_TO_VF |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 11
	},
	[19] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_SHARED |
		BNXT_ULP_ACT_BIT_SAMPLE |
		BNXT_ULP_ACT_BIT_VF_TO_VF |
		BNXT_ULP_ACT_BIT_COUNT |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 12
	},
	[20] = {
	.act_bitmap = { .bits =
		BNXT_ULP_ACT_BIT_NON_GENERIC |
		BNXT_ULP_ACT_BIT_GENERIC |
		BNXT_ULP_ACT_BIT_DELETE |
		BNXT_ULP_ACT_BIT_SHARED_SAMPLE |
		BNXT_ULP_FLOW_DIR_BITMASK_EGR },
	.act_tid = 12
	}
};

