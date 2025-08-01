/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2023 Broadcom
 * All rights reserved.
 */

#ifndef _BNXT_TF_COMMON_H_
#define _BNXT_TF_COMMON_H_

#include "bnxt_tf_ulp.h"
#include "ulp_template_db_enum.h"

#define BNXT_ULP_EM_FLOWS			8192
#define BNXT_ULP_1M_FLOWS			1000000
#define BNXT_EEM_RX_GLOBAL_ID_MASK		(BNXT_ULP_1M_FLOWS - 1)
#define BNXT_EEM_TX_GLOBAL_ID_MASK		(BNXT_ULP_1M_FLOWS - 1)
#define BNXT_EEM_HASH_KEY2_USED			0x8000000
#define BNXT_EEM_RX_HW_HASH_KEY2_BIT		BNXT_ULP_1M_FLOWS
#define	BNXT_ULP_DFLT_RX_MAX_KEY		512
#define	BNXT_ULP_DFLT_RX_MAX_ACTN_ENTRY		256
#define	BNXT_ULP_DFLT_RX_MEM			0
#define	BNXT_ULP_RX_NUM_FLOWS			32
#define	BNXT_ULP_DFLT_TX_MAX_KEY		512
#define	BNXT_ULP_DFLT_TX_MAX_ACTN_ENTRY		256
#define	BNXT_ULP_DFLT_TX_MEM			0
#define	BNXT_ULP_TX_NUM_FLOWS			32

enum bnxt_tf_rc {
	BNXT_TF_RC_PARSE_ERR_NOTSUPP	= -3,
	BNXT_TF_RC_PARSE_ERR		= -2,
	BNXT_TF_RC_ERROR		= -1,
	BNXT_TF_RC_SUCCESS		= 0,
	BNXT_TF_RC_NORMAL		= 1,
	BNXT_TF_RC_FID			= 2,
};

/* eth IPv4 Type */
enum bnxt_ulp_eth_ip_type {
	BNXT_ULP_ETH_IPV4 = 4,
	BNXT_ULP_ETH_IPV6 = 5,
	BNXT_ULP_MAX_ETH_IP_TYPE = 0
};

/* ulp direction Type */
enum bnxt_ulp_direction_type {
	BNXT_ULP_DIR_INVALID,
	BNXT_ULP_DIR_INGRESS,
	BNXT_ULP_DIR_EGRESS,
};

/* enumeration of the interface types */
enum bnxt_ulp_intf_type {
	BNXT_ULP_INTF_TYPE_INVALID = 0,
	BNXT_ULP_INTF_TYPE_PF,
	BNXT_ULP_INTF_TYPE_TRUSTED_VF,
	BNXT_ULP_INTF_TYPE_VF,
	BNXT_ULP_INTF_TYPE_PF_REP,
	BNXT_ULP_INTF_TYPE_VF_REP,
	BNXT_ULP_INTF_TYPE_PHY_PORT,
	BNXT_ULP_INTF_TYPE_LAST
};

/* Truflow declarations */
void bnxt_get_parent_mac_addr(struct bnxt *bp, u8 *mac);
void bnxt_get_iface_mac(struct bnxt *bp, enum bnxt_ulp_intf_type type,
			u8 *mac, u8 *parent_mac);
u16 bnxt_get_vnic_id(struct bnxt *bp, enum bnxt_ulp_intf_type type);
u16 bnxt_get_parent_vnic_id(struct bnxt *bp,
			    enum bnxt_ulp_intf_type type);
u16 bnxt_get_svif(struct bnxt *bp_id, bool func_svif,
		  enum bnxt_ulp_intf_type type);
u16 bnxt_get_fw_func_id(struct bnxt *bp, enum bnxt_ulp_intf_type type);
u16 bnxt_get_parif(struct bnxt *bp);
u16 bnxt_get_lag_vport(struct bnxt *bp);
u16 bnxt_get_phy_port_id(struct bnxt *bp);
u16 bnxt_get_vport(struct bnxt *bp);
enum bnxt_ulp_intf_type bnxt_get_interface_type(struct bnxt *bp);
int bnxt_ulp_create_vfr_default_rules(void *vf_rep);
int bnxt_ulp_delete_vfr_default_rules(void *vf_rep);
int bnxt_ulp_mirror_op(struct bnxt *bp, enum tf_dir dir, u8 enable);

#endif /* _BNXT_TF_COMMON_H_ */
