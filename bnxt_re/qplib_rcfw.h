/*
 * Copyright (c) 2015-2024, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Inc. and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: RDMA Controller HW interface (header)
 */

#ifndef __BNXT_QPLIB_RCFW_H__
#define __BNXT_QPLIB_RCFW_H__

#include <linux/semaphore.h>
#include "qplib_tlv.h"

#define RCFW_CMDQ_TRIG_VAL		1
#define RCFW_COMM_PCI_BAR_REGION	0
#define RCFW_COMM_CONS_PCI_BAR_REGION	2
#define RCFW_COMM_BASE_OFFSET		0x600
#define RCFW_PF_VF_COMM_PROD_OFFSET	0xc
#define RCFW_COMM_TRIG_OFFSET		0x100
#define RCFW_COMM_SIZE			0x104

#define RCFW_DBR_PCI_BAR_REGION		2
#define RCFW_DBR_BASE_PAGE_SHIFT	12
#define RCFW_MAX_LATENCY_SEC_SLAB_INDEX	128
#define RCFW_MAX_LATENCY_MSEC_SLAB_INDEX	3000
#define RCFW_MAX_STAT_INDEX	0x3FFFF
#define	RCFW_FW_STALL_MAX_TIMEOUT	40

extern unsigned int cmdq_shadow_qd;
/* Cmdq contains a fix number of a 16-Byte slots */
struct bnxt_qplib_cmdqe {
	u8		data[16];
};
#define BNXT_QPLIB_CMDQE_UNITS		sizeof(struct bnxt_qplib_cmdqe)
#define BNXT_UDCC_SESSION_SZ_UNITS	16

static inline void bnxt_qplib_rcfw_cmd_prep(void *r, u8 opcode, u8 cmd_size)
{
	struct cmdq_base *req = r;

	req->opcode = opcode;
	req->cmd_size = cmd_size;
}

/* Shadow queue depth for non blocking command */
#define RCFW_CMD_NON_BLOCKING_SHADOW_QD	64
#define RCFW_CMD_DEV_ERR_CHECK_TIME_MS	1000 /* 1 Second time out*/
#define RCFW_ERR_RETRY_COUNT		(RCFW_CMD_WAIT_TIME_MS / RCFW_CMD_DEV_ERR_CHECK_TIME_MS)

/* CMDQ elements */
#define BNXT_QPLIB_CMDQE_MAX_CNT	8192
#define BNXT_QPLIB_CMDQE_BYTES		(BNXT_QPLIB_CMDQE_MAX_CNT * 	\
					 BNXT_QPLIB_CMDQE_UNITS)
#define BNXT_QPLIB_CMDQE_NPAGES		((BNXT_QPLIB_CMDQE_BYTES %	\
					  PAGE_SIZE) ?			\
					  ((BNXT_QPLIB_CMDQE_BYTES /	\
					    PAGE_SIZE) + 1) :		\
					  (BNXT_QPLIB_CMDQE_BYTES /	\
					   PAGE_SIZE))
#define BNXT_QPLIB_CMDQE_PAGE_SIZE	(BNXT_QPLIB_CMDQE_NPAGES *	\
					 PAGE_SIZE)

#define RCFW_MAX_OUTSTANDING_CMD	BNXT_QPLIB_CMDQE_MAX_CNT
#define RCFW_MAX_COOKIE_VALUE		(BNXT_QPLIB_CMDQE_MAX_CNT - 1)
#define RCFW_CMD_IS_BLOCKING		0x8000
#define RCFW_NO_FW_ACCESS(rcfw)						\
	(test_bit(ERR_DEVICE_DETACHED, &(rcfw)->cmdq.flags) ||		\
	 pci_channel_offline((rcfw)->pdev))

/* Get the number of command units required for the req. The
 * function returns correct value only if called before
 * setting using bnxt_qplib_set_cmd_slots
 */
static inline u32 bnxt_qplib_get_cmd_slots(struct cmdq_base *req)
{
	u32 cmd_units = 0;

	if (HAS_TLV_HEADER(req)) {
		struct roce_tlv *tlv_req = (struct roce_tlv *)req;
		cmd_units = tlv_req->total_size;
	} else {
		cmd_units = (req->cmd_size + BNXT_QPLIB_CMDQE_UNITS - 1) /
			    BNXT_QPLIB_CMDQE_UNITS;
	}
	return cmd_units;
}

/* Set the cmd_size to a factor of CMDQE unit */
static inline u32 bnxt_qplib_set_cmd_slots(struct cmdq_base *req)
{
	u32 cmd_byte = 0;

	if (HAS_TLV_HEADER(req)) {
		struct roce_tlv *tlv_req = (struct roce_tlv *)req;
		cmd_byte = tlv_req->total_size * BNXT_QPLIB_CMDQE_UNITS;
	} else {
		cmd_byte = req->cmd_size;
		req->cmd_size = (req->cmd_size + BNXT_QPLIB_CMDQE_UNITS - 1) /
				 BNXT_QPLIB_CMDQE_UNITS;
	}

	return cmd_byte;
}

/* CREQ */
/* Allocate 1 per QP for async error notification for now */
#define BNXT_QPLIB_CREQE_MAX_CNT	(64 * 1024)
#define BNXT_QPLIB_CREQE_UNITS		16	/* 16-Bytes per prod unit */

#define CREQ_CMP_VALID(hdr, pass)				\
	(!!((hdr)->v & CREQ_BASE_V) ==				\
	   !(pass & BNXT_QPLIB_FLAG_EPOCH_CONS_MASK))

#define CREQ_ENTRY_POLL_BUDGET		8

typedef int (*aeq_handler_t)(struct bnxt_qplib_rcfw *, void *, void *);

struct bnxt_qplib_crsqe {
	struct creq_qp_event	*resp;
	u32			req_size;
	bool			is_waiter_alive;
	bool			is_internal_cmd;
	bool			is_in_used;

	/* Free slots at the time of submission */
	u32			free_slots;
	unsigned long		send_timestamp;
	u8			opcode;
	u8			requested_qp_state;
};

struct bnxt_qplib_rcfw_sbuf {
	void *sb;
	dma_addr_t dma_addr;
	u32 size;
};

#define BNXT_QPLIB_OOS_COUNT_MASK 0xFFFFFFFF

#define FIRMWARE_INITIALIZED_FLAG	(0)
#define FIRMWARE_FIRST_FLAG		(31)
#define FIRMWARE_STALL_DETECTED		(3)
#define ERR_DEVICE_DETACHED		(4)
struct bnxt_qplib_cmdq_mbox {
	struct bnxt_qplib_reg_desc	reg;
	void __iomem			*prod;
	void __iomem			*db;
};

struct bnxt_qplib_cmdq_ctx {
	struct bnxt_qplib_hwq		hwq;
	struct bnxt_qplib_cmdq_mbox	cmdq_mbox;
	wait_queue_head_t		waitq;
	unsigned long			flags;
	unsigned long			last_seen;
	u32				seq_num;
};

struct bnxt_qplib_creq_db {
	struct bnxt_qplib_reg_desc	reg;
	void __iomem			*db;
	struct bnxt_qplib_db_info	dbinfo;
};

struct bnxt_qplib_creq_stat {
	u64	creq_arm_count;
	u64	creq_tasklet_schedule_count;
	u64	creq_qp_event_processed;
	u64	creq_func_event_processed;
};

struct bnxt_qplib_creq_ctx {
	struct bnxt_qplib_hwq		hwq;
	struct bnxt_qplib_creq_db	creq_db;
	struct bnxt_qplib_creq_stat	stats;
	struct tasklet_struct		creq_tasklet;
	aeq_handler_t			aeq_handler;
	char				*irq_name;
	int				msix_vec;
	u16				ring_id;
	bool				requested; /*irq handler installed */
};

/* RCFW Communication Channels */
#define BNXT_QPLIB_RCFW_SEND_RETRY_COUNT 4000
struct bnxt_qplib_rcfw {
	struct pci_dev			*pdev;
	struct bnxt_qplib_res		*res;
	struct bnxt_qplib_cmdq_ctx	cmdq;
	struct bnxt_qplib_creq_ctx	creq;
	struct bnxt_qplib_crsqe		*crsqe_tbl;
	u32	rcfw_lat_slab_sec[RCFW_MAX_LATENCY_SEC_SLAB_INDEX];

	/* Slow path Perf Stats */
	u32	*rcfw_lat_slab_msec;
	u64	*qp_create_stats;
	u64	*qp_destroy_stats;
	u64	*qp_modify_stats;
	u64	*mr_create_stats;
	u64	*mr_destroy_stats;
	u32	qp_create_stats_id;
	u32	qp_destroy_stats_id;
	u32	qp_modify_stats_id;
	u32	mr_create_stats_id;
	u32	mr_destroy_stats_id;
	bool	sp_perf_stats_enabled;

#define CTXM_DATA_INDEX_MAX	1024
	bool roce_context_destroy_sb;
	bool roce_udcc_session_destroy_sb;
	u32 udcc_session_sb_sz;
	u32 qp_ctxm_data_index;
	u32 cq_ctxm_data_index;
	u32 mrw_ctxm_data_index;
	u32 srq_ctxm_data_index;
	u16 qp_ctxm_size;
	u16 cq_ctxm_size;
	u16 mrw_ctxm_size;
	u16 srq_ctxm_size;
	void *qp_ctxm_data;
	void *cq_ctxm_data;
	void *mrw_ctxm_data;
	void *srq_ctxm_data;

	/* odd place to have following members. */
	bool init_oos_stats;
	/* cached from chip cctx for quick reference in slow path */
	u16 max_timeout;
	u64 oos_prev;
	u32 num_irq_stopped;
	u32 num_irq_started;
	u32 poll_in_intr_en;
	u32 poll_in_intr_dis;
	atomic_t rcfw_intr_enabled;
	u32 cmdq_full_dbg;
	struct semaphore rcfw_inflight;
	unsigned int	curr_shadow_qd;
	atomic_t timeout_send;
};

struct bnxt_qplib_cmdqmsg {
	struct cmdq_base	*req;
	struct creq_base	*resp;
	void			*sb;
	u32			req_sz;
	u32			res_sz;
	u8			block;
	u8			prio;
	/* TBD - xid can be used in future for generic tracking */
	u8			qp_state;
};

enum bnxt_slowpath_cmd_prio {
	BNXT_RE_NONBLOCK_PRI_LOW = 0,
	BNXT_RE_NONBLOCK_PRI_HI
};

static inline void bnxt_qplib_fill_cmdqmsg(struct bnxt_qplib_cmdqmsg *msg,
					   void *req, void *resp, void *sb,
					   u32 req_sz, u32 res_sz, u8 block)
{
	msg->req = req;
	msg->resp = resp;
	msg->sb = sb;
	msg->req_sz = req_sz;
	msg->res_sz = res_sz;
	msg->block = block;
}

void bnxt_qplib_free_rcfw_channel(struct bnxt_qplib_res *res);
int bnxt_qplib_alloc_rcfw_channel(struct bnxt_qplib_res *res);
void bnxt_qplib_rcfw_stop_irq(struct bnxt_qplib_rcfw *rcfw, bool kill);
void bnxt_qplib_disable_rcfw_channel(struct bnxt_qplib_rcfw *rcfw);
int bnxt_qplib_rcfw_start_irq(struct bnxt_qplib_rcfw *rcfw, int msix_vector,
			      bool need_init);
int bnxt_qplib_enable_rcfw_channel(struct bnxt_qplib_rcfw *rcfw,
				   int msix_vector,
				   int cp_bar_reg_off,
				   aeq_handler_t aeq_handler);

struct bnxt_qplib_rcfw_sbuf *bnxt_qplib_rcfw_alloc_sbuf(
				struct bnxt_qplib_rcfw *rcfw,
				u32 size);
void bnxt_qplib_rcfw_free_sbuf(struct bnxt_qplib_rcfw *rcfw,
				struct bnxt_qplib_rcfw_sbuf *sbuf);
int bnxt_qplib_rcfw_send_message(struct bnxt_qplib_rcfw *rcfw,
				 struct bnxt_qplib_cmdqmsg *msg);

int bnxt_qplib_deinit_rcfw(struct bnxt_qplib_rcfw *rcfw);
int bnxt_qplib_init_rcfw(struct bnxt_qplib_rcfw *rcfw, int is_virtfn);
void bnxt_qplib_mark_qp_error(void *qp_handle);
int __check_cmdq_stall(struct bnxt_qplib_rcfw *rcfw,
			u32 *cur_prod, u32 *cur_cons);
#endif
