/*
 * Copyright (c) 2015-2024, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
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
 * Description: Main component of the bnxt_re driver
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif                          /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "main.h"
#include "abi.h"
#include "bnxt_re_hsi.h"
#include "verbs.h"

#ifdef IBV_FREE_CONTEXT_IN_CONTEXT_OPS
static void bnxt_re_free_context(struct ibv_context *ibvctx);
#endif

#define PCI_VENDOR_ID_BROADCOM		0x14E4

BNXT_RE_DEFINE_CNA_TABLE(cna_table) = {
	CNA(BROADCOM, 0x1605),  /* BCM57454 Stratus NPAR */
	CNA(BROADCOM, 0x1606),	/* BCM57454 Stratus VF */
	CNA(BROADCOM, 0x1614),	/* BCM57454 Stratus */
	CNA(BROADCOM, 0x16C0),	/* BCM57417 NPAR */
	CNA(BROADCOM, 0x16C1),  /* BMC57414 VF */
	CNA(BROADCOM, 0x16CE),	/* BMC57311 */
	CNA(BROADCOM, 0x16CF),	/* BMC57312 */
	CNA(BROADCOM, 0x16D6),	/* BMC57412*/
	CNA(BROADCOM, 0x16D7),	/* BMC57414 */
	CNA(BROADCOM, 0x16D8),	/* BMC57416 Cu */
	CNA(BROADCOM, 0x16D9),	/* BMC57417 Cu */
	CNA(BROADCOM, 0x16DF),	/* BMC57314 */
	CNA(BROADCOM, 0x16E2),	/* BMC57417 */
	CNA(BROADCOM, 0x16E3),	/* BMC57416 */
	CNA(BROADCOM, 0x16E5),	/* BMC57314 VF */
	CNA(BROADCOM, 0x16EB),	/* BCM57412 NPAR */
	CNA(BROADCOM, 0x16ED),	/* BCM57414 NPAR */
	CNA(BROADCOM, 0x16EF),	/* BCM57416 NPAR */
	CNA(BROADCOM, 0x16F0),  /* BCM58730 */
	CNA(BROADCOM, 0x16F1),	/* BCM57452 Stratus Mezz */
	CNA(BROADCOM, 0x1750),	/* Chip num 57500 */
	CNA(BROADCOM, 0x1751),  /* BCM57504 Gen P5 */
	CNA(BROADCOM, 0x1752),  /* BCM57502 Gen P5 */
	CNA(BROADCOM, 0x1760),  /* BCM57608 Thor 2*/
	CNA(BROADCOM, 0xD82E),  /* BCM5760x TH2 VF */
	CNA(BROADCOM, 0x1819),  /* BCM5760x P7 VF */
	CNA(BROADCOM, 0x1803),  /* BCM57508 Gen P5 NPAR */
	CNA(BROADCOM, 0x1804),  /* BCM57504 Gen P5 NPAR */
	CNA(BROADCOM, 0x1805),  /* BCM57502 Gen P5 NPAR */
	CNA(BROADCOM, 0x1807),  /* BCM5750x Gen P5 VF */
	CNA(BROADCOM, 0x1809),  /* BCM5750x Gen P5 VF HV */
	CNA(BROADCOM, 0xD800),  /* BCM880xx SR VF */
	CNA(BROADCOM, 0xD802),  /* BCM58802 SR */
	CNA(BROADCOM, 0xD804),  /* BCM58804 SR */
	CNA(BROADCOM, 0xD818)   /* BCM58818 Gen P5 SR2 */
};

uint32_t bnxt_debug_mask;
int bnxt_freeze_on_error_cqe;

#ifdef RCP_USE_IB_UVERBS
static const struct verbs_context_ops bnxt_re_cntx_ops = {
#else
static struct ibv_context_ops bnxt_re_cntx_ops = {
#endif
#ifdef VERBS_ONLY_QUERY_DEVICE_EX_DEFINED
	.query_device_ex  = bnxt_re_query_device_ex,
#else
	.query_device  = bnxt_re_query_device,
#endif
	.query_port    = bnxt_re_query_port,
	.alloc_pd      = bnxt_re_alloc_pd,
	.dealloc_pd    = bnxt_re_free_pd,
	.reg_mr        = bnxt_re_reg_mr,
#ifdef HAVE_IBV_DMABUF
	.reg_dmabuf_mr = bnxt_re_reg_dmabuf_mr,
#endif
	.dereg_mr      = bnxt_re_dereg_mr,
	.create_cq     = bnxt_re_create_cq,
	.poll_cq       = bnxt_re_poll_cq,
	.req_notify_cq = bnxt_re_arm_cq,
	.cq_event      = bnxt_re_cq_event,
	.resize_cq     = bnxt_re_resize_cq,
	.destroy_cq    = bnxt_re_destroy_cq,
	.create_srq    = bnxt_re_create_srq,
	.modify_srq    = bnxt_re_modify_srq,
	.query_srq     = bnxt_re_query_srq,
	.destroy_srq   = bnxt_re_destroy_srq,
	.post_srq_recv = bnxt_re_post_srq_recv,
	.create_qp     = bnxt_re_create_qp,
	.query_qp      = bnxt_re_query_qp,
	.modify_qp     = bnxt_re_modify_qp,
	.destroy_qp    = bnxt_re_destroy_qp,
	.post_send     = bnxt_re_post_send,
	.post_recv     = bnxt_re_post_recv,
	.async_event   = bnxt_re_async_event,
	.create_ah     = bnxt_re_create_ah,
	.destroy_ah    = bnxt_re_destroy_ah
#ifdef HAVE_IBV_WR_API
	,
	.create_qp_ex  = bnxt_re_create_qp_ex
#endif
#ifdef HAVE_WR_BIND_MW
	,
	/* Memory Window */
	.alloc_mw      = bnxt_re_alloc_mw,
	.dealloc_mw    = bnxt_re_dealloc_mw,
	.bind_mw       = bnxt_re_bind_mw
#endif
#ifdef IBV_FREE_CONTEXT_IN_CONTEXT_OPS
	,
	.free_context = bnxt_re_free_context
#endif
};

bool bnxt_re_is_chip_gen_p5(struct bnxt_re_chip_ctx *cctx)
{
	return (cctx->chip_num == CHIP_NUM_57508 ||
		cctx->chip_num == CHIP_NUM_57504 ||
		cctx->chip_num == CHIP_NUM_57502);
}

bool _is_chip_a0(struct bnxt_re_chip_ctx *cctx)
{
	return !cctx->chip_rev;
}

bool bnxt_re_is_chip_gen_p7(struct bnxt_re_chip_ctx *cctx)
{
	return (cctx->chip_num == CHIP_NUM_58818 ||
		cctx->chip_num == CHIP_NUM_57608);
}

bool bnxt_re_is_chip_gen_p5_p7(struct bnxt_re_chip_ctx *cctx)
{
	return(bnxt_re_is_chip_gen_p5(cctx) || bnxt_re_is_chip_gen_p7(cctx));
}

bool _is_db_drop_recovery_enable(struct bnxt_re_context *cntx)
{
	return cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_DBR_RECOVERY_ENABLED;
}

static inline bool bnxt_re_is_wcdpi_enabled(struct bnxt_re_context *cntx)
{
	return cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_WC_DPI_ENABLED;
}

/* Removed wcdpi arg since bnxt_re_alloc_map_push_page_abi_v8 will manage.
 */
static int bnxt_re_map_db_page(struct bnxt_re_context *cntx, __u32 pg_size,
			       int cmd_fd, uint64_t uc_db_mmap_key,
			       uint32_t dpi)
{
	cntx->udpi.dpindx = dpi;
	cntx->udpi.dbpage = mmap(NULL, pg_size, PROT_WRITE,
				 MAP_SHARED, cmd_fd, uc_db_mmap_key);
	if (cntx->udpi.dbpage == MAP_FAILED)
		return -ENOMEM;

#ifdef BNXT_RE_HAVE_DB_LOCK
	pthread_spin_init(&cntx->udpi.db_lock, PTHREAD_PROCESS_PRIVATE);
#endif
	return 0;
}

/* Determine the env variable */
static int single_threaded_app(void)
{
	char *env;

	env = getenv("BNXT_SINGLE_THREADED");
	if (env)
		return strcmp(env, "1") ? 0 : 1;

	return 0;
}

#ifdef IB_USER_IOCTL_CMDS
static int bnxt_re_alloc_map_dbr_pacing_page(struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_mmap_info minfo = {};
	int ret;

	minfo.type = BNXT_RE_ALLOC_DBR_PAGE;
	ret = bnxt_re_alloc_page(ibvctx, &minfo, NULL);
	if (ret)
		return ret;

	cntx->dbr_pacing_page = mmap(NULL, minfo.alloc_size, PROT_READ,
				     MAP_SHARED, ibvctx->cmd_fd,
				     minfo.alloc_offset);
	if (cntx->dbr_pacing_page == MAP_FAILED)
		return -ENOMEM;

	return 0;
}

static int bnxt_re_alloc_map_dbr_bar_page(struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_mmap_info minfo = {};
	int ret;

	minfo.type = BNXT_RE_ALLOC_DBR_PACING_BAR;
	ret = bnxt_re_alloc_page(ibvctx, &minfo, NULL);
	if (ret)
		return ret;

	cntx->dbr_pacing_bar = mmap(NULL, minfo.alloc_size, PROT_WRITE,
				    MAP_SHARED, ibvctx->cmd_fd,
				    minfo.alloc_offset);
	if (cntx->dbr_pacing_bar == MAP_FAILED)
		return -ENOMEM;

	return 0;
}

static int bnxt_re_alloc_map_push_page_abi_v8(struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_mmap_info minfo = {};
	int ret;

	minfo.type = BNXT_RE_ALLOC_WC_PAGE;
	ret = bnxt_re_alloc_page(ibvctx, &minfo, NULL);
	if (ret)
		return ret;

	cntx->udpi.wcdbpg = mmap(NULL, minfo.alloc_size, PROT_WRITE,
				 MAP_SHARED, ibvctx->cmd_fd, minfo.alloc_offset);
	if (cntx->udpi.wcdbpg == MAP_FAILED)
		return -ENOMEM;

	cntx->udpi.wcdpi = minfo.dpi;

	return 0;
}
#endif

static int bnxt_re_alloc_map_push_page_abi_v7(struct bnxt_re_context *cntx,
					      __u32 pg_size, int cmd_fd,
					      uint64_t wc_db_mmap_key,
					      uint32_t wcdpi)
{
	cntx->udpi.wcdbpg = mmap(NULL, pg_size, PROT_WRITE,
				 MAP_SHARED, cmd_fd,
				 wc_db_mmap_key);
	if (cntx->udpi.wcdbpg == MAP_FAILED)
		return -ENOMEM;
	cntx->udpi.wcdpi = wcdpi;

	return 0;
}

void bnxt_open_debug_file(FILE **dbg_fp)
{
	FILE *default_dbg_fp = NULL;
	char *env;

	env = getenv("BNXT_DEBUG_FILE");

	if (!env)
		env = "/var/log/messages";

	*dbg_fp = fopen(env, "aw+");
	if (!*dbg_fp) {
		*dbg_fp = default_dbg_fp;
		bnxt_err(NULL, "Failed opening debug file %s\n", env);
		return;
	}
}

void bnxt_close_debug_file(FILE *dbg_fp)
{
	if (dbg_fp && dbg_fp != stderr)
		fclose(dbg_fp);
}

void bnxt_set_debug_mask(void)
{
	char *env;

	env = getenv("BNXT_DEBUG_MASK");
	if (env)
		bnxt_debug_mask = strtol(env, NULL, 0);
}

static void set_freeze_on_error(void)
{
	char *env;

	env = getenv("BNXT_FREEZE_ON_ERROR_CQE");
	if (env)
		bnxt_freeze_on_error_cqe = strtol(env, NULL, 0);
}

/* Static Context Init functions */
static int _bnxt_re_init_context(struct bnxt_re_dev *dev,
				 struct bnxt_re_context *cntx,
				 struct bnxt_re_uctx_resp *resp, int cmd_fd)
{
	struct bnxt_re_pacing_data *pacing_data;

	bnxt_single_threaded = 0;
	cntx->cctx = malloc(sizeof(struct bnxt_re_chip_ctx));
	if (!cntx->cctx)
		goto failed;

	if (BNXT_RE_ABI_VERSION >= 4) {
		cntx->cctx->chip_num = resp->chip_id0 & 0xFFFF;
		cntx->cctx->chip_rev = (resp->chip_id0 >>
					BNXT_RE_CHIP_ID0_CHIP_REV_SFT) & 0xFF;
		cntx->cctx->chip_metal = (resp->chip_id0 >>
					  BNXT_RE_CHIP_ID0_CHIP_MET_SFT) &
					  0xFF;
		cntx->cctx->chip_is_gen_p5_p7 = bnxt_re_is_chip_gen_p5_p7(cntx->cctx);
		cntx->cctx->chip_is_gen_p7 = bnxt_re_is_chip_gen_p7(cntx->cctx);
	}
	if (BNXT_RE_ABI_VERSION != 4) {
		cntx->dev_id = resp->dev_id;
		cntx->max_qp = resp->max_qp;
	}

	if (BNXT_RE_ABI_VERSION > 5)
		cntx->modes = resp->modes;
	cntx->comp_mask = resp->comp_mask;
	cntx->db_push_mode = resp->db_push_mode;
	dev->pg_size = resp->pg_size;
	dev->cqe_size = resp->cqe_size;
	dev->max_cq_depth = resp->max_cqd;

#ifdef ROCELIB_DEBUG
	if (cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_MSN_TABLE_ENABLED)
		fprintf(stderr, "Broadcom MSN based transmission is enabled\n");
#endif

	if (bnxt_re_map_db_page(cntx, dev->pg_size, cmd_fd,
				resp->uc_db_mmap_key, resp->dpi))
		goto free;

	if (bnxt_re_is_wcdpi_enabled(cntx)) {
#ifdef IB_USER_IOCTL_CMDS
		if (dev->driver_abi_version == BNXT_RE_ABI_VERSION_UVERBS_IOCTL)
			bnxt_re_alloc_map_push_page_abi_v8(&cntx->ibvctx.context);
		else
			bnxt_re_alloc_map_push_page_abi_v7(cntx, dev->pg_size,
							   cmd_fd, resp->wc_db_mmap_key,
							   resp->wcdpi);
#else
		bnxt_re_alloc_map_push_page_abi_v7(cntx, dev->pg_size,
						   cmd_fd, resp->wc_db_mmap_key,
						   resp->wcdpi);
#endif
		if (cntx->cctx->chip_is_gen_p5_p7 && cntx->udpi.wcdpi)
			bnxt_re_init_pbuf_list(cntx);
	}

	if (cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_DBR_PACING_ENABLED) {
		if (dev->driver_abi_version == BNXT_RE_ABI_VERSION)
			goto dbr_pacing_mmap_abi_v7;

#ifdef IB_USER_IOCTL_CMDS
		if (bnxt_re_alloc_map_dbr_pacing_page(&cntx->ibvctx.context))
			goto free;

		if (bnxt_re_alloc_map_dbr_bar_page(&cntx->ibvctx.context)) {
			munmap(cntx->dbr_pacing_page, dev->pg_size);
			cntx->dbr_pacing_page = NULL;
			goto free;
		}
#endif
dbr_pacing_mmap_abi_v7:

		if (dev->driver_abi_version == BNXT_RE_ABI_VERSION_UVERBS_IOCTL)
			goto dbr_pacing_mmap_done;

		cntx->dbr_pacing_page = mmap(NULL, dev->pg_size, PROT_READ,
					     MAP_SHARED, cmd_fd,
					     resp->dbr_pacing_mmap_key);
		if (cntx->dbr_pacing_page == MAP_FAILED) {
			cntx->dbr_pacing_page = NULL;
			goto free;
		}

		cntx->dbr_pacing_bar = mmap(NULL, dev->pg_size, PROT_READ,
					    MAP_SHARED, cmd_fd,
					    resp->dbr_pacing_bar_mmap_key & BNXT_RE_PAGE_MASK(dev->pg_size));
		if (cntx->dbr_pacing_bar == MAP_FAILED) {
			munmap(cntx->dbr_pacing_page, dev->pg_size);
			cntx->dbr_pacing_page = NULL;
			cntx->dbr_pacing_bar = NULL;
			goto free;
		}

dbr_pacing_mmap_done:
		/* TBD - Upstream don't have below code */
		pacing_data = (struct bnxt_re_pacing_data *)cntx->dbr_pacing_page;

		dev->db_fifo_max_depth = pacing_data->fifo_max_depth;
		if (!dev->db_fifo_max_depth)
			dev->db_fifo_max_depth = BNXT_RE_MAX_FIFO_DEPTH(cntx->cctx);
		dev->db_fifo_room_mask  = pacing_data->fifo_room_mask;
		if (!dev->db_fifo_room_mask)
			dev->db_fifo_room_mask = BNXT_RE_DB_FIFO_ROOM_MASK(cntx->cctx);
		dev->db_fifo_room_shift = pacing_data->fifo_room_shift;
		if (!dev->db_fifo_room_shift)
			dev->db_fifo_room_shift = BNXT_RE_DB_FIFO_ROOM_SHIFT;
		dev->db_grc_reg_offset = pacing_data->grc_reg_offset;
		if (!dev->db_grc_reg_offset)
			dev->db_grc_reg_offset = BNXT_RE_GRC_FIFO_REG_OFFSET;
	}

	if (cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_SMALL_RECV_WQE_DRV_SUP)
		dev->small_rx_wqe = true;

	if (_is_db_drop_recovery_enable(cntx)) {
		INIT_DBLY_LIST_HEAD(&cntx->qp_dbr_res.head);
		pthread_spin_init(&cntx->qp_dbr_res.lock, PTHREAD_PROCESS_PRIVATE);
		INIT_DBLY_LIST_HEAD(&cntx->cq_dbr_res.head);
		pthread_spin_init(&cntx->cq_dbr_res.lock, PTHREAD_PROCESS_PRIVATE);
		INIT_DBLY_LIST_HEAD(&cntx->srq_dbr_res.head);
		pthread_spin_init(&cntx->srq_dbr_res.lock, PTHREAD_PROCESS_PRIVATE);
	}

	if (cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_MAX_RQ_WQES)
		cntx->max_rq_wqes = resp->max_rq_wqes;

	/* check for ENV for single thread */
	bnxt_single_threaded = single_threaded_app();
	if (bnxt_single_threaded)
		fprintf(stderr, DEV " Running in Single threaded mode\n");

	bnxt_open_debug_file(&cntx->dbg_fp);
	bnxt_set_debug_mask();
	set_freeze_on_error();
#if defined(BNXT_RE_ENABLE_DEV_DEBUG)
	bnxt_rocelib_test_init();
#endif
	pthread_mutex_init(&cntx->shlock, NULL);

	return 0;

free:
	free(cntx->cctx);
failed:
	fprintf(stderr, DEV "Failed to initialize context for device\n");
	return errno;
}

static void _bnxt_re_uninit_context(struct bnxt_re_dev *dev,
				    struct bnxt_re_context *cntx)
{
	int ret;

	/* Unmap if anything device specific was
	 * mapped in init_context.
	 */
	pthread_mutex_destroy(&cntx->shlock);

	/* Un-map DPI only for the first PD that was
	 * allocated in this context.
	 */
	if (cntx->udpi.wcdbpg && cntx->udpi.wcdbpg != MAP_FAILED) {
		munmap(cntx->udpi.wcdbpg, dev->pg_size);
		cntx->udpi.wcdbpg = NULL;
		/* TBD - Below is missing in upstream */
		bnxt_re_destroy_pbuf_list(cntx);
	}

	if (cntx->udpi.dbpage && cntx->udpi.dbpage != MAP_FAILED) {
#ifdef BNXT_RE_HAVE_DB_LOCK
		pthread_spin_destroy(&cntx->udpi.db_lock);
#endif
		munmap(cntx->udpi.dbpage, dev->pg_size);
		cntx->udpi.dbpage = NULL;
	}

	if (cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_DBR_PACING_ENABLED) {
		munmap(cntx->dbr_pacing_page, dev->pg_size);
		cntx->dbr_pacing_page = NULL;
		/* TBD - Earlier code never called munmap dbr_pacing_bar */
		munmap(cntx->dbr_pacing_bar, dev->pg_size);
		cntx->dbr_pacing_bar = NULL;
	}

	if (cntx->dbr_cq) {
		if (cntx->dbr_thread) {
			ret = pthread_cancel(cntx->dbr_thread);
			if (ret)
				fprintf(stderr, DEV "pthread_cancel error %d\n", ret);
			ret = pthread_join(cntx->dbr_thread, NULL);
			if (ret)
				fprintf(stderr, DEV "pthread_join error %d\n", ret);
		}
		if (cntx->db_recovery_page)
			munmap(cntx->db_recovery_page, dev->pg_size);
		ret = ibv_destroy_cq(cntx->dbr_cq);
		if (ret)
			fprintf(stderr, DEV "ibv_destroy_cq error %d\n", ret);
	}

	if (cntx->dbr_ev_chan) {
		ret = ibv_destroy_comp_channel(cntx->dbr_ev_chan);
		if (ret)
			fprintf(stderr,	DEV "ibv_destroy_comp_channel error\n");
	}
	if (_is_db_drop_recovery_enable(cntx)) {
		pthread_spin_destroy(&cntx->qp_dbr_res.lock);
		pthread_spin_destroy(&cntx->cq_dbr_res.lock);
		pthread_spin_destroy(&cntx->srq_dbr_res.lock);
	}
	free(cntx->cctx);
}

#ifdef RCP_USE_ALLOC_CONTEXT
/* Context alloc/free functions */
static struct verbs_context *bnxt_re_alloc_context(struct ibv_device *vdev,
						   int cmd_fd
#ifdef ALLOC_CONTEXT_HAS_PRIVATE_DATA
						   , void *private_data
#endif
						)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(vdev);
	struct bnxt_re_uctx_resp resp = {};
	struct bnxt_re_uctx_req req = {};
	struct bnxt_re_context *cntx;
	int ret;

	cntx = compat_verbs_init_and_alloc_context(vdev, cmd_fd, cntx, ibvctx);
	if (!cntx)
		return NULL;

	req.comp_mask |= BNXT_RE_COMP_MASK_REQ_UCNTX_POW2_SUPPORT;
	req.comp_mask |= BNXT_RE_COMP_MASK_REQ_UCNTX_RSVD_WQE;
	req.comp_mask |= BNXT_RE_COMP_MASK_REQ_UCNTX_SMALL_RECV_WQE_LIB_SUP;
	if (ibv_cmd_get_context(&cntx->ibvctx, &req.cmd, sizeof(req),
				&resp.resp, sizeof(resp))) {
		fprintf(stderr, DEV "Failed to get context for device\n");
		goto failed;
	}

	ret = _bnxt_re_init_context(rdev, cntx, &resp, cmd_fd);
	if (ret != 0)
		goto failed;

	verbs_set_ops(&cntx->ibvctx, &bnxt_re_cntx_ops);
	cntx->rdev = rdev;
	ret = bnxt_re_query_device_compat(&cntx->ibvctx.context,
					  &rdev->devattr);
	if (ret)
		goto failed;

	/* If max_rq_wqes is not populated, get it from devattr */
	if (!cntx->max_rq_wqes)
		cntx->max_rq_wqes = rdev->devattr.max_qp_wr;

	return &cntx->ibvctx;
failed:
	fprintf(stderr, DEV "Failed to allocate context for device\n");
	verbs_uninit_context(&cntx->ibvctx);
	free(cntx);
	return NULL;
}

static void bnxt_re_free_context(struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *rdev = cntx->rdev;

	bnxt_close_debug_file(cntx->dbg_fp);
	_bnxt_re_uninit_context(rdev, cntx);

	verbs_uninit_context(&cntx->ibvctx);
	free(cntx);
}

#else
/* Context Init functions */
int bnxt_re_init_context(struct verbs_device *vdev, struct ibv_context *ibvctx,
			 int cmd_fd)
{
	struct bnxt_re_uctx_resp resp = {};
	struct bnxt_re_uctx_req req = {};
	struct bnxt_re_context *cntx;
	struct bnxt_re_dev *rdev;
	int ret;

	rdev = to_bnxt_re_dev(&vdev->device);
	cntx = to_bnxt_re_context(ibvctx);
	ibvctx->cmd_fd = cmd_fd;

	req.comp_mask |= BNXT_RE_COMP_MASK_REQ_UCNTX_POW2_SUPPORT;
	req.comp_mask |= BNXT_RE_COMP_MASK_REQ_UCNTX_RSVD_WQE;
	if (ibv_cmd_get_context(ibvctx, &req.cmd, sizeof(req),
				&resp.resp, sizeof(resp))) {
		fprintf(stderr, DEV "Failed to get context for device\n");
		return errno;
	}

	ret = _bnxt_re_init_context(rdev, cntx, &resp, cmd_fd);
	if (!ret)
		ibvctx->ops = bnxt_re_cntx_ops;

	cntx->rdev = rdev;
	ret = bnxt_re_query_device_compat(&cntx->ibvctx, &rdev->devattr);

	/* If max_rq_wqes is not populated, get it from devattr */
	if (!cntx->max_rq_wqes)
		cntx->max_rq_wqes = rdev->devattr.max_qp_wr;

	return ret;
}

void bnxt_re_uninit_context(struct verbs_device *vdev,
			    struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx;
	struct bnxt_re_dev *rdev;

	cntx = to_bnxt_re_context(ibvctx);
	rdev = cntx->rdev;
	_bnxt_re_uninit_context(rdev, cntx);
}
#endif

#if defined(HAVE_RDMA_CORE_PKG) && !defined(RCP_HAS_PROVIDER_DRIVER)
static struct verbs_device_ops bnxt_re_dev_ops = {
	.init_context = bnxt_re_init_context,
	.uninit_context = bnxt_re_uninit_context,
};
#endif

#ifndef RCP_HAS_PROVIDER_DRIVER
static struct verbs_device *bnxt_re_driver_init(const char *uverbs_sys_path,
						int abi_version)
{
	char value[10];
	struct bnxt_re_dev *dev;
	unsigned vendor, device;
	int i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
				value, sizeof(value)) < 0)
		return NULL;
	vendor = strtol(value, NULL, 16);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
				value, sizeof(value)) < 0)
		return NULL;
	device = strtol(value, NULL, 16);

	for (i = 0; i < sizeof(cna_table) / sizeof(cna_table[0]); ++i)
		if (vendor == cna_table[i].vendor &&
		    device == cna_table[i].device)
			goto found;
	return NULL;
found:
	if (abi_version != BNXT_RE_ABI_VERSION) {
		fprintf(stderr, DEV "FATAL: Max supported ABI of %s is %d "
			"check for the latest version of kernel driver and"
			"user library\n", uverbs_sys_path, abi_version);
		return NULL;
	}

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, DEV "Failed to allocate device for %s\n",
			uverbs_sys_path);
		return NULL;
	}

	dev->vdev.sz = sizeof(*dev);
	dev->vdev.size_of_context =
		sizeof(struct bnxt_re_context) - sizeof(struct ibv_context);
#ifdef HAVE_RDMA_CORE_PKG
	dev->vdev.ops = &bnxt_re_dev_ops;
#else
	dev->vdev.init_context = bnxt_re_init_context;
	dev->vdev.uninit_context = bnxt_re_uninit_context;
#endif

	return &dev->vdev;
}

static __attribute__((constructor)) void bnxt_re_register_driver(void)
{
	verbs_register_driver("bnxtre", bnxt_re_driver_init);
}
#else
static struct verbs_device *
bnxt_re_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct bnxt_re_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

#ifndef RCP_USE_ALLOC_CONTEXT
	dev->vdev.sz = sizeof(*dev);
	dev->vdev.size_of_context =
		sizeof(struct bnxt_re_context) - sizeof(struct ibv_context);
#endif
	dev->pg_size = sysconf(_SC_PAGESIZE);
	dev->driver_abi_version = sysfs_dev->abi_ver;

	return &dev->vdev;
}

static const struct verbs_device_ops bnxt_re_dev_ops = {
	.name = "bnxt_re",
#ifdef IB_USER_IOCTL_CMDS
	.match_min_abi_version = BNXT_RE_ABI_VERSION,
	.match_max_abi_version = BNXT_RE_ABI_VERSION_UVERBS_IOCTL,
#else
	/* In below case driver must have abi version 7.
	 * abi version 7 is driver merged ABI but not supporting
	 * UAPI IOCTL for older kernel only.
	 */
	.match_min_abi_version = BNXT_RE_ABI_VERSION,
	.match_max_abi_version = BNXT_RE_ABI_VERSION,
#endif
	.match_table = cna_table,
	.alloc_device = bnxt_re_device_alloc,
#ifdef RCP_USE_ALLOC_CONTEXT
	.alloc_context = bnxt_re_alloc_context,
#ifndef IBV_FREE_CONTEXT_IN_CONTEXT_OPS
	.free_context = bnxt_re_free_context,
#endif
#else
	.init_context = bnxt_re_init_context,
	.uninit_context = bnxt_re_uninit_context,
#endif
};

COMPAT_PROVIDER_DRIVER(bnxt_re, bnxt_re_dev_ops);
#endif /* RCP_HAS_PROVIDER_DRIVER */
