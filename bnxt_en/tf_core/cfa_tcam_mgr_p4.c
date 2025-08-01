// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2021-2022 Broadcom
 * All rights reserved.
 */

#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include "hcapi_cfa_defs.h"
#include "bnxt_hsi.h"
#include "bnxt_compat.h"
#include "bnxt.h"
#include "cfa_tcam_mgr.h"
#include "cfa_tcam_mgr_p4.h"
#include "cfa_tcam_mgr_device.h"
#include "cfa_resource_types.h"
#include "tf_util.h"
#include "tf_session.h"

/* Sizings of the TCAMs on Whitney+/Stingray */
#define MAX_ROW_WIDTH    48
#define MAX_RESULT_SIZE  8

/* TCAM definitions
 *
 * These define the TCAMs in HW.
 *
 * Note: Set xxx_TCAM_[R|T]X_NUM_ROWS to zero if a TCAM is either not supported
 * by HW or not supported by TCAM Manager.
 */

/* L2 Context TCAM */
#define L2_CTXT_TCAM_RX_MAX_SLICES  1
#define L2_CTXT_TCAM_RX_ROW_WIDTH   TF_BITS2BYTES_WORD_ALIGN(167)
#define L2_CTXT_TCAM_RX_NUM_ROWS    1024
#define L2_CTXT_TCAM_RX_MAX_ENTRIES (L2_CTXT_TCAM_RX_MAX_SLICES * \
				     L2_CTXT_TCAM_RX_NUM_ROWS)
#define L2_CTXT_TCAM_RX_RESULT_SIZE 8

#define L2_CTXT_TCAM_TX_MAX_SLICES  L2_CTXT_TCAM_RX_MAX_SLICES
#define L2_CTXT_TCAM_TX_ROW_WIDTH   L2_CTXT_TCAM_RX_ROW_WIDTH
#define L2_CTXT_TCAM_TX_NUM_ROWS    L2_CTXT_TCAM_RX_NUM_ROWS
#define L2_CTXT_TCAM_TX_MAX_ENTRIES L2_CTXT_TCAM_RX_MAX_ENTRIES
#define L2_CTXT_TCAM_TX_RESULT_SIZE L2_CTXT_TCAM_RX_RESULT_SIZE

/* Profile TCAM */
#define PROF_TCAM_RX_MAX_SLICES  1
#define PROF_TCAM_RX_ROW_WIDTH   TF_BITS2BYTES_WORD_ALIGN(81)
#define PROF_TCAM_RX_NUM_ROWS    1024
#define PROF_TCAM_RX_MAX_ENTRIES (PROF_TCAM_RX_MAX_SLICES * \
				  PROF_TCAM_RX_NUM_ROWS)
#define PROF_TCAM_RX_RESULT_SIZE 8

#define PROF_TCAM_TX_MAX_SLICES  PROF_TCAM_RX_MAX_SLICES
#define PROF_TCAM_TX_ROW_WIDTH   PROF_TCAM_RX_ROW_WIDTH
#define PROF_TCAM_TX_NUM_ROWS    PROF_TCAM_RX_NUM_ROWS
#define PROF_TCAM_TX_MAX_ENTRIES PROF_TCAM_RX_MAX_ENTRIES
#define PROF_TCAM_TX_RESULT_SIZE PROF_TCAM_RX_RESULT_SIZE

/* Wildcard TCAM */
#define WC_TCAM_RX_MAX_SLICES  4
/* 82 bits per slice */
#define WC_TCAM_RX_ROW_WIDTH   (TF_BITS2BYTES_WORD_ALIGN(82) *	\
				WC_TCAM_RX_MAX_SLICES)
#define WC_TCAM_RX_NUM_ROWS    256
#define WC_TCAM_RX_MAX_ENTRIES (WC_TCAM_RX_MAX_SLICES * WC_TCAM_RX_NUM_ROWS)
#define WC_TCAM_RX_RESULT_SIZE 4

#define WC_TCAM_TX_MAX_SLICES  WC_TCAM_RX_MAX_SLICES
#define WC_TCAM_TX_ROW_WIDTH   WC_TCAM_RX_ROW_WIDTH
#define WC_TCAM_TX_NUM_ROWS    WC_TCAM_RX_NUM_ROWS
#define WC_TCAM_TX_MAX_ENTRIES WC_TCAM_RX_MAX_ENTRIES
#define WC_TCAM_TX_RESULT_SIZE WC_TCAM_RX_RESULT_SIZE

/* Source Properties TCAM */
#define SP_TCAM_RX_MAX_SLICES  1
#define SP_TCAM_RX_ROW_WIDTH   TF_BITS2BYTES_WORD_ALIGN(89)
#define SP_TCAM_RX_NUM_ROWS    512
#define SP_TCAM_RX_MAX_ENTRIES (SP_TCAM_RX_MAX_SLICES * SP_TCAM_RX_NUM_ROWS)
#define SP_TCAM_RX_RESULT_SIZE 8

#define SP_TCAM_TX_MAX_SLICES  SP_TCAM_RX_MAX_SLICES
#define SP_TCAM_TX_ROW_WIDTH   SP_TCAM_RX_ROW_WIDTH
#define SP_TCAM_TX_NUM_ROWS    SP_TCAM_RX_NUM_ROWS
#define SP_TCAM_TX_MAX_ENTRIES SP_TCAM_RX_MAX_ENTRIES
#define SP_TCAM_TX_RESULT_SIZE SP_TCAM_RX_RESULT_SIZE

/* Connection Tracking Rule TCAM */
#define CT_RULE_TCAM_RX_MAX_SLICES  1
#define CT_RULE_TCAM_RX_ROW_WIDTH   TF_BITS2BYTES_WORD_ALIGN(16)
#define CT_RULE_TCAM_RX_NUM_ROWS    16
#define CT_RULE_TCAM_RX_MAX_ENTRIES (CT_RULE_TCAM_RX_MAX_SLICES * \
				     CT_RULE_TCAM_RX_NUM_ROWS)
#define CT_RULE_TCAM_RX_RESULT_SIZE 8

#define CT_RULE_TCAM_TX_MAX_SLICES  CT_RULE_TCAM_RX_MAX_SLICES
#define CT_RULE_TCAM_TX_ROW_WIDTH   CT_RULE_TCAM_RX_ROW_WIDTH
#define CT_RULE_TCAM_TX_NUM_ROWS    CT_RULE_TCAM_RX_NUM_ROWS
#define CT_RULE_TCAM_TX_MAX_ENTRIES CT_RULE_TCAM_RX_MAX_ENTRIES
#define CT_RULE_TCAM_TX_RESULT_SIZE CT_RULE_TCAM_RX_RESULT_SIZE

/* Virtual Edge Bridge TCAM */
#define VEB_TCAM_RX_MAX_SLICES  1
#define VEB_TCAM_RX_ROW_WIDTH   TF_BITS2BYTES_WORD_ALIGN(78)
/* Tx only */
#define VEB_TCAM_RX_NUM_ROWS    1024
#define VEB_TCAM_RX_MAX_ENTRIES (VEB_TCAM_RX_MAX_SLICES * VEB_TCAM_RX_NUM_ROWS)
#define VEB_TCAM_RX_RESULT_SIZE 8

#define VEB_TCAM_TX_MAX_SLICES  VEB_TCAM_RX_MAX_SLICES
#define VEB_TCAM_TX_ROW_WIDTH   VEB_TCAM_RX_ROW_WIDTH
#define VEB_TCAM_TX_NUM_ROWS    1024
#define VEB_TCAM_TX_MAX_ENTRIES (VEB_TCAM_TX_MAX_SLICES * VEB_TCAM_TX_NUM_ROWS)
#define VEB_TCAM_TX_RESULT_SIZE VEB_TCAM_RX_RESULT_SIZE

/* Declare the table rows for each table here.  If new tables are added to the
 * enum tf_tcam_tbl_type, then new declarations will be needed here.
 *
 * The numeric suffix of the structure type indicates how many slices a
 * particular TCAM supports.
 */

struct cfa_tcam_mgr_table_rows_p4 {
	struct cfa_tcam_mgr_table_rows_1
		table_rows_L2_CTXT_TCAM_RX[L2_CTXT_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_L2_CTXT_TCAM_TX[L2_CTXT_TCAM_TX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_PROF_TCAM_RX[PROF_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_PROF_TCAM_TX[PROF_TCAM_TX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_4
		table_rows_WC_TCAM_RX[WC_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_4
		table_rows_WC_TCAM_TX[WC_TCAM_TX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_SP_TCAM_RX[SP_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_SP_TCAM_TX[SP_TCAM_TX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_CT_RULE_TCAM_RX[CT_RULE_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_CT_RULE_TCAM_TX[CT_RULE_TCAM_TX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_VEB_TCAM_RX[VEB_TCAM_RX_NUM_ROWS];
	struct cfa_tcam_mgr_table_rows_1
		table_rows_VEB_TCAM_TX[VEB_TCAM_TX_NUM_ROWS];
};

struct cfa_tcam_mgr_table_data
cfa_tcam_mgr_tables_p4[TF_DIR_MAX][CFA_TCAM_MGR_TBL_TYPE_MAX] = {
	{				/* RX */
		{			/* High AFM */
			.max_slices  = L2_CTXT_TCAM_RX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_RX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = L2_CTXT_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_HIGH,
		},
		{			/* High APPS */
			.max_slices  = L2_CTXT_TCAM_RX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_RX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = L2_CTXT_TCAM_RX_APP_HI_END,
			.max_entries = (L2_CTXT_TCAM_RX_MAX_ENTRIES / 2),
			.result_size = L2_CTXT_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_HIGH,
		},
		{			/* Low AFM */
			.max_slices  = L2_CTXT_TCAM_RX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_RX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = L2_CTXT_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_LOW,
		},
		{			/* Low APPS */
			.max_slices  = L2_CTXT_TCAM_RX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_RX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_RX_NUM_ROWS,
			.start_row   = L2_CTXT_TCAM_RX_APP_LO_START,
			.end_row     = L2_CTXT_TCAM_RX_NUM_ROWS - 1,
			.max_entries = (L2_CTXT_TCAM_RX_MAX_ENTRIES / 2),
			.result_size = L2_CTXT_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_LOW,
		},
		{			/* AFM */
			.max_slices  = PROF_TCAM_RX_MAX_SLICES,
			.row_width   = PROF_TCAM_RX_ROW_WIDTH,
			.num_rows    = PROF_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = PROF_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_PROF_TCAM,
		},
		{			/* APPS */
			.max_slices  = PROF_TCAM_RX_MAX_SLICES,
			.row_width   = PROF_TCAM_RX_ROW_WIDTH,
			.num_rows    = PROF_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = PROF_TCAM_RX_NUM_ROWS - 1,
			.max_entries = PROF_TCAM_RX_MAX_ENTRIES,
			.result_size = PROF_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_PROF_TCAM,
		},
		{			/* AFM */
			.max_slices  = WC_TCAM_RX_MAX_SLICES,
			.row_width   = WC_TCAM_RX_ROW_WIDTH,
			.num_rows    = WC_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = WC_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_WC_TCAM,
		},
		{			/* APPS */
			.max_slices  = WC_TCAM_RX_MAX_SLICES,
			.row_width   = WC_TCAM_RX_ROW_WIDTH,
			.num_rows    = WC_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = WC_TCAM_RX_NUM_ROWS - 1,
			.max_entries = WC_TCAM_RX_MAX_ENTRIES,
			.result_size = WC_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_WC_TCAM,
		},
		{			/* AFM */
			.max_slices  = SP_TCAM_RX_MAX_SLICES,
			.row_width   = SP_TCAM_RX_ROW_WIDTH,
			.num_rows    = SP_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = SP_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_SP_TCAM,
		},
		{			/* APPS */
			.max_slices  = SP_TCAM_RX_MAX_SLICES,
			.row_width   = SP_TCAM_RX_ROW_WIDTH,
			.num_rows    = SP_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = SP_TCAM_RX_NUM_ROWS - 1,
			.max_entries = SP_TCAM_RX_MAX_ENTRIES,
			.result_size = SP_TCAM_RX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_SP_TCAM,
		},
		{			/* AFM */
			.max_slices  = CT_RULE_TCAM_RX_MAX_SLICES,
			.row_width   = CT_RULE_TCAM_RX_ROW_WIDTH,
			.num_rows    = CT_RULE_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = CT_RULE_TCAM_RX_RESULT_SIZE,
		},
		{			/* APPS */
			.max_slices  = CT_RULE_TCAM_RX_MAX_SLICES,
			.row_width   = CT_RULE_TCAM_RX_ROW_WIDTH,
			.num_rows    = CT_RULE_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     =
				TCAM_SET_END_ROW(CT_RULE_TCAM_RX_NUM_ROWS),
			.max_entries = CT_RULE_TCAM_RX_MAX_ENTRIES,
			.result_size = CT_RULE_TCAM_RX_RESULT_SIZE,
		},
		{			/* AFM */
			.max_slices  = VEB_TCAM_RX_MAX_SLICES,
			.row_width   = VEB_TCAM_RX_ROW_WIDTH,
			.num_rows    = VEB_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = VEB_TCAM_RX_RESULT_SIZE,
		},
		{			/* APPS */
			.max_slices  = VEB_TCAM_RX_MAX_SLICES,
			.row_width   = VEB_TCAM_RX_ROW_WIDTH,
			.num_rows    = VEB_TCAM_RX_NUM_ROWS,
			.start_row   = 0,
			.end_row     =
				TCAM_SET_END_ROW(VEB_TCAM_RX_NUM_ROWS),
			.max_entries = VEB_TCAM_RX_MAX_ENTRIES,
			.result_size = VEB_TCAM_RX_RESULT_SIZE,
		},
	},
	{				/* TX */
		{			/* AFM */
			.max_slices  = L2_CTXT_TCAM_TX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_TX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = L2_CTXT_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_HIGH,
		},
		{			/* APPS */
			.max_slices  = L2_CTXT_TCAM_TX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_TX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = L2_CTXT_TCAM_TX_APP_HI_END,
			.max_entries = (L2_CTXT_TCAM_TX_MAX_ENTRIES / 2),
			.result_size = L2_CTXT_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_HIGH,
		},
		{			/* AFM */
			.max_slices  = L2_CTXT_TCAM_TX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_TX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = L2_CTXT_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_LOW,
		},
		{			/* APPS */
			.max_slices  = L2_CTXT_TCAM_TX_MAX_SLICES,
			.row_width   = L2_CTXT_TCAM_TX_ROW_WIDTH,
			.num_rows    = L2_CTXT_TCAM_TX_NUM_ROWS,
			.start_row   = L2_CTXT_TCAM_TX_APP_LO_START,
			.end_row     = L2_CTXT_TCAM_TX_NUM_ROWS - 1,
			.max_entries = (L2_CTXT_TCAM_TX_MAX_ENTRIES / 2),
			.result_size = L2_CTXT_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_L2_CTXT_TCAM_LOW,
		},
		{			/* AFM */
			.max_slices  = PROF_TCAM_TX_MAX_SLICES,
			.row_width   = PROF_TCAM_TX_ROW_WIDTH,
			.num_rows    = PROF_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = PROF_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_PROF_TCAM,
		},
		{			/* APPS */
			.max_slices  = PROF_TCAM_TX_MAX_SLICES,
			.row_width   = PROF_TCAM_TX_ROW_WIDTH,
			.num_rows    = PROF_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = PROF_TCAM_TX_NUM_ROWS - 1,
			.max_entries = PROF_TCAM_TX_MAX_ENTRIES,
			.result_size = PROF_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_PROF_TCAM,
		},
		{			/* AFM */
			.max_slices  = WC_TCAM_TX_MAX_SLICES,
			.row_width   = WC_TCAM_TX_ROW_WIDTH,
			.num_rows    = WC_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = WC_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_WC_TCAM,
		},
		{			/* APPS */
			.max_slices  = WC_TCAM_TX_MAX_SLICES,
			.row_width   = WC_TCAM_TX_ROW_WIDTH,
			.num_rows    = WC_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = WC_TCAM_TX_NUM_ROWS - 1,
			.max_entries = WC_TCAM_TX_MAX_ENTRIES,
			.result_size = WC_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_WC_TCAM,
		},
		{			/* AFM */
			.max_slices  = SP_TCAM_TX_MAX_SLICES,
			.row_width   = SP_TCAM_TX_ROW_WIDTH,
			.num_rows    = SP_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = SP_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_SP_TCAM,
		},
		{			/* APPS */
			.max_slices  = SP_TCAM_TX_MAX_SLICES,
			.row_width   = SP_TCAM_TX_ROW_WIDTH,
			.num_rows    = SP_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = SP_TCAM_TX_NUM_ROWS - 1,
			.max_entries = SP_TCAM_TX_MAX_ENTRIES,
			.result_size = SP_TCAM_TX_RESULT_SIZE,
			.hcapi_type  = CFA_RESOURCE_TYPE_P4_SP_TCAM,
		},
		{			/* AFM */
			.max_slices  = CT_RULE_TCAM_TX_MAX_SLICES,
			.row_width   = CT_RULE_TCAM_TX_ROW_WIDTH,
			.num_rows    = CT_RULE_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = CT_RULE_TCAM_RX_RESULT_SIZE,
		},
		{			/* APPS */
			.max_slices  = CT_RULE_TCAM_TX_MAX_SLICES,
			.row_width   = CT_RULE_TCAM_TX_ROW_WIDTH,
			.num_rows    = CT_RULE_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     =
				TCAM_SET_END_ROW(CT_RULE_TCAM_TX_NUM_ROWS),
			.max_entries = CT_RULE_TCAM_TX_MAX_ENTRIES,
			.result_size = CT_RULE_TCAM_RX_RESULT_SIZE,
		},
		{			/* AFM */
			.max_slices  = VEB_TCAM_TX_MAX_SLICES,
			.row_width   = VEB_TCAM_TX_ROW_WIDTH,
			.num_rows    = VEB_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = 0,
			.max_entries = 0,
			.result_size = VEB_TCAM_RX_RESULT_SIZE,
		},
		{			/* APPS */
			.max_slices  = VEB_TCAM_TX_MAX_SLICES,
			.row_width   = VEB_TCAM_TX_ROW_WIDTH,
			.num_rows    = VEB_TCAM_TX_NUM_ROWS,
			.start_row   = 0,
			.end_row     = VEB_TCAM_TX_NUM_ROWS - 1,
			.max_entries = VEB_TCAM_TX_MAX_ENTRIES,
			.result_size = VEB_TCAM_RX_RESULT_SIZE,
		},
	},
};

static int cfa_tcam_mgr_row_data_alloc(struct cfa_tcam_mgr_data *tcam_mgr_data);
static void cfa_tcam_mgr_row_data_free(struct cfa_tcam_mgr_data *tcam_mgr_data);

static void cfa_tcam_mgr_data_free(struct tf_session *tfs)
{
	struct cfa_tcam_mgr_data *tcam_mgr_data = tfs->tcam_mgr_handle;

	if (!tcam_mgr_data)
		return;

	vfree(tcam_mgr_data->table_rows);
	vfree(tcam_mgr_data->entry_data);
	vfree(tcam_mgr_data->logical_id_bmp);
	cfa_tcam_mgr_row_data_free(tcam_mgr_data);

	vfree(tcam_mgr_data);
	tfs->tcam_mgr_handle = NULL;
}

int cfa_tcam_mgr_init_p4(struct tf *tfp)
{
	struct cfa_tcam_mgr_table_rows_p4 *table_rows;
	struct cfa_tcam_mgr_entry_data *entry_data;
	struct cfa_tcam_mgr_data *tcam_mgr_data;
	int max_result_size = 0;
	struct tf_session *tfs;
	int max_row_width = 0;
	int dir, type;
	int rc;

	rc = tf_session_get_session_internal(tfp, &tfs);
	if (rc)
		return rc;

	tcam_mgr_data = vzalloc(sizeof(*tcam_mgr_data));
	if (!tcam_mgr_data)
		return -ENOMEM;
	tfs->tcam_mgr_handle = tcam_mgr_data;

	table_rows = vzalloc(sizeof(*table_rows));
	if (!table_rows) {
		rc = -ENOMEM;
		goto fail;
	}
	tcam_mgr_data->table_rows = table_rows;

	entry_data = vzalloc(sizeof(*entry_data) * TF_TCAM_MAX_ENTRIES);
	if (!entry_data) {
		rc = -ENOMEM;
		goto fail;
	}
	tcam_mgr_data->entry_data = entry_data;

	rc = cfa_tcam_mgr_row_data_alloc(tcam_mgr_data);
	if (rc)
		goto fail;

	memcpy(&tcam_mgr_data->cfa_tcam_mgr_tables,
	       &cfa_tcam_mgr_tables_p4,
	       sizeof(tcam_mgr_data->cfa_tcam_mgr_tables));

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_HIGH_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_HIGH_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_HIGH_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_HIGH_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_LOW_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_LOW_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_LOW_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_L2_CTXT_TCAM_LOW_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_L2_CTXT_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_PROF_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_PROF_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_PROF_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_PROF_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_PROF_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_PROF_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_PROF_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_PROF_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_WC_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_WC_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_WC_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_WC_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_WC_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_WC_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_WC_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_WC_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_SP_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_SP_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_SP_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_SP_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_SP_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_SP_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_SP_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_SP_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_CT_RULE_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_CT_RULE_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_CT_RULE_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_CT_RULE_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_CT_RULE_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_CT_RULE_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_CT_RULE_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_CT_RULE_TCAM_TX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_VEB_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_VEB_TCAM_RX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_RX]
		[CFA_TCAM_MGR_TBL_TYPE_VEB_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_VEB_TCAM_RX[0];

	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_VEB_TCAM_AFM].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_VEB_TCAM_TX[0];
	tcam_mgr_data->cfa_tcam_mgr_tables[TF_DIR_TX]
		[CFA_TCAM_MGR_TBL_TYPE_VEB_TCAM_APPS].tcam_rows =
		(struct cfa_tcam_mgr_table_rows_0 *)
		&table_rows->table_rows_VEB_TCAM_TX[0];
	for (dir = 0; dir < TF_DIR_MAX; dir++) {
		for (type = 0; type < CFA_TCAM_MGR_TBL_TYPE_MAX; type++) {
			if (tcam_mgr_data->cfa_tcam_mgr_tables[dir][type].row_width >
			    max_row_width)
				max_row_width =
				       tcam_mgr_data->cfa_tcam_mgr_tables[dir][type].row_width;
			if (tcam_mgr_data->cfa_tcam_mgr_tables[dir][type].result_size >
			    max_result_size)
				max_result_size =
				     tcam_mgr_data->cfa_tcam_mgr_tables[dir][type].result_size;
		}
	}

	if (max_row_width != MAX_ROW_WIDTH) {
		netdev_dbg(tfp->bp->dev,
			   "MAX_ROW_WIDTH:%d does not match actual val:%d\n",
			   MAX_ROW_WIDTH, max_row_width);
		rc = -EINVAL;
		goto fail;
	}
	if (max_result_size != MAX_RESULT_SIZE) {
		netdev_dbg(tfp->bp->dev,
			   "MAX_RESULT_SIZE:%d does not match actual val:%d\n",
			   MAX_RESULT_SIZE, max_result_size);
		rc = -EINVAL;
		goto fail;
	}

	return 0;

fail:
	cfa_tcam_mgr_data_free(tfs);
	return rc;
}

void cfa_tcam_mgr_uninit_p4(struct tf *tfp)
{
	struct tf_session *tfs;
	int rc;

	rc = tf_session_get_session_internal(tfp, &tfs);
	if (rc)
		return;

	cfa_tcam_mgr_data_free(tfs);
}

/* HW OP declarations begin here */
struct cfa_tcam_mgr_TCAM_row_data {
	int key_size;
	int result_size;
	u8 key[MAX_ROW_WIDTH];
	u8 mask[MAX_ROW_WIDTH];
	u8 result[MAX_RESULT_SIZE];
};

/* These macros are only needed to avoid exceeding 80 columns */
#define L2_CTXT_RX_MAX_ROWS \
	(L2_CTXT_TCAM_RX_MAX_SLICES * L2_CTXT_TCAM_RX_NUM_ROWS)
#define PROF_RX_MAX_ROWS    (PROF_TCAM_RX_MAX_SLICES * PROF_TCAM_RX_NUM_ROWS)
#define WC_RX_MAX_ROWS	    (WC_TCAM_RX_MAX_SLICES * WC_TCAM_RX_NUM_ROWS)
#define SP_RX_MAX_ROWS	    (SP_TCAM_RX_MAX_SLICES * SP_TCAM_RX_NUM_ROWS)
#define CT_RULE_RX_MAX_ROWS \
	(CT_RULE_TCAM_RX_MAX_SLICES * CT_RULE_TCAM_RX_NUM_ROWS)
#define VEB_RX_MAX_ROWS	    (VEB_TCAM_RX_MAX_SLICES * VEB_TCAM_RX_NUM_ROWS)

#define L2_CTXT_TX_MAX_ROWS \
	(L2_CTXT_TCAM_TX_MAX_SLICES * L2_CTXT_TCAM_TX_NUM_ROWS)
#define PROF_TX_MAX_ROWS    (PROF_TCAM_TX_MAX_SLICES * PROF_TCAM_TX_NUM_ROWS)
#define WC_TX_MAX_ROWS	    (WC_TCAM_TX_MAX_SLICES * WC_TCAM_TX_NUM_ROWS)
#define SP_TX_MAX_ROWS	    (SP_TCAM_TX_MAX_SLICES * SP_TCAM_TX_NUM_ROWS)
#define CT_RULE_TX_MAX_ROWS \
	(CT_RULE_TCAM_TX_MAX_SLICES * CT_RULE_TCAM_TX_NUM_ROWS)
#define VEB_TX_MAX_ROWS	    (VEB_TCAM_TX_MAX_SLICES * VEB_TCAM_TX_NUM_ROWS)

struct cfa_tcam_mgr_rx_row_data {
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_L2_CTXT_TCAM_RX_row_data[L2_CTXT_RX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_PROF_TCAM_RX_row_data[PROF_RX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_WC_TCAM_RX_row_data[WC_RX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_SP_TCAM_RX_row_data[SP_RX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_CT_RULE_TCAM_RX_row_data[CT_RULE_RX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_VEB_TCAM_RX_row_data[VEB_RX_MAX_ROWS];
};

struct cfa_tcam_mgr_tx_row_data {
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_L2_CTXT_TCAM_TX_row_data[L2_CTXT_TX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_PROF_TCAM_TX_row_data[PROF_TX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_WC_TCAM_TX_row_data[WC_TX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_SP_TCAM_TX_row_data[SP_TX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_CT_RULE_TCAM_TX_row_data[CT_RULE_TX_MAX_ROWS];
	struct cfa_tcam_mgr_TCAM_row_data
		cfa_tcam_mgr_VEB_TCAM_TX_row_data[VEB_TX_MAX_ROWS];
};

#define TF_TCAM_L2_CTX_HI	TF_TCAM_TBL_TYPE_L2_CTXT_TCAM_HIGH
#define TF_TCAM_L2_CTX_LO	TF_TCAM_TBL_TYPE_L2_CTXT_TCAM_LOW
#define TF_TCAM_PROF		TF_TCAM_TBL_TYPE_PROF_TCAM
#define	TF_TCAM_WC		TF_TCAM_TBL_TYPE_WC_TCAM
#define	TF_TCAM_SP		TF_TCAM_TBL_TYPE_SP_TCAM
#define	TF_TCAM_CT		TF_TCAM_TBL_TYPE_CT_RULE_TCAM
#define	TF_TCAM_VEB		TF_TCAM_TBL_TYPE_VEB_TCAM

static int cfa_tcam_mgr_row_data_alloc(struct cfa_tcam_mgr_data
				       *tcam_mgr_data)
{
	struct cfa_tcam_mgr_rx_row_data *rx_row_data;
	struct cfa_tcam_mgr_tx_row_data *tx_row_data;

	rx_row_data = vzalloc(sizeof(*rx_row_data));
	if (!rx_row_data)
		return -ENOMEM;

	tx_row_data = vzalloc(sizeof(*tx_row_data));
	if (!tx_row_data) {
		vfree(rx_row_data);
		return -ENOMEM;
	}

	tcam_mgr_data->rx_row_data = rx_row_data;
	tcam_mgr_data->tx_row_data = tx_row_data;

	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_L2_CTX_HI] =
		&rx_row_data->cfa_tcam_mgr_L2_CTXT_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_L2_CTX_LO] =
		&rx_row_data->cfa_tcam_mgr_L2_CTXT_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_PROF] =
		&rx_row_data->cfa_tcam_mgr_PROF_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_WC] =
		&rx_row_data->cfa_tcam_mgr_WC_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_SP] =
		&rx_row_data->cfa_tcam_mgr_SP_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_CT] =
		&rx_row_data->cfa_tcam_mgr_CT_RULE_TCAM_RX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_RX][TF_TCAM_VEB] =
		&rx_row_data->cfa_tcam_mgr_VEB_TCAM_RX_row_data[0];

	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_L2_CTX_HI] =
		&tx_row_data->cfa_tcam_mgr_L2_CTXT_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_L2_CTX_LO] =
		&tx_row_data->cfa_tcam_mgr_L2_CTXT_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_PROF] =
		&tx_row_data->cfa_tcam_mgr_PROF_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_WC] =
		&tx_row_data->cfa_tcam_mgr_WC_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_SP] =
		&tx_row_data->cfa_tcam_mgr_SP_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_CT] =
		&tx_row_data->cfa_tcam_mgr_CT_RULE_TCAM_TX_row_data[0];
	tcam_mgr_data->row_tables[TF_DIR_TX][TF_TCAM_VEB] =
		&tx_row_data->cfa_tcam_mgr_VEB_TCAM_TX_row_data[0];

	return 0;
}

static void cfa_tcam_mgr_row_data_free(struct cfa_tcam_mgr_data
				       *tcam_mgr_data)
{
	vfree(tcam_mgr_data->rx_row_data);
	vfree(tcam_mgr_data->tx_row_data);
}

static int cfa_tcam_mgr_hwop_set(struct cfa_tcam_mgr_data *tcam_mgr_data,
				 struct cfa_tcam_mgr_set_parms
				 *parms, int row, int slice, int max_slices)
{
	struct cfa_tcam_mgr_TCAM_row_data *this_table;
	struct cfa_tcam_mgr_TCAM_row_data *this_row;

	this_table = tcam_mgr_data->row_tables[parms->dir]
		[cfa_tcam_mgr_get_phys_table_type(parms->type)];
	this_row   = &this_table[row * max_slices + slice];
	this_row->key_size = parms->key_size;
	memcpy(&this_row->key, parms->key, parms->key_size);
	memcpy(&this_row->mask, parms->mask, parms->key_size);
	this_row->result_size = parms->result_size;
	if (parms->result)
		memcpy(&this_row->result, parms->result, parms->result_size);
	return 0;
};

static int cfa_tcam_mgr_hwop_get(struct cfa_tcam_mgr_data *tcam_mgr_data,
				 struct cfa_tcam_mgr_get_parms
				 *parms, int row, int slice, int max_slices)
{
	struct cfa_tcam_mgr_TCAM_row_data *this_table;
	struct cfa_tcam_mgr_TCAM_row_data *this_row;

	this_table = tcam_mgr_data->row_tables[parms->dir]
		[cfa_tcam_mgr_get_phys_table_type(parms->type)];
	this_row   = &this_table[row * max_slices + slice];
	parms->key_size = this_row->key_size;
	parms->result_size = this_row->result_size;
	if (parms->key)
		memcpy(parms->key, &this_row->key, parms->key_size);
	if (parms->mask)
		memcpy(parms->mask, &this_row->mask, parms->key_size);
	if (parms->result)
		memcpy(parms->result, &this_row->result, parms->result_size);
	return 0;
};

static int cfa_tcam_mgr_hwop_free(struct cfa_tcam_mgr_data *tcam_mgr_data,
				  struct cfa_tcam_mgr_free_parms
				  *parms, int row, int slice, int max_slices)
{
	struct cfa_tcam_mgr_TCAM_row_data *this_table;
	struct cfa_tcam_mgr_TCAM_row_data *this_row;

	this_table = tcam_mgr_data->row_tables[parms->dir]
		[cfa_tcam_mgr_get_phys_table_type(parms->type)];
	this_row   = &this_table[row * max_slices + slice];
	memset(&this_row->key, 0, sizeof(this_row->key));
	memset(&this_row->mask, 0, sizeof(this_row->mask));
	memset(&this_row->result, 0, sizeof(this_row->result));
	this_row->key_size = 0;
	this_row->result_size = 0;
	return 0;
};

int cfa_tcam_mgr_hwops_get_funcs_p4(struct cfa_tcam_mgr_hwops_funcs
				    *hwop_funcs)
{
	hwop_funcs->set	 = cfa_tcam_mgr_hwop_set;
	hwop_funcs->get	 = cfa_tcam_mgr_hwop_get;
	hwop_funcs->free = cfa_tcam_mgr_hwop_free;
	return 0;
}
