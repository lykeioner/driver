/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2018 Broadcom Limited
 * Copyright (c) 2018-2025 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/bitops.h>
#include <linux/ctype.h>
#include <linux/stringify.h>
#include <linux/ethtool.h>
#ifdef HAVE_ETHTOOL_TCP_DATA_SPLIT
#include <linux/ethtool_netlink.h>
#endif
#ifdef HAVE_LINKMODE
#include <linux/linkmode.h>
#endif
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/crc32.h>
#include <linux/firmware.h>
#if defined(ETHTOOL_GET_TS_INFO) && defined(HAVE_IEEE1588_SUPPORT)
#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>
#include <linux/timecounter.h>
#endif
#include <net/netlink.h>
#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#if defined(ETHTOOL_GET_DUMP_FLAG) && !defined(GET_ETHTOOL_OP_EXT)
#include "bnxt_coredump.h"
#endif
#include "bnxt_hwrm.h"
#include "bnxt_ulp.h"
#include "bnxt_xdp.h"
#include "bnxt_ptp.h"
#include "bnxt_ethtool.h"
#include "bnxt_sriov.h"
#include "bnxt_nvm_defs.h"	/* NVRAM content constant and structure defs */
#include "bnxt_fw_hdr.h"	/* Firmware hdr constant and structure defs */
#include "bnxt_mpc.h"
#include "bnxt_ktls.h"
#include "bnxt_quic.h"

#define FLASH_NVRAM_TIMEOUT	(bp->hwrm_cmd_max_timeout)
#define FLASH_PACKAGE_TIMEOUT	(bp->hwrm_cmd_max_timeout)
#define INSTALL_PACKAGE_TIMEOUT	(bp->hwrm_cmd_max_timeout)
#define FW_SYNC_TIMEOUT		(bp->hwrm_cmd_max_timeout)

#define BNXT_NVM_ERR_MSG(dev, extack, msg)			\
	do {							\
		if (extack)					\
			NL_SET_ERR_MSG_MOD(extack, msg);	\
		netdev_err(dev, "%s\n", msg);			\
	} while (0)

enum bnxt_priv_flags {
	BNXT_PRIV_FLAG_NUMA_DIRECT,
	BNXT_PRIV_FLAG_CORE_RESET_TX_TIMEOUT,
	BNXT_PRIV_FLAG_RSS_IPV6_FLOW_LABEL_EN,
};

static const char * const bnxt_priv_flags[] = {
	[BNXT_PRIV_FLAG_NUMA_DIRECT] = "numa_direct",
	[BNXT_PRIV_FLAG_CORE_RESET_TX_TIMEOUT] = "core_reset_tx_timeout",
	[BNXT_PRIV_FLAG_RSS_IPV6_FLOW_LABEL_EN] = "ipv6_flow_label_rss_en",
};

static u32 bnxt_get_msglevel(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	return bp->msg_enable;
}

static void bnxt_set_msglevel(struct net_device *dev, u32 value)
{
	struct bnxt *bp = netdev_priv(dev);

	bp->msg_enable = value;
}

static int bnxt_get_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_coal *hw_coal;
	u16 mult;

	memset(coal, 0, sizeof(*coal));

	coal->use_adaptive_rx_coalesce = bp->flags & BNXT_FLAG_DIM;

	hw_coal = &bp->rx_coal;
	mult = hw_coal->bufs_per_record;
	coal->rx_coalesce_usecs = hw_coal->coal_ticks;
	coal->rx_max_coalesced_frames = hw_coal->coal_bufs / mult;
	coal->rx_coalesce_usecs_irq = hw_coal->coal_ticks_irq;
	coal->rx_max_coalesced_frames_irq = hw_coal->coal_bufs_irq / mult;
#ifdef HAVE_CQE_ETHTOOL_COALESCE
	if (hw_coal->flags &
	    RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET)
		kernel_coal->use_cqe_mode_rx = true;
#endif

	hw_coal = &bp->tx_coal;
	mult = hw_coal->bufs_per_record;
	coal->tx_coalesce_usecs = hw_coal->coal_ticks;
	coal->tx_max_coalesced_frames = hw_coal->coal_bufs/ mult;
	coal->tx_coalesce_usecs_irq = hw_coal->coal_ticks_irq;
	coal->tx_max_coalesced_frames_irq = hw_coal->coal_bufs_irq / mult;
#ifdef HAVE_CQE_ETHTOOL_COALESCE
	if (hw_coal->flags &
	    RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET)
		kernel_coal->use_cqe_mode_tx = true;
#endif

	coal->stats_block_coalesce_usecs = bp->stats_coal_ticks;

	return 0;
}

#ifdef HAVE_ETHTOOL_GET_PER_QUEUE_COAL
static int bnxt_get_per_queue_coalesce(struct net_device *dev, u32 queue,
				       struct ethtool_coalesce *coal)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_cp_ring_info *cpr;
	struct bnxt_coal *hw_coal;
	u16 mult;

	if (queue >= bp->rx_nr_rings && bp->flags & BNXT_FLAG_SHARED_RINGS)
		return -EINVAL;

	if (queue >= bp->rx_nr_rings && queue >= bp->tx_nr_rings_per_tc)
		return -EINVAL;

	if (queue >= bp->rx_nr_rings)
		goto tx_coal;

	coal->use_adaptive_rx_coalesce = bp->flags & BNXT_FLAG_DIM;

	hw_coal = &bp->rx_coal;
	mult = hw_coal->bufs_per_record;

	if (!bp->bnapi) {
		coal->rx_coalesce_usecs = hw_coal->coal_ticks;
		coal->rx_max_coalesced_frames = hw_coal->coal_bufs / mult;
	} else {
		cpr = &bp->bnapi[queue]->cp_ring;
		coal->rx_coalesce_usecs = cpr->rx_ring_coal.coal_ticks;
		coal->rx_max_coalesced_frames = cpr->rx_ring_coal.coal_bufs / mult;
	}
	coal->rx_coalesce_usecs_irq = hw_coal->coal_ticks_irq;
	coal->rx_max_coalesced_frames_irq = hw_coal->coal_bufs_irq / mult;

tx_coal:
	if (queue >= bp->tx_nr_rings_per_tc)
		goto skip_tx_coal;

	hw_coal = &bp->tx_coal;
	mult = hw_coal->bufs_per_record;
	coal->tx_coalesce_usecs = hw_coal->coal_ticks;
	coal->tx_max_coalesced_frames = hw_coal->coal_bufs / mult;
	coal->tx_coalesce_usecs_irq = hw_coal->coal_ticks_irq;
	coal->tx_max_coalesced_frames_irq = hw_coal->coal_bufs_irq / mult;

skip_tx_coal:
	return 0;
}
#endif

static int bnxt_set_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	bool update_stats = false;
	struct bnxt_coal *hw_coal;
	int rc = 0;
	u16 mult;

	if (coal->use_adaptive_rx_coalesce) {
		bp->flags |= BNXT_FLAG_DIM;
	} else {
		if (bp->flags & BNXT_FLAG_DIM) {
			bp->flags &= ~(BNXT_FLAG_DIM);
			goto reset_coalesce;
		}
	}

#ifdef HAVE_CQE_ETHTOOL_COALESCE
	if ((kernel_coal->use_cqe_mode_rx || kernel_coal->use_cqe_mode_tx) &&
	    !(bp->coal_cap.cmpl_params &
	      RING_AGGINT_QCAPS_RESP_CMPL_PARAMS_TIMER_RESET))
		return -EOPNOTSUPP;
#endif

	hw_coal = &bp->rx_coal;
	mult = hw_coal->bufs_per_record;
	hw_coal->coal_ticks = coal->rx_coalesce_usecs;
	hw_coal->coal_bufs = coal->rx_max_coalesced_frames * mult;
	hw_coal->coal_ticks_irq = coal->rx_coalesce_usecs_irq;
	hw_coal->coal_bufs_irq = coal->rx_max_coalesced_frames_irq * mult;
#ifdef HAVE_CQE_ETHTOOL_COALESCE
	hw_coal->flags &=
		~RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET;
	if (kernel_coal->use_cqe_mode_rx)
		hw_coal->flags |=
			RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET;
#endif

	hw_coal = &bp->tx_coal;
	mult = hw_coal->bufs_per_record;
	hw_coal->coal_ticks = coal->tx_coalesce_usecs;
	hw_coal->coal_bufs = coal->tx_max_coalesced_frames * mult;
	hw_coal->coal_ticks_irq = coal->tx_coalesce_usecs_irq;
	hw_coal->coal_bufs_irq = coal->tx_max_coalesced_frames_irq * mult;
#ifdef HAVE_CQE_ETHTOOL_COALESCE
	hw_coal->flags &=
		~RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET;
	if (kernel_coal->use_cqe_mode_tx)
		hw_coal->flags |=
			RING_CMPL_RING_CFG_AGGINT_PARAMS_REQ_FLAGS_TIMER_RESET;
#endif

	if (bp->stats_coal_ticks != coal->stats_block_coalesce_usecs) {
		u32 stats_ticks = coal->stats_block_coalesce_usecs;

		/* Allow 0, which means disable. */
		if (stats_ticks)
			stats_ticks = clamp_t(u32, stats_ticks,
					      BNXT_MIN_STATS_COAL_TICKS,
					      BNXT_MAX_STATS_COAL_TICKS);
		stats_ticks = rounddown(stats_ticks, BNXT_MIN_STATS_COAL_TICKS);
		bp->stats_coal_ticks = stats_ticks;
		if (bp->stats_coal_ticks)
			bp->current_interval =
				bp->stats_coal_ticks * HZ / 1000000;
		else
			bp->current_interval = BNXT_TIMER_INTERVAL;
		update_stats = true;
	}

reset_coalesce:
	if (test_bit(BNXT_STATE_OPEN, &bp->state)) {
		if (update_stats) {
			bnxt_close_nic(bp, true, false);
			rc = bnxt_open_nic(bp, true, false);
		} else {
			rc = bnxt_hwrm_set_coal(bp);
		}
	}

	return rc;
}

static const char *const bnxt_ring_rx_stats_str[] = {
	"rx_ucast_packets",
	"rx_mcast_packets",
	"rx_bcast_packets",
	"rx_discards",
	"rx_errors",
	"rx_ucast_bytes",
	"rx_mcast_bytes",
	"rx_bcast_bytes",
};

static const char *const bnxt_ring_tx_stats_str[] = {
	"tx_ucast_packets",
	"tx_mcast_packets",
	"tx_bcast_packets",
	"tx_errors",
	"tx_discards",
	"tx_ucast_bytes",
	"tx_mcast_bytes",
	"tx_bcast_bytes",
};

static const char *bnxt_ring_tpa_stats_str[] = {
	"tpa_packets",
	"tpa_bytes",
	"tpa_events",
	"tpa_aborts",
};

static const char *bnxt_ring_tpa2_stats_str[] = {
	"rx_tpa_eligible_pkt",
	"rx_tpa_eligible_bytes",
	"rx_tpa_pkt",
	"rx_tpa_bytes",
	"rx_tpa_errors",
	"rx_tpa_events",
};

static const char *const bnxt_rx_sw_stats_str[] = {
	"rx_hds_pkt",
	"rx_tpa_hds_pkt",
	"rx_l4_csum_errors",
	"rx_resets",
	"rx_buf_errors",
};

static const char *const bnxt_tx_sw_push_stats_str[] = {
	"tx_push_xmit",
	"tx_push_cmpl",
};

static const char *const bnxt_cmn_sw_stats_str[] = {
	"missed_irqs",
};

static const char *const bnxt_txtime_sw_stats_str[] = {
	"so_txtime_xmit",
	"so_txtime_cmpl_errors",
};

#define BNXT_RX_STATS_ENTRY(counter)	\
	{ BNXT_RX_STATS_OFFSET(counter), __stringify(counter) }

#define BNXT_TX_STATS_ENTRY(counter)	\
	{ BNXT_TX_STATS_OFFSET(counter), __stringify(counter) }

#define BNXT_RX_STATS_EXT_ENTRY(counter)	\
	{ BNXT_RX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNXT_TX_STATS_EXT_ENTRY(counter)	\
	{ BNXT_TX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNXT_RX_STATS_EXT_PFC_ENTRY(n)				\
	BNXT_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_duration_us),	\
	BNXT_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_transitions)

#define BNXT_TX_STATS_EXT_PFC_ENTRY(n)				\
	BNXT_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_duration_us),	\
	BNXT_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_transitions)

#define BNXT_RX_STATS_EXT_PFC_ENTRIES				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(0),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(1),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(2),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(3),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(4),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(5),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(6),				\
	BNXT_RX_STATS_EXT_PFC_ENTRY(7)

#define BNXT_TX_STATS_EXT_PFC_ENTRIES				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(0),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(1),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(2),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(3),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(4),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(5),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(6),				\
	BNXT_TX_STATS_EXT_PFC_ENTRY(7)

/* If BNXT_RX_STATS_EXT_ENTRY changes, bnxt_port_stats_cos_strcpy()
 * should be modified accordingly
 */
#define BNXT_RX_STATS_EXT_COS_ENTRY(n)				\
	BNXT_RX_STATS_EXT_ENTRY(rx_bytes_cos##n),		\
	BNXT_RX_STATS_EXT_ENTRY(rx_packets_cos##n)

/* If BNXT_TX_STATS_EXT_ENTRY changes, bnxt_port_stats_cos_strcpy()
 * should be modified accordingly
 */
#define BNXT_TX_STATS_EXT_COS_ENTRY(n)				\
	BNXT_TX_STATS_EXT_ENTRY(tx_bytes_cos##n),		\
	BNXT_TX_STATS_EXT_ENTRY(tx_packets_cos##n)

#define BNXT_RX_STATS_EXT_COS_ENTRIES				\
	BNXT_RX_STATS_EXT_COS_ENTRY(0),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(1),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(2),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(3),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(4),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(5),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(6),				\
	BNXT_RX_STATS_EXT_COS_ENTRY(7)				\

#define BNXT_TX_STATS_EXT_COS_ENTRIES				\
	BNXT_TX_STATS_EXT_COS_ENTRY(0),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(1),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(2),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(3),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(4),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(5),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(6),				\
	BNXT_TX_STATS_EXT_COS_ENTRY(7)				\

#define BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(n)			\
	BNXT_RX_STATS_EXT_ENTRY(rx_discard_bytes_cos##n),	\
	BNXT_RX_STATS_EXT_ENTRY(rx_discard_packets_cos##n)

#define BNXT_RX_STATS_EXT_DISCARD_COS_ENTRIES				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(0),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(1),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(2),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(3),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(4),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(5),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(6),				\
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRY(7)

#define BNXT_RX_STATS_PRI_ENTRY(counter, n)		\
	{ BNXT_RX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNXT_TX_STATS_PRI_ENTRY(counter, n)		\
	{ BNXT_TX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNXT_RX_STATS_PRI_ENTRIES(counter)		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 0),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 1),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 2),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 3),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 4),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 5),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 6),		\
	BNXT_RX_STATS_PRI_ENTRY(counter, 7)

#define BNXT_TX_STATS_PRI_ENTRIES(counter)		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 0),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 1),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 2),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 3),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 4),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 5),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 6),		\
	BNXT_TX_STATS_PRI_ENTRY(counter, 7)

static const char *const bnxt_ecn_port_stats_arr[] = {
	"ecnmark_pkts_cos0",
	"ecnmark_pkts_cos1",
	"ecnmark_pkts_cos2",
	"ecnmark_pkts_cos3",
	"ecnmark_pkts_cos4",
	"ecnmark_pkts_cos5",
	"ecnmark_pkts_cos6",
	"ecnmark_pkts_cos7",
};

enum {
	RX_TOTAL_DISCARDS,
	TX_TOTAL_DISCARDS,
	RX_OOM_DISCARDS,
	RX_NETPOLL_DISCARDS,
};

static const char *const bnxt_ring_err_stats_arr[] = {
	"rx_total_l4_csum_errors",
	"rx_total_resets",
	"rx_total_buf_errors",
	"rx_total_oom_discards",
	"rx_total_netpoll_discards",
	"rx_total_ring_discards",
	"tx_total_resets",
	"tx_total_ring_discards",
	"total_missed_irqs",
};

static const char *const bnxt_ktls_stats[] = {
	"ktls_tx_add",
	"ktls_tx_del",
	"ktls_tx_hw_pkt",
	"ktls_tx_sw_pkt",
	"ktls_tx_tls_ooo",
	"ktls_tx_retrans_pkt",
	"ktls_tx_replay",
	"ktls_rx_add",
	"ktls_rx_del",
	"ktls_rx_hw_pkt",
	"ktls_rx_sw_pkt",
	"ktls_rx_resync_req",
	"ktls_rx_resync_ack",
	"ktls_rx_resync_discard",
	"ktls_rx_resync_nak",
};

static const char *const bnxt_quic_stats[] = {
	"quic_tx_add",
	"quic_tx_del",
	"quic_tx_hw_pkt",
	"quic_tx_sw_pkt",
	"quic_rx_add",
	"quic_rx_del",
	"quic_rx_hw_pkt",
	"quic_rx_sw_pkt",
	"quic_rx_payload_decrypted",
	"quic_rx_hdr_decrypted",
	"quic_rx_key_phase_mismatch",
	"quic_rx_runt",
	"quic_rx_short_hdr",
	"quic_rx_long_hdr",
};

static const char *const bnxt_generic_stats[] = {
	"pcie_statistics_tx_tlp",
	"pcie_statistics_rx_tlp",
	"pcie_credit_fc_hdr_posted",
	"pcie_credit_fc_hdr_nonposted",
	"pcie_credit_fc_hdr_cmpl",
	"pcie_credit_fc_data_posted",
	"pcie_credit_fc_data_nonposted",
	"pcie_credit_fc_data_cmpl",
	"pcie_credit_fc_tgt_nonposted",
	"pcie_credit_fc_tgt_data_posted",
	"pcie_credit_fc_tgt_hdr_posted",
	"pcie_credit_fc_cmpl_hdr_posted",
	"pcie_credit_fc_cmpl_data_posted",
	"pcie_cmpl_longest",
	"pcie_cmpl_shortest",
	"cache_miss_count_cfcq",
	"cache_miss_count_cfcs",
	"cache_miss_count_cfcc",
	"cache_miss_count_cfcm",
	"hw_db_recov_dbs_dropped",
	"hw_db_recov_drops_serviced",
	"hw_db_recov_dbs_recovered",
	"hw_db_recov_oo_drop_count",
};

static const char *const bnxt_xsk_stats[] = {
	"xsk_rx_success",
	"xsk_rx_redirect_fail",
	"xsk_rx_alloc_fail",
	"xsk_rx_no_room",
	"xsk_tx_ring_full",
	"xsk_wakeup",
	"xsk_tx_completed",
	"xsk_tx_sent_pkts",
};

static const char *const bnxt_lpbk_stats[] = {
	"lpbk_ucast_frames",
	"lpbk_mcast_frames",
	"lpbk_bcast_frames",
	"lpbk_ucast_bytes",
	"lpbk_mcast_bytes",
	"lpbk_bcast_bytes",
	"lpbk_tx_discards",
	"lpbk_tx_errors",
	"lpbk_rx_discards",
	"lpbk_rx_errors",
};

struct stats_entry {
	long offset;
	char string[ETH_GSTRING_LEN];
};

#define NUM_RING_RX_SW_STATS		ARRAY_SIZE(bnxt_rx_sw_stats_str)
#define NUM_RING_TX_PUSH_SW_STATS	ARRAY_SIZE(bnxt_tx_sw_push_stats_str)
#define NUM_RING_CMN_SW_STATS		ARRAY_SIZE(bnxt_cmn_sw_stats_str)
#define NUM_RING_RX_HW_STATS		ARRAY_SIZE(bnxt_ring_rx_stats_str)
#define NUM_RING_TX_HW_STATS		ARRAY_SIZE(bnxt_ring_tx_stats_str)
#define NUM_RING_TXTIME_SW_STATS	ARRAY_SIZE(bnxt_txtime_sw_stats_str)

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnxt_port_stats_arr[] = {
	BNXT_RX_STATS_ENTRY(rx_64b_frames),
	BNXT_RX_STATS_ENTRY(rx_65b_127b_frames),
	BNXT_RX_STATS_ENTRY(rx_128b_255b_frames),
	BNXT_RX_STATS_ENTRY(rx_256b_511b_frames),
	BNXT_RX_STATS_ENTRY(rx_512b_1023b_frames),
	BNXT_RX_STATS_ENTRY(rx_1024b_1518b_frames),
	BNXT_RX_STATS_ENTRY(rx_good_vlan_frames),
	BNXT_RX_STATS_ENTRY(rx_1519b_2047b_frames),
	BNXT_RX_STATS_ENTRY(rx_2048b_4095b_frames),
	BNXT_RX_STATS_ENTRY(rx_4096b_9216b_frames),
	BNXT_RX_STATS_ENTRY(rx_9217b_16383b_frames),
	BNXT_RX_STATS_ENTRY(rx_total_frames),
	BNXT_RX_STATS_ENTRY(rx_ucast_frames),
	BNXT_RX_STATS_ENTRY(rx_mcast_frames),
	BNXT_RX_STATS_ENTRY(rx_bcast_frames),
	BNXT_RX_STATS_ENTRY(rx_fcs_err_frames),
	BNXT_RX_STATS_ENTRY(rx_ctrl_frames),
	BNXT_RX_STATS_ENTRY(rx_pause_frames),
	BNXT_RX_STATS_ENTRY(rx_pfc_frames),
	BNXT_RX_STATS_ENTRY(rx_align_err_frames),
	BNXT_RX_STATS_ENTRY(rx_ovrsz_frames),
	BNXT_RX_STATS_ENTRY(rx_jbr_frames),
	BNXT_RX_STATS_ENTRY(rx_mtu_err_frames),
	BNXT_RX_STATS_ENTRY(rx_tagged_frames),
	BNXT_RX_STATS_ENTRY(rx_double_tagged_frames),
	BNXT_RX_STATS_ENTRY(rx_good_frames),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri0),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri1),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri2),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri3),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri4),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri5),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri6),
	BNXT_RX_STATS_ENTRY(rx_pfc_ena_frames_pri7),
	BNXT_RX_STATS_ENTRY(rx_undrsz_frames),
	BNXT_RX_STATS_ENTRY(rx_eee_lpi_events),
	BNXT_RX_STATS_ENTRY(rx_eee_lpi_duration),
	BNXT_RX_STATS_ENTRY(rx_bytes),
	BNXT_RX_STATS_ENTRY(rx_runt_bytes),
	BNXT_RX_STATS_ENTRY(rx_runt_frames),
	BNXT_RX_STATS_ENTRY(rx_stat_discard),
	BNXT_RX_STATS_ENTRY(rx_stat_err),

	BNXT_TX_STATS_ENTRY(tx_64b_frames),
	BNXT_TX_STATS_ENTRY(tx_65b_127b_frames),
	BNXT_TX_STATS_ENTRY(tx_128b_255b_frames),
	BNXT_TX_STATS_ENTRY(tx_256b_511b_frames),
	BNXT_TX_STATS_ENTRY(tx_512b_1023b_frames),
	BNXT_TX_STATS_ENTRY(tx_1024b_1518b_frames),
	BNXT_TX_STATS_ENTRY(tx_good_vlan_frames),
	BNXT_TX_STATS_ENTRY(tx_1519b_2047b_frames),
	BNXT_TX_STATS_ENTRY(tx_2048b_4095b_frames),
	BNXT_TX_STATS_ENTRY(tx_4096b_9216b_frames),
	BNXT_TX_STATS_ENTRY(tx_9217b_16383b_frames),
	BNXT_TX_STATS_ENTRY(tx_good_frames),
	BNXT_TX_STATS_ENTRY(tx_total_frames),
	BNXT_TX_STATS_ENTRY(tx_ucast_frames),
	BNXT_TX_STATS_ENTRY(tx_mcast_frames),
	BNXT_TX_STATS_ENTRY(tx_bcast_frames),
	BNXT_TX_STATS_ENTRY(tx_pause_frames),
	BNXT_TX_STATS_ENTRY(tx_pfc_frames),
	BNXT_TX_STATS_ENTRY(tx_jabber_frames),
	BNXT_TX_STATS_ENTRY(tx_fcs_err_frames),
	BNXT_TX_STATS_ENTRY(tx_err),
	BNXT_TX_STATS_ENTRY(tx_fifo_underruns),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri0),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri1),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri2),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri3),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri4),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri5),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri6),
	BNXT_TX_STATS_ENTRY(tx_pfc_ena_frames_pri7),
	BNXT_TX_STATS_ENTRY(tx_eee_lpi_events),
	BNXT_TX_STATS_ENTRY(tx_eee_lpi_duration),
	BNXT_TX_STATS_ENTRY(tx_total_collisions),
	BNXT_TX_STATS_ENTRY(tx_bytes),
	BNXT_TX_STATS_ENTRY(tx_xthol_frames),
	BNXT_TX_STATS_ENTRY(tx_stat_discard),
	BNXT_TX_STATS_ENTRY(tx_stat_error),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnxt_port_stats_ext_arr[] = {
	BNXT_RX_STATS_EXT_ENTRY(link_down_events),
	BNXT_RX_STATS_EXT_ENTRY(continuous_pause_events),
	BNXT_RX_STATS_EXT_ENTRY(resume_pause_events),
	BNXT_RX_STATS_EXT_ENTRY(continuous_roce_pause_events),
	BNXT_RX_STATS_EXT_ENTRY(resume_roce_pause_events),
	BNXT_RX_STATS_EXT_COS_ENTRIES,
	BNXT_RX_STATS_EXT_PFC_ENTRIES,
	BNXT_RX_STATS_EXT_ENTRY(rx_bits),
	BNXT_RX_STATS_EXT_ENTRY(rx_buffer_passed_threshold),
	BNXT_RX_STATS_EXT_ENTRY(rx_pcs_symbol_err),
	BNXT_RX_STATS_EXT_ENTRY(rx_corrected_bits),
	BNXT_RX_STATS_EXT_DISCARD_COS_ENTRIES,
	BNXT_RX_STATS_EXT_ENTRY(rx_fec_corrected_blocks),
	BNXT_RX_STATS_EXT_ENTRY(rx_fec_uncorrectable_blocks),
	BNXT_RX_STATS_EXT_ENTRY(rx_filter_miss),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnxt_tx_port_stats_ext_arr[] = {
	BNXT_TX_STATS_EXT_COS_ENTRIES,
	BNXT_TX_STATS_EXT_PFC_ENTRIES,
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnxt_rx_bytes_pri_arr[] = {
	BNXT_RX_STATS_PRI_ENTRIES(rx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnxt_rx_pkts_pri_arr[] = {
	BNXT_RX_STATS_PRI_ENTRIES(rx_packets),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnxt_tx_bytes_pri_arr[] = {
	BNXT_TX_STATS_PRI_ENTRIES(tx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnxt_tx_pkts_pri_arr[] = {
	BNXT_TX_STATS_PRI_ENTRIES(tx_packets),
};

#define BNXT_NUM_ECN_PORT_STATS	ARRAY_SIZE(bnxt_ecn_port_stats_arr)
#define BNXT_NUM_RING_ERR_STATS	ARRAY_SIZE(bnxt_ring_err_stats_arr)
#define BNXT_NUM_KTLS_STATS	ARRAY_SIZE(bnxt_ktls_stats)
#define BNXT_NUM_QUIC_STATS	ARRAY_SIZE(bnxt_quic_stats)
#define BNXT_NUM_PORT_STATS ARRAY_SIZE(bnxt_port_stats_arr)
#define BNXT_NUM_STATS_PRI			\
	(ARRAY_SIZE(bnxt_rx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnxt_rx_pkts_pri_arr) +	\
	 ARRAY_SIZE(bnxt_tx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnxt_tx_pkts_pri_arr))
#define BNXT_NUM_GENERIC_STATS	ARRAY_SIZE(bnxt_generic_stats)
#define BNXT_NUM_XSK_STATS	ARRAY_SIZE(bnxt_xsk_stats)
#define BNXT_NUM_LPBK_STATS	ARRAY_SIZE(bnxt_lpbk_stats)

static int bnxt_get_num_tpa_ring_stats(struct bnxt *bp)
{
	if (BNXT_SUPPORTS_TPA(bp)) {
		if (bp->max_tpa_v2) {
			if (BNXT_CHIP_P5(bp))
				return BNXT_NUM_TPA_RING_STATS_P5;
			return BNXT_NUM_TPA_RING_STATS_P7;
		}
		return BNXT_NUM_TPA_RING_STATS;
	}
	return 0;
}

static int bnxt_get_num_tx_sw_push_stats(struct bnxt *bp)
{
	if (bp->tx_push_mode == BNXT_PUSH_MODE_NONE)
		return 0;
	return NUM_RING_TX_PUSH_SW_STATS;
}

static int bnxt_get_num_txtime_sw_stats(struct bnxt *bp)
{
	if (BNXT_SUPPORTS_ETF(bp))
		return NUM_RING_TXTIME_SW_STATS;
	return 0;
}

static int bnxt_get_num_ring_stats(struct bnxt *bp)
{
	int rx, tx, cmn, xsk;

	rx = NUM_RING_RX_HW_STATS + NUM_RING_RX_SW_STATS +
	     bnxt_get_num_tpa_ring_stats(bp);
	tx = NUM_RING_TX_HW_STATS + bnxt_get_num_tx_sw_push_stats(bp) +
		bnxt_get_num_txtime_sw_stats(bp);
	cmn = NUM_RING_CMN_SW_STATS;
	xsk = BNXT_NUM_XSK_STATS;

	return rx * bp->rx_nr_rings +
	       tx * (bp->tx_nr_rings_xdp + bp->tx_nr_rings_per_tc) +
	       cmn * bp->cp_nr_rings +
	       xsk * bp->cp_nr_rings;
}

static int bnxt_skip_port_stats_ext_count(struct bnxt *bp)
{
	int skip = 0;

	if (!BNXT_CHIP_P5_PLUS(bp))
		return 0;

	if (bp->fw_rx_stats_ext_size >
	    BNXT_RX_STATS_EXT_OFFSET(pfc_pri0_rx_duration_us))
		skip = BNXT_NUM_RX_PFC_DURATION_STATS;

	if (bp->fw_tx_stats_ext_size >
	    BNXT_TX_STATS_EXT_OFFSET(pfc_pri0_tx_duration_us))
		skip += BNXT_NUM_TX_PFC_DURATION_STATS;

	return skip;
}

#define BNXT_DURATION_OFFSET(base, offset) ((offset) >= (base) &&	     \
			(offset) < ((base) + BNXT_NUM_PFC_DURATION_STATS) && \
			((offset) - (base)) % 2 == 0)

static bool bnxt_skip_port_stats_ext(struct bnxt *bp, u32 idx)
{
	long base = BNXT_RX_STATS_EXT_OFFSET(pfc_pri0_rx_duration_us);
	long offset = bnxt_port_stats_ext_arr[idx].offset;

	if (BNXT_CHIP_P5_PLUS(bp))
		return BNXT_DURATION_OFFSET(base, offset);

	return false;
}

static bool bnxt_skip_tx_port_stats_ext(struct bnxt *bp, u32 idx)
{
	long base = BNXT_TX_STATS_EXT_OFFSET(pfc_pri0_tx_duration_us);
	long offset = bnxt_tx_port_stats_ext_arr[idx].offset;

	if (BNXT_CHIP_P5_PLUS(bp))
		return BNXT_DURATION_OFFSET(base, offset);

	return false;
}

static int bnxt_get_num_stats(struct bnxt *bp)
{
	int num_stats = bnxt_get_num_ring_stats(bp);
	int len;

	num_stats += BNXT_NUM_RING_ERR_STATS;

	if (bp->ktls_info)
		num_stats += BNXT_NUM_KTLS_STATS;
	if (bp->quic_info)
		num_stats += BNXT_NUM_QUIC_STATS;

	if (bp->flags & BNXT_FLAG_PORT_STATS)
		num_stats += BNXT_NUM_PORT_STATS;

	if (bp->flags & BNXT_FLAG_PORT_STATS_EXT) {
		len = min_t(u32, bp->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnxt_port_stats_ext_arr));
		num_stats += len;
		len = min_t(u32, bp->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnxt_tx_port_stats_ext_arr));
		num_stats += len;
		if (bp->pri2cos_valid)
			num_stats += BNXT_NUM_STATS_PRI;
		num_stats -= bnxt_skip_port_stats_ext_count(bp);
	}
	if (bp->flags & BNXT_FLAG_ECN_STATS)
		num_stats += BNXT_NUM_ECN_PORT_STATS;

	if (bp->fw_cap & BNXT_FW_CAP_GENERIC_STATS) {
		if (bp->generic_stats.hw_stats)
			num_stats += BNXT_NUM_GENERIC_STATS;
	}

	if (bp->fw_cap & BNXT_FW_CAP_LPBK_STATS) {
		if (bp->lpbk_stats.hw_stats)
			num_stats += BNXT_NUM_LPBK_STATS;
	}
	return num_stats;
}

static bool bnxt_core_reset_avail(struct bnxt *bp)
{
	if (!BNXT_PF(bp) || pci_vfs_assigned(bp->pdev) ||
	    bp->hwrm_spec_code < 0x10803)
		return false;
	else
		return true;
}

static int bnxt_get_sset_count(struct net_device *dev, int sset)
{
	struct bnxt *bp = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return bnxt_get_num_stats(bp);
	case ETH_SS_TEST:
		if (!bp->num_tests)
			return -EOPNOTSUPP;
		return bp->num_tests;
	case ETH_SS_PRIV_FLAGS:
		return ARRAY_SIZE(bnxt_priv_flags);
	default:
		return -EOPNOTSUPP;
	}
}

static bool is_rx_ring(struct bnxt *bp, int ring_num)
{
	return ring_num < bp->rx_nr_rings;
}

static bool is_tx_ring(struct bnxt *bp, int ring_num)
{
	int tx_base = 0;

	if (!(bp->flags & BNXT_FLAG_SHARED_RINGS))
		tx_base = bp->rx_nr_rings;

	if (ring_num >= tx_base && ring_num < (tx_base + bp->tx_nr_rings))
		return true;
	return false;
}

static void bnxt_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *buf)
{
	u32 i, j = 0;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_total_ring_err_stats ring_err_stats = {0};
	int buf_size = bnxt_get_num_stats(bp) * sizeof(u64);
	u64 *curr, *prev;
	u32 tpa_stats;

	memset(buf, 0, buf_size);

	if (!bp->bnapi || !netif_running(bp->dev)) {
		j += bnxt_get_num_ring_stats(bp);
		goto skip_ring_stats;
	}

	tpa_stats = bnxt_get_num_tpa_ring_stats(bp);
	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_napi *bnapi = bp->bnapi[i];
		struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
		u64 *sw_stats = cpr->stats.sw_stats;
		u64 *sw;
		int k;

		if (is_rx_ring(bp, i)) {
			for (k = 0; k < NUM_RING_RX_HW_STATS; j++, k++)
				buf[j] = sw_stats[k];
		}
		if (is_tx_ring(bp, i)) {
			k = NUM_RING_RX_HW_STATS;
			for (; k < NUM_RING_RX_HW_STATS + NUM_RING_TX_HW_STATS;
			       j++, k++)
				buf[j] = sw_stats[k];
		}
		if (!tpa_stats || !is_rx_ring(bp, i))
			goto skip_tpa_ring_stats;

		k = NUM_RING_RX_HW_STATS + NUM_RING_TX_HW_STATS;
		for (; k < NUM_RING_RX_HW_STATS + NUM_RING_TX_HW_STATS +
			   tpa_stats; j++, k++)
			buf[j] = sw_stats[k];

skip_tpa_ring_stats:
		sw = (u64 *)&cpr->sw_stats->rx;
		if (is_rx_ring(bp, i)) {
			for (k = 0; k < NUM_RING_RX_SW_STATS; j++, k++)
				buf[j] = sw[k];
		}

		sw = (u64 *)&cpr->sw_stats->tx;
		if (is_tx_ring(bp, i)) {
			for (k = 0; k < bnxt_get_num_tx_sw_push_stats(bp); j++, k++)
				buf[j] = sw[k];

			sw = (u64 *)&cpr->sw_stats->txtime;
			if (is_tx_ring(bp, i)) {
				for (k = 0; k < bnxt_get_num_txtime_sw_stats(bp); j++, k++)
					buf[j] = sw[k];
			}
		}

		sw = (u64 *)&cpr->sw_stats->cmn;
		for (k = 0; k < NUM_RING_CMN_SW_STATS; j++, k++)
			buf[j] = sw[k];

		/* xsk stats */
		sw = (u64 *)&cpr->sw_stats->xsk_stats;
		for (k = 0; k < BNXT_NUM_XSK_STATS; j++, k++)
			buf[j] = sw[k];
	}

	bnxt_get_ring_err_stats(bp, &ring_err_stats);

skip_ring_stats:
	curr = &ring_err_stats.rx_total_l4_csum_errors;
	prev = &bp->ring_err_stats_prev.rx_total_l4_csum_errors;
	for (i = 0; i < BNXT_NUM_RING_ERR_STATS; i++, j++, curr++, prev++)
		buf[j] = *curr + *prev;

	if (bp->ktls_info) {
		struct bnxt_tls_info *ktls = bp->ktls_info;

		for (i = 0; i < BNXT_NUM_KTLS_STATS; i++, j++)
			buf[j] = atomic64_read(&ktls->counters[i]);
	}
	if (bp->quic_info) {
		struct bnxt_tls_info *quic = bp->quic_info;

		for (i = 0; i < BNXT_NUM_QUIC_STATS; i++, j++)
			buf[j] = atomic64_read(&quic->counters[i]);
	}
	if (bp->flags & BNXT_FLAG_PORT_STATS) {
		u64 *port_stats = bp->port_stats.sw_stats;

		for (i = 0; i < BNXT_NUM_PORT_STATS; i++, j++)
			buf[j] = *(port_stats + bnxt_port_stats_arr[i].offset);
	}

	if (bp->flags & BNXT_FLAG_PORT_STATS_EXT) {
		u64 *rx_port_stats_ext = bp->rx_port_stats_ext.sw_stats;
		u64 *tx_port_stats_ext = bp->tx_port_stats_ext.sw_stats;
		u32 len;

		len = min_t(u32, bp->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnxt_port_stats_ext_arr));
		for (i = 0; i < len; i++) {
			if (bnxt_skip_port_stats_ext(bp, i))
				continue;

			buf[j++] = *(rx_port_stats_ext +
				     bnxt_port_stats_ext_arr[i].offset);
		}
		len = min_t(u32, bp->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnxt_tx_port_stats_ext_arr));
		for (i = 0; i < len; i++) {
			if (bnxt_skip_tx_port_stats_ext(bp, i))
				continue;

			buf[j++] = *(tx_port_stats_ext +
				     bnxt_tx_port_stats_ext_arr[i].offset);
		}
		if (bp->pri2cos_valid) {
			for (i = 0; i < 8; i++, j++) {
				long n = bnxt_rx_bytes_pri_arr[i].base_off +
					 bp->rx_pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnxt_rx_pkts_pri_arr[i].base_off +
					 bp->rx_pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnxt_tx_bytes_pri_arr[i].base_off +
					 bp->tx_pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnxt_tx_pkts_pri_arr[i].base_off +
					 bp->tx_pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
		}
	}
	if (bp->flags & BNXT_FLAG_ECN_STATS) {
		u64 *port_stats = bp->ecn_marked_stats.sw_stats;

		for (i = 0; i < BNXT_NUM_ECN_PORT_STATS; i++, j++)
			buf[j] = *(port_stats++);
	}

	if (bp->fw_cap & BNXT_FW_CAP_GENERIC_STATS) {
		u64 *hw = bp->generic_stats.hw_stats;

		if (!hw)
			goto skip_gen_stats;

		for (i = 0; i < BNXT_NUM_GENERIC_STATS; i++, j++)
			buf[j] = le64_to_cpu(hw[i]);
	}

skip_gen_stats:
	if (bp->fw_cap & BNXT_FW_CAP_LPBK_STATS) {
		u64 *hw = bp->lpbk_stats.hw_stats;

		if (!hw)
			return;

		for (i = 0; i < BNXT_NUM_LPBK_STATS; i++, j++)
			buf[j] = le64_to_cpu(hw[i]);
	}
}

static void bnxt_port_stats_cos_strcpy(char *cosq_names, int base, char *out, const char *in)
{
	int len = 0;

	while ((*out++ = *in++))
		len++;
	if (!strncmp(out - 6, "_cos", 4)) {
		int id = *(out - 2) - '0';

		if (cosq_names && cosq_names[base + (BNXT_MAX_COSQ_NAME_LEN * id)]) {
			strncpy(out - 2, &cosq_names[base + (BNXT_MAX_COSQ_NAME_LEN * id)],
				ETH_GSTRING_LEN - len + 1);
			out[ETH_GSTRING_LEN - len - 2] = '\0';
		}
	}
}

static void bnxt_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	struct bnxt *bp = netdev_priv(dev);
	static const char **str;
	u32 i, j, num_str;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < bp->cp_nr_rings; i++) {
			if (is_rx_ring(bp, i)) {
				num_str = NUM_RING_RX_HW_STATS;
				for (j = 0; j < num_str; j++) {
					sprintf(buf, "[%d]: %s", i,
						bnxt_ring_rx_stats_str[j]);
					buf += ETH_GSTRING_LEN;
				}
			}
			if (is_tx_ring(bp, i)) {
				num_str = NUM_RING_TX_HW_STATS;
				for (j = 0; j < num_str; j++) {
					sprintf(buf, "[%d]: %s", i,
						bnxt_ring_tx_stats_str[j]);
					buf += ETH_GSTRING_LEN;
				}
			}
			num_str = bnxt_get_num_tpa_ring_stats(bp);
			if (!num_str || !is_rx_ring(bp, i))
				goto skip_tpa_stats;

			if (bp->max_tpa_v2)
				str = bnxt_ring_tpa2_stats_str;
			else
				str = bnxt_ring_tpa_stats_str;

			for (j = 0; j < num_str; j++) {
				sprintf(buf, "[%d]: %s", i, str[j]);
				buf += ETH_GSTRING_LEN;
			}
skip_tpa_stats:
			if (is_rx_ring(bp, i)) {
				num_str = NUM_RING_RX_SW_STATS;
				for (j = 0; j < num_str; j++) {
					sprintf(buf, "[%d]: %s", i,
						bnxt_rx_sw_stats_str[j]);
					buf += ETH_GSTRING_LEN;
				}
			}
			if (is_tx_ring(bp, i)) {
				num_str = bnxt_get_num_tx_sw_push_stats(bp);
				for (j = 0; j < num_str; j++) {
					sprintf(buf, "[%d]: %s", i,
						bnxt_tx_sw_push_stats_str[j]);
					buf += ETH_GSTRING_LEN;
				}

				num_str = bnxt_get_num_txtime_sw_stats(bp);
				for (j = 0; j < num_str; j++) {
					sprintf(buf, "[%d]: %s", i,
						bnxt_txtime_sw_stats_str[j]);
					buf += ETH_GSTRING_LEN;
				}
			}
			num_str = NUM_RING_CMN_SW_STATS;
			for (j = 0; j < num_str; j++) {
				sprintf(buf, "[%d]: %s", i,
					bnxt_cmn_sw_stats_str[j]);
				buf += ETH_GSTRING_LEN;
			}
			num_str = BNXT_NUM_XSK_STATS;
			for (j = 0; j < num_str; j++) {
				sprintf(buf, "[%d]: %s", i, bnxt_xsk_stats[j]);
				buf += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < BNXT_NUM_RING_ERR_STATS; i++) {
			strcpy(buf, bnxt_ring_err_stats_arr[i]);
			buf += ETH_GSTRING_LEN;
		}
		if (bp->ktls_info) {
			for (i = 0; i < BNXT_NUM_KTLS_STATS; i++) {
				strcpy(buf, bnxt_ktls_stats[i]);
				buf += ETH_GSTRING_LEN;
			}
		}
		if (bp->quic_info) {
			for (i = 0; i < BNXT_NUM_QUIC_STATS; i++) {
				strscpy(buf, bnxt_quic_stats[i], ETH_GSTRING_LEN);
				buf += ETH_GSTRING_LEN;
			}
		}
		if (bp->flags & BNXT_FLAG_PORT_STATS) {
			for (i = 0; i < BNXT_NUM_PORT_STATS; i++) {
				strcpy(buf, bnxt_port_stats_arr[i].string);
				buf += ETH_GSTRING_LEN;
			}
		}
		if (bp->flags & BNXT_FLAG_PORT_STATS_EXT) {
			u32 len;

			len = min_t(u32, bp->fw_rx_stats_ext_size,
				    ARRAY_SIZE(bnxt_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				if (bnxt_skip_port_stats_ext(bp, i))
					continue;

				bnxt_port_stats_cos_strcpy(bp->rx_cosq_names, BNXT_MAX_QUEUE *
							   BNXT_MAX_COSQ_NAME_LEN, buf,
							   bnxt_port_stats_ext_arr[i].string);
				buf += ETH_GSTRING_LEN;
			}
			len = min_t(u32, bp->fw_tx_stats_ext_size,
				    ARRAY_SIZE(bnxt_tx_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				if (bnxt_skip_tx_port_stats_ext(bp, i))
					continue;

				bnxt_port_stats_cos_strcpy(bp->tx_cosq_names, 0, buf,
							   bnxt_tx_port_stats_ext_arr[i].string);
				buf += ETH_GSTRING_LEN;
			}
			if (bp->pri2cos_valid) {
				for (i = 0; i < 8; i++) {
					strcpy(buf,
					       bnxt_rx_bytes_pri_arr[i].string);
					buf += ETH_GSTRING_LEN;
				}
				for (i = 0; i < 8; i++) {
					strcpy(buf,
					       bnxt_rx_pkts_pri_arr[i].string);
					buf += ETH_GSTRING_LEN;
				}
				for (i = 0; i < 8; i++) {
					strcpy(buf,
					       bnxt_tx_bytes_pri_arr[i].string);
					buf += ETH_GSTRING_LEN;
				}
				for (i = 0; i < 8; i++) {
					strcpy(buf,
					       bnxt_tx_pkts_pri_arr[i].string);
					buf += ETH_GSTRING_LEN;
				}
			}
		}
		if (bp->flags & BNXT_FLAG_ECN_STATS) {
			for (i = 0; i < BNXT_NUM_ECN_PORT_STATS; i++) {
				bnxt_port_stats_cos_strcpy(bp->rx_cosq_names, 0, buf,
							   bnxt_ecn_port_stats_arr[i]);
				if (bp->rx_cosq_names)
					bnxt_port_stats_cos_strcpy(bp->rx_cosq_names,
								   BNXT_MAX_QUEUE *
								   BNXT_MAX_COSQ_NAME_LEN, buf,
								   bnxt_ecn_port_stats_arr[i]);
				buf += ETH_GSTRING_LEN;
			}
		}
		if (bp->fw_cap & BNXT_FW_CAP_GENERIC_STATS) {
			if (!bp->generic_stats.hw_stats)
				goto skip_gen_stats;

			for (i = 0; i < BNXT_NUM_GENERIC_STATS; i++) {
				strscpy(buf, bnxt_generic_stats[i], ETH_GSTRING_LEN);
				buf += ETH_GSTRING_LEN;
			}
		}

skip_gen_stats:
		if (bp->fw_cap & BNXT_FW_CAP_LPBK_STATS) {
			if (bp->lpbk_stats.hw_stats) {
				for (i = 0; i < BNXT_NUM_LPBK_STATS; i++) {
					strscpy(buf, bnxt_lpbk_stats[i], ETH_GSTRING_LEN);
					buf += ETH_GSTRING_LEN;
				}
			}
		}
		break;
	case ETH_SS_TEST:
		if (bp->num_tests)
			memcpy(buf, bp->test_info->string,
			       bp->num_tests * ETH_GSTRING_LEN);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < ARRAY_SIZE(bnxt_priv_flags); i++) {
			strscpy(buf, bnxt_priv_flags[i], ETH_GSTRING_LEN);
			buf += ETH_GSTRING_LEN;
		}
		break;
	default:
		netdev_err(bp->dev, "bnxt_get_strings invalid request %x\n",
			   stringset);
		break;
	}
}

static void bnxt_get_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *ering,
			       struct kernel_ethtool_ringparam *kernel_ering,
			       struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);

	if (bp->flags & BNXT_FLAG_AGG_RINGS) {
		ering->rx_max_pending = BNXT_MAX_RX_DESC_CNT_JUM_ENA;
		ering->rx_jumbo_max_pending = BNXT_MAX_RX_JUM_DESC_CNT;
#ifdef HAVE_ETHTOOL_TCP_DATA_SPLIT
		kernel_ering->tcp_data_split = ETHTOOL_TCP_DATA_SPLIT_ENABLED;
#endif
	} else {
		ering->rx_max_pending = BNXT_MAX_RX_DESC_CNT;
		ering->rx_jumbo_max_pending = 0;
#ifdef HAVE_ETHTOOL_TCP_DATA_SPLIT
		kernel_ering->tcp_data_split = ETHTOOL_TCP_DATA_SPLIT_DISABLED;
#endif
	}
	ering->tx_max_pending = BNXT_MAX_TX_DESC_CNT;

	ering->rx_pending = bp->rx_ring_size;
	ering->rx_jumbo_pending = bp->rx_agg_ring_size;
	ering->tx_pending = bp->tx_ring_size;
}

static int bnxt_set_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *ering,
			      struct kernel_ethtool_ringparam *kernel_ering,
			      struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);

	if ((ering->rx_pending > BNXT_MAX_RX_DESC_CNT) ||
	    (ering->tx_pending > BNXT_MAX_TX_DESC_CNT) ||
	    (ering->tx_pending < BNXT_MIN_TX_DESC_CNT))
		return -EINVAL;

	if (netif_running(dev))
		bnxt_close_nic(bp, false, false);

	bp->rx_ring_size = ering->rx_pending;
	bp->tx_ring_size = ering->tx_pending;

	bnxt_set_ring_params(bp, false);

	if (netif_running(dev))
		return bnxt_open_nic(bp, false, false);

	return 0;
}

#if defined(ETHTOOL_GCHANNELS) && !defined(GET_ETHTOOL_OP_EXT)
static void bnxt_get_channels(struct net_device *dev,
			      struct ethtool_channels *channel)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	int max_rx_rings, max_tx_rings, tcs;
	int max_tx_sch_inputs, tx_grps;
	u32 curr_rx_shared = 0;

	if (bp->flags & BNXT_FLAG_SHARED_RINGS) {
		curr_rx_shared = bp->rx_nr_rings;
		if (BNXT_CHIP_TYPE_NITRO_A0(bp))
			curr_rx_shared--;
	}
	/* Get the most up-to-date max_tx_sch_inputs. */
	if (netif_running(dev) && BNXT_NEW_RM(bp))
		bnxt_hwrm_func_resc_qcaps(bp, false);
	max_tx_sch_inputs = hw_resc->max_tx_sch_inputs;

	bnxt_get_max_rings(bp, &max_rx_rings, &max_tx_rings, true);
	if (max_tx_sch_inputs)
		max_tx_rings = min_t(int, max_tx_rings, max_tx_sch_inputs);

	tcs = bp->num_tc;
	tx_grps = max(tcs, 1);
	if (bp->tx_nr_rings_xdp)
		tx_grps++;
	max_tx_rings /= tx_grps;
	channel->max_combined = min_t(int, max_rx_rings, max_tx_rings);
	channel->max_combined = max(channel->max_combined, curr_rx_shared);

	if (bnxt_get_max_rings(bp, &max_rx_rings, &max_tx_rings, false)) {
		max_rx_rings = 0;
		max_tx_rings = 0;
	}
	if (max_tx_sch_inputs)
		max_tx_rings = min_t(int, max_tx_rings, max_tx_sch_inputs);

	if (tcs > 1)
		max_tx_rings /= tcs;

	channel->max_rx = max_rx_rings;
	channel->max_tx = max_tx_rings;
	channel->max_other = 0;

	if (!bp->tx_nr_rings)
		return;

	if (bp->flags & BNXT_FLAG_SHARED_RINGS) {
		channel->combined_count = curr_rx_shared;
	} else {
		if (!BNXT_CHIP_TYPE_NITRO_A0(bp)) {
			channel->rx_count = bp->rx_nr_rings;
			channel->tx_count = bp->tx_nr_rings_per_tc;
		}
	}
}

#if defined(HAVE_ETF_QOPT_OFFLOAD)
static int bnxt_check_etf_tx_rings(struct bnxt *bp, int tx, int tcs, int tx_xdp)
{
	int max_etf_bit, tx_count, tx_sets = 1;

	if (tcs)
		tx_sets = tcs;

	tx_count = tx * tx_sets - tx_xdp;

	if (!bp->etf_tx_ring_map)
		return 0;

	max_etf_bit = find_last_bit(bp->etf_tx_ring_map,
				    bp->hw_resc.max_tx_rings);
	/* no bit is set */
	if (max_etf_bit == bp->hw_resc.max_tx_rings)
		max_etf_bit = 0;

	if (tx_count <= max_etf_bit) {
		netdev_warn(bp->dev,
			    "Cannot configure tx rings below ETF enabled ring %d\n",
			    max_etf_bit);
		return -EINVAL;
	}
	return 0;
}
#endif

static int bnxt_set_channels(struct net_device *dev,
			     struct ethtool_channels *channel)
{
	struct bnxt *bp = netdev_priv(dev);
	int req_tx_rings, req_rx_rings, tcs;
	bool sh = false;
	int tx_xdp = 0;
	int rc = 0;
	int tx_cp;

	if (bp->sriov_cfg)
		return -EBUSY;

	if (channel->other_count)
		return -EINVAL;

	if (!channel->combined_count &&
	    (!channel->rx_count || !channel->tx_count))
		return -EINVAL;

	if (channel->combined_count &&
	    (channel->rx_count || channel->tx_count))
		return -EINVAL;

	if (BNXT_CHIP_TYPE_NITRO_A0(bp) && (channel->rx_count ||
					    channel->tx_count))
		return -EINVAL;

	if (channel->combined_count)
		sh = true;

	tcs = bp->num_tc;

	req_tx_rings = sh ? channel->combined_count : channel->tx_count;
	req_rx_rings = sh ? channel->combined_count : channel->rx_count;
	if (bp->tx_nr_rings_xdp) {
		if (!sh) {
			netdev_err(dev, "Only combined mode supported when XDP is enabled.\n");
			return -EINVAL;
		}
		tx_xdp = req_rx_rings;
	}

#if defined(HAVE_ETF_QOPT_OFFLOAD)
	rc = bnxt_check_etf_tx_rings(bp, req_tx_rings, tcs, tx_xdp);
	if (rc)
		return rc;
#endif
#ifndef HAVE_NEW_RSSCTX_INTERFACE
	if (BNXT_SUPPORTS_MULTI_RSS_CTX(bp) &&
	    req_rx_rings < bp->rx_nr_rings &&
	    req_rx_rings <= bnxt_get_max_rss_ctx_ring(bp)) {
		netdev_warn(dev, "Can't deactivate rings used by RSS contexts\n");
		return -EINVAL;
	}
#endif
	if (bnxt_get_nr_rss_ctxs(bp, req_rx_rings) !=
	    bnxt_get_nr_rss_ctxs(bp, bp->rx_nr_rings) &&
	    netif_is_rxfh_configured(dev)) {
		netdev_warn(dev, "RSS table size change required, RSS table entries must be default to proceed\n");
		return -EINVAL;
	}

	rc = bnxt_check_rings(bp, req_tx_rings, req_rx_rings, sh, tcs, tx_xdp);
	if (rc) {
		netdev_warn(dev, "Unable to allocate the requested rings\n");
		return rc;
	}

	bnxt_clear_usr_fltrs(bp, true);
	if (BNXT_SUPPORTS_MULTI_RSS_CTX(bp))
		bnxt_clear_rss_ctxs(bp);
	if (netif_running(dev)) {
		if (BNXT_PF(bp)) {
			/* TODO CHIMP_FW: Send message to all VF's
			 * before PF unload
			 */
		}
		bnxt_close_nic(bp, true, false);
	}

	if (sh) {
		bp->flags |= BNXT_FLAG_SHARED_RINGS;
		bp->rx_nr_rings = channel->combined_count;
		bp->tx_nr_rings_per_tc = channel->combined_count;
	} else {
		bp->flags &= ~BNXT_FLAG_SHARED_RINGS;
		bp->rx_nr_rings = channel->rx_count;
		bp->tx_nr_rings_per_tc = channel->tx_count;
	}
	bp->tx_nr_rings_xdp = tx_xdp;
	bp->tx_nr_rings = bp->tx_nr_rings_per_tc + tx_xdp;
	if (tcs > 1)
		bp->tx_nr_rings = bp->tx_nr_rings_per_tc * tcs + tx_xdp;

	tx_cp = bnxt_num_tx_to_cp(bp, bp->tx_nr_rings);
	bp->cp_nr_rings = sh ? max_t(int, tx_cp, bp->rx_nr_rings) :
			       tx_cp + bp->rx_nr_rings;

	bnxt_set_dflt_mpc_rings(bp);

	/* After changing number of rx channels, update NTUPLE feature. */
	netdev_update_features(dev);
	if (netif_running(dev)) {
		rc = bnxt_open_nic(bp, true, false);
		if ((!rc) && BNXT_PF(bp)) {
			/* TODO CHIMP_FW: Send message to all VF's
			 * to renable
			 */
		}
	} else {
		rc = bnxt_reserve_rings(bp, true);
	}

	return rc;
}
#endif

#ifdef HAVE_RXNFC
static u32 bnxt_get_all_fltr_ids_rcu(struct bnxt *bp, struct hlist_head tbl[],
				     int tbl_size, u32 *ids, u32 start,
				     u32 id_cnt)
{
	int i, j = start;

	if (j >= id_cnt)
		return j;
	for (i = 0; i < tbl_size; i++) {
		struct hlist_head *head;
		struct hlist_node __maybe_unused *node;
		struct bnxt_filter_base *fltr;

		head = &tbl[i];
		__hlist_for_each_entry_rcu(fltr, node, head, hash) {
			if (!fltr->flags ||
			    test_bit(BNXT_FLTR_FW_DELETED, &fltr->state))
				continue;
			ids[j++] = fltr->sw_id;
			if (j == id_cnt)
				return j;
		}
	}
	return j;
}

static struct bnxt_filter_base *bnxt_get_one_fltr_rcu(struct bnxt *bp,
						      struct hlist_head tbl[],
						      int tbl_size, u32 id)
{
	int i;

	for (i = 0; i < tbl_size; i++) {
		struct hlist_head *head;
		struct hlist_node __maybe_unused *node;
		struct bnxt_filter_base *fltr;

		head = &tbl[i];
		__hlist_for_each_entry_rcu(fltr, node, head, hash) {
			if (fltr->flags && fltr->sw_id == id)
				return fltr;
		}
	}
	return NULL;
}

static int bnxt_grxclsrlall(struct bnxt *bp, struct ethtool_rxnfc *cmd,
			    u32 *rule_locs)
{
	u32 count;

	cmd->data = bp->ntp_fltr_count;
	rcu_read_lock();
	count = bnxt_get_all_fltr_ids_rcu(bp, bp->l2_fltr_hash_tbl,
					  BNXT_L2_FLTR_HASH_SIZE, rule_locs, 0,
					  cmd->rule_cnt);
	cmd->rule_cnt = bnxt_get_all_fltr_ids_rcu(bp, bp->ntp_fltr_hash_tbl,
						  BNXT_NTP_FLTR_HASH_SIZE,
						  rule_locs, count,
						  cmd->rule_cnt);
	rcu_read_unlock();
	return 0;
}

static int bnxt_grxclsrule(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fs =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct bnxt_filter_base *fltr_base;
	struct bnxt_ntuple_filter *fltr;
	struct bnxt_flow_masks *fmasks;
	struct flow_keys *fkeys;
	int rc = -EINVAL;

	if (fs->location >= bp->max_fltr)
		return rc;

	rcu_read_lock();
	fltr_base = bnxt_get_one_fltr_rcu(bp, bp->l2_fltr_hash_tbl,
					  BNXT_L2_FLTR_HASH_SIZE,
					  fs->location);
	if (fltr_base) {
		struct ethhdr *h_ether = &fs->h_u.ether_spec;
		struct ethhdr *m_ether = &fs->m_u.ether_spec;
		struct bnxt_l2_filter *l2_fltr;
		struct bnxt_l2_key *l2_key;

		l2_fltr = container_of(fltr_base, struct bnxt_l2_filter, base);
		l2_key = &l2_fltr->l2_key;
		fs->flow_type = ETHER_FLOW;
		ether_addr_copy(h_ether->h_dest, l2_key->dst_mac_addr);
		eth_broadcast_addr(m_ether->h_dest);
		if (l2_key->vlan) {
			struct ethtool_flow_ext *m_ext = &fs->m_ext;
			struct ethtool_flow_ext *h_ext = &fs->h_ext;

			fs->flow_type |= FLOW_EXT;
			m_ext->vlan_tci = htons(0xfff);
			h_ext->vlan_tci = htons(l2_key->vlan);
		}
		if (fltr_base->flags & BNXT_ACT_RING_DST)
			fs->ring_cookie = fltr_base->rxq;
		if (fltr_base->flags & BNXT_ACT_FUNC_DST)
			fs->ring_cookie = (u64)(fltr_base->vf_idx + 1) <<
					  ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF;
		rcu_read_unlock();
		return 0;
	}
	fltr_base = bnxt_get_one_fltr_rcu(bp, bp->ntp_fltr_hash_tbl,
					  BNXT_NTP_FLTR_HASH_SIZE,
					  fs->location);
	if (!fltr_base) {
		rcu_read_unlock();
		return rc;
	}
	fltr = container_of(fltr_base, struct bnxt_ntuple_filter, base);
	fkeys = &fltr->fkeys;
	fmasks = &fltr->fmasks;
	if (fkeys->basic.n_proto == htons(ETH_P_IP)) {
		if (fkeys->basic.ip_proto == IPPROTO_ICMP ||
		    fkeys->basic.ip_proto == IPPROTO_RAW) {
			fs->flow_type = IP_USER_FLOW;
			fs->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
			if (fkeys->basic.ip_proto == IPPROTO_ICMP)
				fs->h_u.usr_ip4_spec.proto = IPPROTO_ICMP;
			else
				fs->h_u.usr_ip4_spec.proto = IPPROTO_RAW;
			fs->m_u.usr_ip4_spec.proto = BNXT_IP_PROTO_FULL_MASK;
		} else if (fkeys->basic.ip_proto == IPPROTO_TCP) {
			fs->flow_type = TCP_V4_FLOW;
		} else if (fkeys->basic.ip_proto == IPPROTO_UDP) {
			fs->flow_type = UDP_V4_FLOW;
		} else {
			goto fltr_err;
		}

		fs->h_u.tcp_ip4_spec.ip4src = fkeys->addrs.v4addrs.src;
		fs->m_u.tcp_ip4_spec.ip4src = fmasks->addrs.v4addrs.src;
		fs->h_u.tcp_ip4_spec.ip4dst = fkeys->addrs.v4addrs.dst;
		fs->m_u.tcp_ip4_spec.ip4dst = fmasks->addrs.v4addrs.dst;
		if (fs->flow_type == TCP_V4_FLOW ||
		    fs->flow_type == UDP_V4_FLOW) {
			fs->h_u.tcp_ip4_spec.psrc = fkeys->ports.src;
			fs->m_u.tcp_ip4_spec.psrc = fmasks->ports.src;
			fs->h_u.tcp_ip4_spec.pdst = fkeys->ports.dst;
			fs->m_u.tcp_ip4_spec.pdst = fmasks->ports.dst;
		}
	} else {
#ifdef HAVE_ETHTOOL_IP6_SPEC
		if (fkeys->basic.ip_proto == IPPROTO_ICMPV6 ||
		    fkeys->basic.ip_proto == IPPROTO_RAW) {
			fs->flow_type = IPV6_USER_FLOW;
			if (fkeys->basic.ip_proto == IPPROTO_ICMPV6)
				fs->h_u.usr_ip6_spec.l4_proto = IPPROTO_ICMPV6;
			else
				fs->h_u.usr_ip6_spec.l4_proto = IPPROTO_RAW;
			fs->m_u.usr_ip6_spec.l4_proto = BNXT_IP_PROTO_FULL_MASK;
		} else if (fkeys->basic.ip_proto == IPPROTO_TCP) {
			fs->flow_type = TCP_V6_FLOW;
		} else if (fkeys->basic.ip_proto == IPPROTO_UDP) {
			fs->flow_type = UDP_V6_FLOW;
		} else {
			goto fltr_err;
		}

		*(struct in6_addr *)&fs->h_u.tcp_ip6_spec.ip6src[0] =
			fkeys->addrs.v6addrs.src;
		*(struct in6_addr *)&fs->m_u.tcp_ip6_spec.ip6src[0] =
			fmasks->addrs.v6addrs.src;
		*(struct in6_addr *)&fs->h_u.tcp_ip6_spec.ip6dst[0] =
			fkeys->addrs.v6addrs.dst;
		*(struct in6_addr *)&fs->m_u.tcp_ip6_spec.ip6dst[0] =
			fmasks->addrs.v6addrs.dst;
		if (fs->flow_type == TCP_V6_FLOW ||
		    fs->flow_type == UDP_V6_FLOW) {
			fs->h_u.tcp_ip6_spec.psrc = fkeys->ports.src;
			fs->m_u.tcp_ip6_spec.psrc = fmasks->ports.src;
			fs->h_u.tcp_ip6_spec.pdst = fkeys->ports.dst;
			fs->m_u.tcp_ip6_spec.pdst = fmasks->ports.dst;
		}
#endif
	}

	if (fltr->base.flags & BNXT_ACT_DROP)
		fs->ring_cookie = RX_CLS_FLOW_DISC;
	else if (fltr->base.flags & BNXT_ACT_NUMA_DIRECT)
		fs->ring_cookie = fltr->base.rxq - BNXT_NTUPLE_COOKIE_NUMA_DIRECT;
	else
		fs->ring_cookie = fltr->base.rxq;
	rc = 0;

fltr_err:
	rcu_read_unlock();

	return rc;
}

#if defined(HAVE_ETH_RXNFC_RSSCTX) || defined(HAVE_ETHTOOL_RXFH_PARAM)
static struct bnxt_rss_ctx *bnxt_get_rss_ctx_from_index(struct bnxt *bp,
							u32 index)
{
#ifdef HAVE_NEW_RSSCTX_INTERFACE
	struct ethtool_rxfh_context *ctx;

	ctx = xa_load(&bp->dev->ethtool->rss_ctx, index);
	if (!ctx)
		return NULL;
	return ethtool_rxfh_context_priv(ctx);
#else
	struct bnxt_rss_ctx *rss_ctx, *tmp;

	list_for_each_entry_safe(rss_ctx, tmp, &bp->rss_ctx_list, list)
		if (rss_ctx->index == index)
			return rss_ctx;
	return NULL;
#endif
}

static int bnxt_alloc_vnic_rss_table(struct bnxt *bp,
				     struct bnxt_vnic_info *vnic)
{
	int size = L1_CACHE_ALIGN(BNXT_MAX_RSS_TABLE_SIZE_P5);

	vnic->rss_table_size = size + HW_HASH_KEY_SIZE;
	vnic->rss_table = dma_alloc_coherent(&bp->pdev->dev,
					     vnic->rss_table_size,
					     &vnic->rss_table_dma_addr,
					     GFP_KERNEL);
	if (!vnic->rss_table)
		return -ENOMEM;

	vnic->rss_hash_key = ((void *)vnic->rss_table) + size;
	vnic->rss_hash_key_dma_addr = vnic->rss_table_dma_addr + size;
	return 0;
}
#endif

static int bnxt_add_l2_cls_rule(struct bnxt *bp,
				struct ethtool_rx_flow_spec *fs)
{
	u32 ring = ethtool_get_flow_spec_ring(fs->ring_cookie);
	u8 vf = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	struct ethhdr *h_ether = &fs->h_u.ether_spec;
	struct ethhdr *m_ether = &fs->m_u.ether_spec;
	struct bnxt_l2_filter *fltr;
	struct bnxt_l2_key key;
	u16 vnic_id;
	u8 flags;
	int rc;

	if (BNXT_CHIP_P5_PLUS(bp))
		return -EOPNOTSUPP;

	if (!is_broadcast_ether_addr(m_ether->h_dest))
		return -EINVAL;
	ether_addr_copy(key.dst_mac_addr, h_ether->h_dest);
	key.vlan = 0;
	if (fs->flow_type & FLOW_EXT) {
		struct ethtool_flow_ext *m_ext = &fs->m_ext;
		struct ethtool_flow_ext *h_ext = &fs->h_ext;

		if (m_ext->vlan_tci != htons(0xfff) || !h_ext->vlan_tci)
			return -EINVAL;
		key.vlan = htons(h_ext->vlan_tci);
	}

	if (vf) {
		flags = BNXT_ACT_FUNC_DST;
		vnic_id = 0xffff;
		vf--;
		if (!bnxt_vf_vnic_state_is_up(bp, vf))
			return -ENODEV;
	} else {
		flags = BNXT_ACT_RING_DST;
		if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
			vnic_id = bp->vnic_info[BNXT_VNIC_DEFAULT].fw_vnic_id;
		else
			vnic_id = bp->vnic_info[ring + 1].fw_vnic_id;
	}
	fltr = bnxt_alloc_new_l2_filter(bp, &key, flags);
	if (IS_ERR(fltr))
		return PTR_ERR(fltr);

	fltr->base.fw_vnic_id = vnic_id;
	fltr->base.rxq = ring;
	fltr->base.vf_idx = vf;
	rc = bnxt_hwrm_l2_filter_alloc(bp, fltr);
	if (rc)
		bnxt_del_l2_filter(bp, fltr);
	else
		fs->location = fltr->base.sw_id;
	return rc;
}

static bool bnxt_verify_ntuple_ip4_flow(struct ethtool_usrip4_spec *ip_spec,
					struct ethtool_usrip4_spec *ip_mask)
{
	if (ip_mask->l4_4_bytes || ip_mask->tos ||
	    ip_spec->ip_ver != ETH_RX_NFC_IP4 ||
	    ip_mask->proto != BNXT_IP_PROTO_FULL_MASK ||
	    (ip_spec->proto != IPPROTO_RAW && ip_spec->proto != IPPROTO_ICMP))
		return false;
	return true;
}

#ifdef HAVE_ETHTOOL_IP6_SPEC
static bool bnxt_verify_ntuple_ip6_flow(struct ethtool_usrip6_spec *ip_spec,
					struct ethtool_usrip6_spec *ip_mask)
{
	if (ip_mask->l4_4_bytes || ip_mask->tclass ||
	    ip_mask->l4_proto != BNXT_IP_PROTO_FULL_MASK ||
	    (ip_spec->l4_proto != IPPROTO_RAW &&
	     ip_spec->l4_proto != IPPROTO_ICMPV6))
		return false;
	return true;
}
#endif

static int bnxt_add_ntuple_cls_rule(struct bnxt *bp,
				    struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	u8 vf = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	struct bnxt_ntuple_filter *new_fltr, *fltr;
	u32 flow_type = fs->flow_type & 0xff;
	s64 cookie = (s64)fs->ring_cookie;
	struct bnxt_l2_filter *l2_fltr;
	struct bnxt_flow_masks *fmasks;
	struct flow_keys *fkeys;
	u32 idx;
	int rc;

	if (!bp->vnic_info)
		return -EAGAIN;

	if ((fs->flow_type & (FLOW_MAC_EXT | FLOW_EXT)) || (vf && cookie > 0))
		return -EOPNOTSUPP;

	if (flow_type == IP_USER_FLOW) {
		if (!bnxt_verify_ntuple_ip4_flow(&fs->h_u.usr_ip4_spec,
						 &fs->m_u.usr_ip4_spec))
			return -EOPNOTSUPP;
	}

#ifdef HAVE_ETHTOOL_IP6_SPEC
	if (flow_type == IPV6_USER_FLOW) {
		if (!bnxt_verify_ntuple_ip6_flow(&fs->h_u.usr_ip6_spec,
						 &fs->m_u.usr_ip6_spec))
			return -EOPNOTSUPP;
	}
#endif

	new_fltr = kzalloc(sizeof(*new_fltr), GFP_KERNEL);
	if (!new_fltr)
		return -ENOMEM;

	l2_fltr = bp->vnic_info[BNXT_VNIC_DEFAULT].l2_filters[0];
	atomic_inc(&l2_fltr->refcnt);
	new_fltr->l2_fltr = l2_fltr;
	fmasks = &new_fltr->fmasks;
	fkeys = &new_fltr->fkeys;

	rc = -EOPNOTSUPP;
	switch (flow_type) {
	case IP_USER_FLOW: {
		struct ethtool_usrip4_spec *ip_spec = &fs->h_u.usr_ip4_spec;
		struct ethtool_usrip4_spec *ip_mask = &fs->m_u.usr_ip4_spec;

		fkeys->basic.ip_proto = ip_spec->proto;
		fkeys->basic.n_proto = htons(ETH_P_IP);
		fkeys->addrs.v4addrs.src = ip_spec->ip4src;
		fmasks->addrs.v4addrs.src = ip_mask->ip4src;
		fkeys->addrs.v4addrs.dst = ip_spec->ip4dst;
		fmasks->addrs.v4addrs.dst = ip_mask->ip4dst;
		break;
	}
	case TCP_V4_FLOW:
	case UDP_V4_FLOW: {
		struct ethtool_tcpip4_spec *ip_spec = &fs->h_u.tcp_ip4_spec;
		struct ethtool_tcpip4_spec *ip_mask = &fs->m_u.tcp_ip4_spec;

		fkeys->basic.ip_proto = IPPROTO_TCP;
		if (flow_type == UDP_V4_FLOW)
			fkeys->basic.ip_proto = IPPROTO_UDP;
		fkeys->basic.n_proto = htons(ETH_P_IP);
		fkeys->addrs.v4addrs.src = ip_spec->ip4src;
		fmasks->addrs.v4addrs.src = ip_mask->ip4src;
		fkeys->addrs.v4addrs.dst = ip_spec->ip4dst;
		fmasks->addrs.v4addrs.dst = ip_mask->ip4dst;
		fkeys->ports.src = ip_spec->psrc;
		fmasks->ports.src = ip_mask->psrc;
		fkeys->ports.dst = ip_spec->pdst;
		fmasks->ports.dst = ip_mask->pdst;
		break;
	}
#ifdef HAVE_ETHTOOL_IP6_SPEC
	case IPV6_USER_FLOW: {
		struct ethtool_usrip6_spec *ip_spec = &fs->h_u.usr_ip6_spec;
		struct ethtool_usrip6_spec *ip_mask = &fs->m_u.usr_ip6_spec;

		fkeys->basic.ip_proto = ip_spec->l4_proto;
		fkeys->basic.n_proto = htons(ETH_P_IPV6);
		fkeys->addrs.v6addrs.src = *(struct in6_addr *)&ip_spec->ip6src;
		fmasks->addrs.v6addrs.src = *(struct in6_addr *)&ip_mask->ip6src;
		fkeys->addrs.v6addrs.dst = *(struct in6_addr *)&ip_spec->ip6dst;
		fmasks->addrs.v6addrs.dst = *(struct in6_addr *)&ip_mask->ip6dst;
		break;
	}
	case TCP_V6_FLOW:
	case UDP_V6_FLOW: {
		struct ethtool_tcpip6_spec *ip_spec = &fs->h_u.tcp_ip6_spec;
		struct ethtool_tcpip6_spec *ip_mask = &fs->m_u.tcp_ip6_spec;

		fkeys->basic.ip_proto = IPPROTO_TCP;
		if (flow_type == UDP_V6_FLOW)
			fkeys->basic.ip_proto = IPPROTO_UDP;
		fkeys->basic.n_proto = htons(ETH_P_IPV6);

		fkeys->addrs.v6addrs.src = *(struct in6_addr *)&ip_spec->ip6src;
		fmasks->addrs.v6addrs.src = *(struct in6_addr *)&ip_mask->ip6src;
		fkeys->addrs.v6addrs.dst = *(struct in6_addr *)&ip_spec->ip6dst;
		fmasks->addrs.v6addrs.dst = *(struct in6_addr *)&ip_mask->ip6dst;
		fkeys->ports.src = ip_spec->psrc;
		fmasks->ports.src = ip_mask->psrc;
		fkeys->ports.dst = ip_spec->pdst;
		fmasks->ports.dst = ip_mask->pdst;
		break;
	}
#endif
	default:
		goto ntuple_err;
	}
	if (!memcmp(&BNXT_FLOW_MASK_NONE, fmasks, sizeof(*fmasks)))
		goto ntuple_err;

	idx = bnxt_get_ntp_filter_idx(bp, fkeys, NULL);
	rcu_read_lock();
	fltr = bnxt_lookup_ntp_filter_from_idx(bp, new_fltr, idx);
	if (fltr) {
		rcu_read_unlock();
		rc = -EEXIST;
		goto ntuple_err;
	}
	rcu_read_unlock();

	new_fltr->base.flags = BNXT_ACT_NO_AGING;
#if defined(HAVE_ETH_RXNFC_RSSCTX)
	if (fs->flow_type & FLOW_RSS) {
		struct bnxt_rss_ctx *rss_ctx;

		new_fltr->base.fw_vnic_id = 0;
		new_fltr->base.flags |= BNXT_ACT_RSS_CTX;
		rss_ctx = bnxt_get_rss_ctx_from_index(bp, cmd->rss_context);
		if (rss_ctx) {
			new_fltr->base.fw_vnic_id = rss_ctx->index;
		} else {
			rc = -EINVAL;
			goto ntuple_err;
		}
	}
#endif
	if (cookie == RX_CLS_FLOW_DISC) {
		new_fltr->base.flags |= BNXT_ACT_DROP;
	} else if (cookie <= BNXT_NTUPLE_COOKIE_NUMA_DIRECT) {
		new_fltr->base.flags |= BNXT_ACT_NUMA_DIRECT;
		new_fltr->base.rxq = BNXT_NTUPLE_COOKIE_NUMA_DIRECT - cookie;
	} else {
		new_fltr->base.rxq = ethtool_get_flow_spec_ring(fs->ring_cookie);
	}
	__set_bit(BNXT_FLTR_VALID, &new_fltr->base.state);
	rc = bnxt_insert_ntp_filter(bp, new_fltr, idx);
	if (!rc) {
		rc = bnxt_hwrm_cfa_ntuple_filter_alloc(bp, new_fltr);
		if (rc) {
			bnxt_del_ntp_filter(bp, new_fltr);
			return rc;
		}
		fs->location = new_fltr->base.sw_id;
		return 0;
	}

ntuple_err:
	atomic_dec(&l2_fltr->refcnt);
	kfree(new_fltr);
	return rc;
}

static int bnxt_srxclsrlins(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	s64 cookie = (s64)fs->ring_cookie;
	u32 ring, flow_type;
	int rc;
	u8 vf;

	if (!netif_running(bp->dev))
		return -EAGAIN;
	if (fs->location != RX_CLS_LOC_ANY)
		return -EINVAL;

	flow_type = fs->flow_type;
#ifdef HAVE_ETHTOOL_IP6_SPEC
	if ((flow_type == IP_USER_FLOW ||
	     flow_type == IPV6_USER_FLOW) &&
	    !(bp->fw_cap & BNXT_FW_CAP_CFA_NTUPLE_RX_EXT_IP_PROTO))
		return -EOPNOTSUPP;
#else
	if ((flow_type == IP_USER_FLOW) &&
	    !(bp->fw_cap & BNXT_FW_CAP_CFA_NTUPLE_RX_EXT_IP_PROTO))
		return -EOPNOTSUPP;
#endif

#if defined(HAVE_ETH_RXNFC_RSSCTX)
	if (flow_type & FLOW_MAC_EXT)
#else
	if (flow_type & (FLOW_MAC_EXT | FLOW_RSS))
#endif
		return -EINVAL;
	flow_type &= ~FLOW_EXT;

	if (cookie == RX_CLS_FLOW_DISC && flow_type != ETHER_FLOW)
		return bnxt_add_ntuple_cls_rule(bp, cmd);

	if (cookie <= BNXT_NTUPLE_COOKIE_NUMA_DIRECT) {
		if (~bp->flags & BNXT_FLAG_NUMA_DIRECT)
			return -EPERM;
		if (flow_type == ETHER_FLOW)
			return -EINVAL; /* no L2 context */
		if (BNXT_NTUPLE_COOKIE_NUMA_DIRECT - cookie > bp->rx_nr_rings)
			return -EINVAL;
		return bnxt_add_ntuple_cls_rule(bp, cmd);
	}

	if (!(bp->flags & BNXT_FLAG_RFS))
		return -EPERM;

	ring = ethtool_get_flow_spec_ring(fs->ring_cookie);
	vf = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	if (BNXT_VF(bp) && vf)
		return -EINVAL;
	if (BNXT_PF(bp) && vf > bp->pf.active_vfs)
		return -EINVAL;
	if (!vf && ring >= bp->rx_nr_rings)
		return -EINVAL;

	if (flow_type == ETHER_FLOW)
		rc = bnxt_add_l2_cls_rule(bp, fs);
	else
		rc = bnxt_add_ntuple_cls_rule(bp, cmd);
	return rc;
}

static int bnxt_srxclsrldel(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	struct bnxt_filter_base *fltr_base;
	struct bnxt_ntuple_filter *fltr;
	u32 id = fs->location;

	if (!netif_running(bp->dev))
		return -EAGAIN;

	rcu_read_lock();
	fltr_base = bnxt_get_one_fltr_rcu(bp, bp->l2_fltr_hash_tbl,
					  BNXT_L2_FLTR_HASH_SIZE, id);
	if (fltr_base) {
		struct bnxt_l2_filter *l2_fltr;

		l2_fltr = container_of(fltr_base, struct bnxt_l2_filter, base);
		rcu_read_unlock();
		bnxt_hwrm_l2_filter_free(bp, l2_fltr);
		bnxt_del_l2_filter(bp, l2_fltr);
		return 0;
	}
	fltr_base = bnxt_get_one_fltr_rcu(bp, bp->ntp_fltr_hash_tbl,
					  BNXT_NTP_FLTR_HASH_SIZE,
					  fs->location);
	if (!fltr_base) {
		rcu_read_unlock();
		return -ENOENT;
	}

	fltr = container_of(fltr_base, struct bnxt_ntuple_filter, base);
	if (!(fltr->base.flags & BNXT_ACT_NO_AGING)) {
		rcu_read_unlock();
		return -EINVAL;
	}
	rcu_read_unlock();
	bnxt_hwrm_cfa_ntuple_filter_free(bp, fltr);
	bnxt_del_ntp_filter(bp, fltr);
	return 0;
}

static u64 get_ethtool_ipv4_rss(struct bnxt *bp)
{
	if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4)
		return RXH_IP_SRC | RXH_IP_DST;
	return 0;
}

static u64 get_ethtool_ipv6_rss(struct bnxt *bp)
{
	if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6)
		return RXH_IP_SRC | RXH_IP_DST;
	return 0;
}

static int bnxt_grxfh(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	cmd->data = 0;
	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= get_ethtool_ipv4_rss(bp);
		break;
	case UDP_V4_FLOW:
		if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		fallthrough;
	case AH_ESP_V4_FLOW:
		if (bp->rss_hash_cfg &
		    (VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
		     VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4))
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		fallthrough;
	case SCTP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
		cmd->data |= get_ethtool_ipv4_rss(bp);
		break;

	case TCP_V6_FLOW:
		if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= get_ethtool_ipv6_rss(bp);
		break;
	case UDP_V6_FLOW:
		if (bp->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		fallthrough;
	case AH_ESP_V6_FLOW:
		if (bp->rss_hash_cfg &
		    (VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
		     VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6))
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		fallthrough;
	case SCTP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		cmd->data |= get_ethtool_ipv6_rss(bp);
		break;
	}
	return 0;
}

#define RXH_4TUPLE (RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3)
#define RXH_2TUPLE (RXH_IP_SRC | RXH_IP_DST)

static int bnxt_srxfh(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	u32 rss_hash_cfg = bp->rss_hash_cfg;
	int tuple, rc = 0;

	if (cmd->data == RXH_4TUPLE)
		tuple = 4;
	else if (cmd->data == RXH_2TUPLE)
		tuple = 2;
	else if (!cmd->data)
		tuple = 0;
	else
		return -EINVAL;

	if (cmd->flow_type == TCP_V4_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4;
	} else if (cmd->flow_type == UDP_V4_FLOW) {
		if (tuple == 4 && !(bp->rss_cap & BNXT_RSS_CAP_UDP_RSS_CAP))
			return -EINVAL;
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4;
	} else if (cmd->flow_type == TCP_V6_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6;
	} else if (cmd->flow_type == UDP_V6_FLOW) {
		if (tuple == 4 && !(bp->rss_cap & BNXT_RSS_CAP_UDP_RSS_CAP))
			return -EINVAL;
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6;
	} else if (cmd->flow_type == AH_ESP_V4_FLOW) {
		if (tuple == 4 && (!(bp->rss_cap & BNXT_RSS_CAP_AH_V4_RSS_CAP) ||
				   !(bp->rss_cap & BNXT_RSS_CAP_ESP_V4_RSS_CAP)))
			return -EINVAL;
		rss_hash_cfg &= ~(VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
				  VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4);
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
					VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4;
	} else if (cmd->flow_type == AH_ESP_V6_FLOW) {
		if (tuple == 4 && (!(bp->rss_cap & BNXT_RSS_CAP_AH_V6_RSS_CAP) ||
				   !(bp->rss_cap & BNXT_RSS_CAP_ESP_V6_RSS_CAP)))
			return -EINVAL;
		rss_hash_cfg &= ~(VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
				  VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6);
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
					VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6;
	} else if (tuple == 4) {
		return -EINVAL;
	}

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
		if (tuple == 2)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4;
		else if (!tuple)
			rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4;
		break;

	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		if (tuple == 2) {
			if (bp->ipv6_flow_lbl_rss_en) {
				/* Hash type ipv6 and ipv6_flow_label are mutually
				 * exclusive. HW does not include the flow_label
				 * in hash calculation for the packets that are
				 * matching tcp_ipv6 and udp_ipv6 hash types
				 */
				rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL;
				rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6;
			} else {
				/* Negate flow label if priv flag not set */
				rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6;
				rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL;
			}
		} else if (!tuple) {
			rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6;
		}
		break;
	}

	if (bp->rss_hash_cfg == rss_hash_cfg)
		return 0;

	if (bp->rss_cap & BNXT_RSS_CAP_RSS_HASH_TYPE_DELTA)
		bp->rss_hash_delta = bp->rss_hash_cfg ^ rss_hash_cfg;
	bp->rss_hash_cfg = rss_hash_cfg;
	if (netif_running(bp->dev)) {
		bnxt_close_nic(bp, false, false);
		rc = bnxt_open_nic(bp, false, false);
	}
	return rc;
}

static int bnxt_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd,
#ifdef HAVE_RXNFC_VOID
			  void *rule_locs)
#else
			  u32 *rule_locs)
#endif
{
	struct bnxt *bp = netdev_priv(dev);
	int rc = 0;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = bp->rx_nr_rings;
		break;

	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = bp->ntp_fltr_count;
		cmd->data = bp->max_fltr | RX_CLS_LOC_SPECIAL;
		break;

	case ETHTOOL_GRXCLSRLALL:
		rc = bnxt_grxclsrlall(bp, cmd, (u32 *)rule_locs);
		break;

	case ETHTOOL_GRXCLSRULE:
		rc = bnxt_grxclsrule(bp, cmd);
		break;

	case ETHTOOL_GRXFH:
		rc = bnxt_grxfh(bp, cmd);
		break;

	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

static int bnxt_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		rc = bnxt_srxfh(bp, cmd);
		break;

	case ETHTOOL_SRXCLSRLINS:
		rc = bnxt_srxclsrlins(bp, cmd);
		break;

	case ETHTOOL_SRXCLSRLDEL:
		rc = bnxt_srxclsrldel(bp, cmd);
		break;

	default:
		rc = -EOPNOTSUPP;
		break;
	}
	return rc;
}

#endif /* HAVE_RXNFC */

u32 bnxt_get_rxfh_indir_size(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
		return bnxt_get_nr_rss_ctxs(bp, bp->rx_nr_rings) *
		       BNXT_RSS_TABLE_ENTRIES_P5;
	return HW_HASH_INDEX_SIZE;
}

#if defined(HAVE_GET_RXFH_KEY_SIZE) && !defined(GET_ETHTOOL_OP_EXT)
static u32 bnxt_get_rxfh_key_size(struct net_device *dev)
{
	return HW_HASH_KEY_SIZE;
}

#if defined(HAVE_ETHTOOL_RXFH_PARAM)
static int bnxt_get_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh)
{
	struct bnxt_rss_ctx *rss_ctx = NULL;
	struct bnxt *bp = netdev_priv(dev);
	u32 *indir_tbl = bp->rss_indir_tbl;
	struct bnxt_vnic_info *vnic;
	u32 i, tbl_size;

	/* WIP: Return HWRM_VNIC_RSS_QCFG response, instead of driver cache */
	rxfh->hfunc = bp->rss_hfunc;

	if (!bp->vnic_info)
		return 0;

	vnic = &bp->vnic_info[BNXT_VNIC_DEFAULT];
	if (rxfh->rss_context) {
#ifdef HAVE_NEW_RSSCTX_INTERFACE
		struct ethtool_rxfh_context *ctx;

		ctx = xa_load(&bp->dev->ethtool->rss_ctx, rxfh->rss_context);
		if (!ctx)
			return -EINVAL;
		indir_tbl = ethtool_rxfh_context_indir(ctx);
		rss_ctx = ethtool_rxfh_context_priv(ctx);
#else
		rss_ctx = bnxt_get_rss_ctx_from_index(bp, rxfh->rss_context);
		if (!rss_ctx)
			return -EINVAL;
		indir_tbl = rss_ctx->rss_indir_tbl;
#endif
		vnic = &rss_ctx->vnic;
	}

	if (rxfh->indir && indir_tbl) {
		tbl_size = bnxt_get_rxfh_indir_size(dev);
		for (i = 0; i < tbl_size; i++)
			rxfh->indir[i] = indir_tbl[i];
	}

	if (rxfh->key && vnic->rss_hash_key)
		memcpy(rxfh->key, vnic->rss_hash_key, HW_HASH_KEY_SIZE);

	return 0;
}
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
#endif

#if defined(HAVE_ETHTOOL_RXFH_PARAM)
static void bnxt_modify_rss(struct bnxt *bp, struct ethtool_rxfh_context *ctx,
			    struct bnxt_rss_ctx *rss_ctx,
			    const struct ethtool_rxfh_param *rxfh)
{
	if (rxfh->key) {
		if (rss_ctx) {
			memcpy(rss_ctx->vnic.rss_hash_key, rxfh->key,
			       HW_HASH_KEY_SIZE);
		} else {
			memcpy(bp->rss_hash_key, rxfh->key, HW_HASH_KEY_SIZE);
			bp->rss_hash_key_updated = true;
		}
	}
	if (rxfh->indir) {
		u32 i, pad, tbl_size = bnxt_get_rxfh_indir_size(bp->dev);
		u32 *indir_tbl = bp->rss_indir_tbl;

		if (rss_ctx)
			indir_tbl = ethtool_rxfh_context_indir(ctx);
		for (i = 0; i < tbl_size; i++)
			indir_tbl[i] = rxfh->indir[i];
		pad = bp->rss_indir_tbl_entries - tbl_size;
		if (pad)
			memset(&indir_tbl[i], 0, pad * sizeof(*indir_tbl));
	}
}

static int bnxt_rxfh_context_check(struct bnxt *bp,
				   struct netlink_ext_ack *extack)
{
	if (!BNXT_SUPPORTS_MULTI_RSS_CTX(bp)) {
		NL_SET_ERR_MSG_MOD(extack, "RSS contexts not supported");
		return -EOPNOTSUPP;
	}

	if (!netif_running(bp->dev)) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set RSS contexts when interface is down");
		return -EAGAIN;
	}

	return 0;
}

#ifdef HAVE_NEW_RSSCTX_INTERFACE
static int bnxt_create_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
#else
static int bnxt_set_rxfh_context(struct bnxt *bp,
				 struct ethtool_rxfh_param *rxfh,
				 struct netlink_ext_ack *extack)
#endif
{
#ifdef HAVE_NEW_RSSCTX_INTERFACE
	struct bnxt *bp = netdev_priv(dev);
#endif
	struct bnxt_rss_ctx *rss_ctx;
	struct bnxt_vnic_info *vnic;
#ifndef HAVE_NEW_RSSCTX_INTERFACE
	u32 *rss_context = &rxfh->rss_context;
	bool modify = false;
	bool delete;
	int bit_id;
#endif
	int rc;

	rc = bnxt_rxfh_context_check(bp, extack);
	if (rc)
		return rc;

	if (bp->num_rss_ctx >= BNXT_MAX_ETH_RSS_CTX) {
		NL_SET_ERR_MSG_FMT_MOD(extack, "Out of RSS contexts, maximum %u",
				       BNXT_MAX_ETH_RSS_CTX);
		return -EINVAL;
	}

#ifndef HAVE_NEW_RSSCTX_INTERFACE
	delete = *rss_context != ETH_RXFH_CONTEXT_ALLOC && rxfh->rss_delete;
	if (*rss_context != ETH_RXFH_CONTEXT_ALLOC) {
		rss_ctx = bnxt_get_rss_ctx_from_index(bp, *rss_context);
		if (!rss_ctx) {
			NL_SET_ERR_MSG_FMT_MOD(extack, "RSS context %u not found",
					       *rss_context);
			return -EINVAL;
		}
		if (delete) {
			bnxt_del_one_rss_ctx(bp, rss_ctx, true, false);
			return 0;
		}
		modify = true;
		vnic = &rss_ctx->vnic;
		goto modify_context;
	}

	if (test_and_set_bit(rxfh->rss_context, bp->rss_ctx_bmap)) {
		NL_SET_ERR_MSG_MOD(extack, "Context ID conflict");
		return -EINVAL;
	}
#endif
	if (!bnxt_rfs_capable(bp, true)) {
		NL_SET_ERR_MSG_MOD(extack, "Out hardware resources");
		return -ENOMEM;
	}

#ifndef HAVE_NEW_RSSCTX_INTERFACE
	rss_ctx = bnxt_alloc_rss_ctx(bp);
	if (!rss_ctx)
		return -ENOMEM;
#else
	rss_ctx = ethtool_rxfh_context_priv(ctx);

	bp->num_rss_ctx++;

	rss_ctx->vnic.rss_ctx = ctx;
#endif

	vnic = &rss_ctx->vnic;
	vnic->flags |= BNXT_VNIC_RSSCTX_FLAG;
	vnic->vnic_id = BNXT_VNIC_ID_INVALID;
	rc = bnxt_alloc_vnic_rss_table(bp, vnic);
	if (rc)
		goto out;
#ifndef HAVE_NEW_RSSCTX_INTERFACE
	rc = bnxt_alloc_rss_indir_tbl_compat(bp, rss_ctx);
	if (rc)
		goto out;
	bnxt_set_dflt_rss_indir_tbl(bp, rss_ctx);
#else

	bnxt_set_dflt_rss_indir_tbl(bp, ctx);
#endif
	memcpy(vnic->rss_hash_key, bp->rss_hash_key, HW_HASH_KEY_SIZE);

	rc = bnxt_hwrm_vnic_alloc(bp, vnic, 0, bp->rx_nr_rings);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to allocate VNIC");
		goto out;
	}

	rc = bnxt_hwrm_vnic_set_tpa(bp, vnic, bp->flags & BNXT_FLAG_TPA);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to setup TPA");
		goto out;
	}
#ifndef HAVE_NEW_RSSCTX_INTERFACE
modify_context:
	bnxt_modify_rss(bp, rss_ctx, rss_ctx, rxfh);
	if (modify)
		return bnxt_hwrm_vnic_rss_cfg_p5(bp, vnic);
#endif

	rc = __bnxt_setup_vnic_p5(bp, vnic);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to setup TPA");
		goto out;
	}
#ifndef HAVE_NEW_RSSCTX_INTERFACE
	bit_id = bitmap_find_free_region(bp->rss_ctx_bmap,
					 BNXT_RSS_CTX_BMAP_LEN, 0);
	if (bit_id < 0) {
		rc = -ENOMEM;
		goto out;
	}
	rss_ctx->index = (u16)bit_id;
	*rss_context = rss_ctx->index;
#else
	rss_ctx->index = rxfh->rss_context;
#endif
	return 0;
out:
	bnxt_del_one_rss_ctx(bp, rss_ctx, true, false);
	return rc;
}

#ifdef HAVE_NEW_RSSCTX_INTERFACE
static int bnxt_modify_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_rss_ctx *rss_ctx;
	int rc;

	rc = bnxt_rxfh_context_check(bp, extack);
	if (rc)
		return rc;

	rss_ctx = ethtool_rxfh_context_priv(ctx);

	bnxt_modify_rss(bp, ctx, rss_ctx, rxfh);

	return bnxt_hwrm_vnic_rss_cfg_p5(bp, &rss_ctx->vnic);
}

static int bnxt_remove_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    u32 rss_context,
				    struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_rss_ctx *rss_ctx;

	rss_ctx = ethtool_rxfh_context_priv(ctx);

	bnxt_del_one_rss_ctx(bp, rss_ctx, true, false);
	return 0;
}
#endif

static int bnxt_set_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh,
			 struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	bool skip_key = false;
	int rc = 0;

	/* Check HW cap and cache hash func details */
	switch (rxfh->hfunc) {
	case ETH_RSS_HASH_XOR:
		if (!(bp->rss_cap & BNXT_RSS_CAP_XOR_CAP))
			return -EOPNOTSUPP;
		/* hkey not needed in XOR mode */
		skip_key = true;
		break;
	case ETH_RSS_HASH_TOP:
		if (!(bp->rss_cap & BNXT_RSS_CAP_TOEPLITZ_CAP))
			return -EOPNOTSUPP;
		break;
	case ETH_RSS_HASH_CRC32:
		/* default keys/indir */
		if (!(bp->rss_cap & BNXT_RSS_CAP_TOEPLITZ_CHKSM_CAP))
			return -EOPNOTSUPP;
		skip_key = true;
		break;
	case ETH_RSS_HASH_NO_CHANGE:
		break;
	default:
		return -EOPNOTSUPP;
	}
#ifndef HAVE_NEW_RSSCTX_INTERFACE
	if (rxfh->rss_context)
		return bnxt_set_rxfh_context(bp, rxfh, extack);
#endif
	/* Repeat of same hfunc with no key or weight */
	if (bp->rss_hfunc == rxfh->hfunc && !rxfh->key && !rxfh->indir)
		return -EINVAL;

	/* for xor and crc32 block hkey config */
	if (rxfh->key && skip_key)
		return -EINVAL;

	bnxt_modify_rss(bp, NULL, NULL, rxfh);

	bp->rss_hfunc = rxfh->hfunc;
	bnxt_clear_usr_fltrs(bp, false);
	if (netif_running(bp->dev)) {
		bnxt_close_nic(bp, false, false);
		rc = bnxt_open_nic(bp, false, false);
	}
	return rc;
}
#endif /* HAVE_ETHTOOL_RXFH_PARAM */

static void bnxt_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct bnxt *bp = netdev_priv(dev);

	strscpy(info->driver, DRV_MODULE_NAME, sizeof(info->driver));
	strscpy(info->version, DRV_MODULE_VERSION, sizeof(info->version));
	strscpy(info->fw_version, bp->fw_ver_str, sizeof(info->fw_version));
	strscpy(info->bus_info, pci_name(bp->pdev), sizeof(info->bus_info));
	info->n_stats = bnxt_get_num_stats(bp);
	info->testinfo_len = bp->num_tests;
	/* TODO CHIMP_FW: eeprom dump details */
	info->eedump_len = 0;
	/* TODO CHIMP FW: reg dump details */
	info->regdump_len = 0;
}

static int bnxt_get_regs_len(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);
	int reg_len;

	if (!BNXT_PF(bp))
		return -EOPNOTSUPP;

	reg_len = BNXT_PXP_REG_LEN;

	if (bp->fw_cap & BNXT_FW_CAP_PCIE_STATS_SUPPORTED)
		reg_len += sizeof(struct pcie_ctx_hw_stats);

	return reg_len;
}

static void bnxt_get_regs(struct net_device *dev, struct ethtool_regs *regs,
			  void *_p)
{
	struct pcie_ctx_hw_stats *hw_pcie_stats;
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_pcie_qstats_input *req;
	dma_addr_t hw_pcie_stats_addr;
	int rc;

	regs->version = 0;
	if (!(bp->fw_dbg_cap & DBG_QCAPS_RESP_FLAGS_REG_ACCESS_RESTRICTED))
		bnxt_dbg_hwrm_rd_reg(bp, 0, BNXT_PXP_REG_LEN / 4, _p);

	if (!(bp->fw_cap & BNXT_FW_CAP_PCIE_STATS_SUPPORTED))
		return;

	if (hwrm_req_init(bp, req, HWRM_PCIE_QSTATS))
		return;

	hw_pcie_stats = hwrm_req_dma_slice(bp, req, sizeof(*hw_pcie_stats),
					   &hw_pcie_stats_addr);
	if (!hw_pcie_stats) {
		hwrm_req_drop(bp, req);
		return;
	}

	regs->version = 1;
	hwrm_req_hold(bp, req); /* hold on to slice */
	req->pcie_stat_size = cpu_to_le16(sizeof(*hw_pcie_stats));
	req->pcie_stat_host_addr = cpu_to_le64(hw_pcie_stats_addr);
	rc = hwrm_req_send(bp, req);
	if (!rc) {
		__le64 *src = (__le64 *)hw_pcie_stats;
		u64 *dst = (u64 *)(_p + BNXT_PXP_REG_LEN);
		int i;

		for (i = 0; i < sizeof(*hw_pcie_stats) / sizeof(__le64); i++)
			dst[i] = le64_to_cpu(src[i]);
	}
	hwrm_req_drop(bp, req);
}

static void bnxt_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bnxt *bp = netdev_priv(dev);

	wol->supported = 0;
	wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
	if (bp->flags & BNXT_FLAG_WOL_CAP) {
		wol->supported = WAKE_MAGIC;
		if (bp->wol)
			wol->wolopts = WAKE_MAGIC;
	}
}

static int bnxt_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bnxt *bp = netdev_priv(dev);

	if (wol->wolopts & ~WAKE_MAGIC)
		return -EINVAL;

	if (wol->wolopts & WAKE_MAGIC) {
		if (!(bp->flags & BNXT_FLAG_WOL_CAP))
			return -EINVAL;
		if (!bp->wol) {
			if (bnxt_hwrm_alloc_wol_fltr(bp))
				return -EBUSY;
			bp->wol = 1;
		}
	} else {
		if (bp->wol) {
			if (bnxt_hwrm_free_wol_fltr(bp))
				return -EBUSY;
			bp->wol = 0;
		}
	}
	return 0;
}

#ifdef HAVE_ETHTOOL_KEEE
/* TODO: support 25GB, 40GB, 50GB with different cable type */
void _bnxt_fw_to_linkmode(unsigned long *mode, u16 fw_speeds)
{
	linkmode_zero(mode);

	if (fw_speeds & BNXT_LINK_SPEED_MSK_100MB)
		linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, mode);
	if (fw_speeds & BNXT_LINK_SPEED_MSK_1GB)
		linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, mode);
	if (fw_speeds & BNXT_LINK_SPEED_MSK_2_5GB)
		linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT, mode);
	if (fw_speeds & BNXT_LINK_SPEED_MSK_10GB)
		linkmode_set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, mode);
	if (fw_speeds & BNXT_LINK_SPEED_MSK_40GB)
		linkmode_set_bit(ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT, mode);
}
#endif

enum bnxt_media_type {
	BNXT_MEDIA_UNKNOWN = 0,
	BNXT_MEDIA_TP,
	BNXT_MEDIA_CR,
	BNXT_MEDIA_SR,
	BNXT_MEDIA_LR_ER_FR,
	BNXT_MEDIA_KR,
	BNXT_MEDIA_KX,
	BNXT_MEDIA_X,
	__BNXT_MEDIA_END,
};

static const enum bnxt_media_type bnxt_phy_types[] = {
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASECR] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASEKR4] =  BNXT_MEDIA_KR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASELR] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASESR] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASEKR2] = BNXT_MEDIA_KR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASEKX] = BNXT_MEDIA_KX,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASEKR] = BNXT_MEDIA_KR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASET] = BNXT_MEDIA_TP,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_BASETE] = BNXT_MEDIA_TP,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_25G_BASECR_CA_L] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_25G_BASECR_CA_S] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_25G_BASECR_CA_N] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_25G_BASESR] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASECR4] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASESR4] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASELR4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASEER4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASESR10] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_40G_BASECR4] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_40G_BASESR4] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_40G_BASELR4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_40G_BASEER4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_40G_ACTIVE_CABLE] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_1G_BASET] = BNXT_MEDIA_TP,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_1G_BASESX] = BNXT_MEDIA_X,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_1G_BASECX] = BNXT_MEDIA_X,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASECR4] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASESR4] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASELR4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASEER4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_50G_BASECR] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_50G_BASESR] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_50G_BASELR] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_50G_BASEER] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASECR2] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASESR2] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASELR2] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASEER2] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASECR] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASESR] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASELR] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_100G_BASEER] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASECR2] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASESR2] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASELR2] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_200G_BASEER2] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASECR8] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASESR8] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASELR8] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASEER8] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASECR4] = BNXT_MEDIA_CR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASESR4] = BNXT_MEDIA_SR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASELR4] = BNXT_MEDIA_LR_ER_FR,
	[PORT_PHY_QCFG_RESP_PHY_TYPE_400G_BASEER4] = BNXT_MEDIA_LR_ER_FR,
};

static enum bnxt_media_type
bnxt_get_media(struct bnxt_link_info *link_info)
{
	switch (link_info->media_type) {
	case PORT_PHY_QCFG_RESP_MEDIA_TYPE_TP:
		return BNXT_MEDIA_TP;
	case PORT_PHY_QCFG_RESP_MEDIA_TYPE_DAC:
		return BNXT_MEDIA_CR;
	default:
		if (link_info->phy_type < ARRAY_SIZE(bnxt_phy_types))
			return bnxt_phy_types[link_info->phy_type];
		return BNXT_MEDIA_UNKNOWN;
	}
}

enum bnxt_link_speed_indices {
	BNXT_LINK_SPEED_UNKNOWN = 0,
	BNXT_LINK_SPEED_100MB_IDX,
	BNXT_LINK_SPEED_1GB_IDX,
	BNXT_LINK_SPEED_10GB_IDX,
	BNXT_LINK_SPEED_25GB_IDX,
	BNXT_LINK_SPEED_40GB_IDX,
	BNXT_LINK_SPEED_50GB_IDX,
	BNXT_LINK_SPEED_100GB_IDX,
	BNXT_LINK_SPEED_200GB_IDX,
	BNXT_LINK_SPEED_400GB_IDX,
	__BNXT_LINK_SPEED_END
};

static enum bnxt_link_speed_indices bnxt_fw_speed_idx(u16 speed)
{
	switch (speed) {
	case BNXT_LINK_SPEED_100MB: return BNXT_LINK_SPEED_100MB_IDX;
	case BNXT_LINK_SPEED_1GB: return BNXT_LINK_SPEED_1GB_IDX;
	case BNXT_LINK_SPEED_10GB: return BNXT_LINK_SPEED_10GB_IDX;
	case BNXT_LINK_SPEED_25GB: return BNXT_LINK_SPEED_25GB_IDX;
	case BNXT_LINK_SPEED_40GB: return BNXT_LINK_SPEED_40GB_IDX;
	case BNXT_LINK_SPEED_50GB:
	case BNXT_LINK_SPEED_50GB_PAM4:
		return BNXT_LINK_SPEED_50GB_IDX;
	case BNXT_LINK_SPEED_100GB:
	case BNXT_LINK_SPEED_100GB_PAM4:
	case BNXT_LINK_SPEED_100GB_PAM4_112:
		return BNXT_LINK_SPEED_100GB_IDX;
	case BNXT_LINK_SPEED_200GB:
	case BNXT_LINK_SPEED_200GB_PAM4:
	case BNXT_LINK_SPEED_200GB_PAM4_112:
		return BNXT_LINK_SPEED_200GB_IDX;
	case BNXT_LINK_SPEED_400GB:
	case BNXT_LINK_SPEED_400GB_PAM4:
	case BNXT_LINK_SPEED_400GB_PAM4_112:
		return BNXT_LINK_SPEED_400GB_IDX;
	default: return BNXT_LINK_SPEED_UNKNOWN;
	}
}

static const enum ethtool_link_mode_bit_indices
bnxt_link_modes[__BNXT_LINK_SPEED_END][BNXT_SIG_MODE_MAX][__BNXT_MEDIA_END] = {
	[BNXT_LINK_SPEED_100MB_IDX] = {
		{
			[BNXT_MEDIA_TP] = ETHTOOL_LINK_MODE_100baseT_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_1GB_IDX] = {
		{
			[BNXT_MEDIA_TP] = ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
			/* historically baseT, but DAC is more correctly baseX */
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_1000baseX_Full_BIT,
			[BNXT_MEDIA_KX] = ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
			[BNXT_MEDIA_X] = ETHTOOL_LINK_MODE_1000baseX_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_10GB_IDX] = {
		{
			[BNXT_MEDIA_TP] = ETHTOOL_LINK_MODE_10000baseT_Full_BIT,
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
			[BNXT_MEDIA_KX] = ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_25GB_IDX] = {
		{
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_40GB_IDX] = {
		{
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_50GB_IDX] = {
		[BNXT_SIG_MODE_NRZ] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,
		},
		[BNXT_SIG_MODE_PAM4] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_100GB_IDX] = {
		[BNXT_SIG_MODE_NRZ] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,
		},
		[BNXT_SIG_MODE_PAM4] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT,
		},
		[BNXT_SIG_MODE_PAM4_112] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_100000baseCR_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_100000baseSR_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_100000baseKR_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_200GB_IDX] = {
		[BNXT_SIG_MODE_PAM4] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT,
		},
		[BNXT_SIG_MODE_PAM4_112] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT,
		},
	},
	[BNXT_LINK_SPEED_400GB_IDX] = {
		[BNXT_SIG_MODE_PAM4] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT,
		},
		[BNXT_SIG_MODE_PAM4_112] = {
			[BNXT_MEDIA_CR] = ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT,
			[BNXT_MEDIA_KR] = ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT,
			[BNXT_MEDIA_SR] = ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT,
			[BNXT_MEDIA_LR_ER_FR] = ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT,
		},
	},
};

#define BNXT_LINK_MODE_UNKNOWN -1
static enum ethtool_link_mode_bit_indices
bnxt_get_link_mode(struct bnxt_link_info *link_info)
{
	enum ethtool_link_mode_bit_indices link_mode;
	enum bnxt_link_speed_indices speed;
	enum bnxt_media_type media;
	u8 sig_mode;

	if (link_info->phy_link_status != BNXT_LINK_LINK)
		return BNXT_LINK_MODE_UNKNOWN;

	media = bnxt_get_media(link_info);
	if (BNXT_AUTO_MODE(link_info->auto_mode)) {
		speed = bnxt_fw_speed_idx(link_info->link_speed);
		sig_mode = link_info->active_fec_sig_mode &
			PORT_PHY_QCFG_RESP_SIGNAL_MODE_MASK;
	} else {
		speed = bnxt_fw_speed_idx(link_info->req_link_speed);
		sig_mode = link_info->req_signal_mode;
	}
	if (sig_mode >= BNXT_SIG_MODE_MAX)
		return BNXT_LINK_MODE_UNKNOWN;

	/* Note ETHTOOL_LINK_MODE_10baseT_Half_BIT == 0 is a legal Linux
	 * link mode, but since no such devices exist, the zeroes in the
	 * map can be conveniently used to represent unknown link modes.
	 */
	link_mode = bnxt_link_modes[speed][sig_mode][media];
	if (!link_mode)
		return BNXT_LINK_MODE_UNKNOWN;

	switch (link_mode) {
	case ETHTOOL_LINK_MODE_100baseT_Full_BIT:
		if (~link_info->duplex & BNXT_LINK_DUPLEX_FULL)
			link_mode = ETHTOOL_LINK_MODE_100baseT_Half_BIT;
		break;
	case ETHTOOL_LINK_MODE_1000baseT_Full_BIT:
		if (~link_info->duplex & BNXT_LINK_DUPLEX_FULL)
			link_mode = ETHTOOL_LINK_MODE_1000baseT_Half_BIT;
		break;
	default:
		break;
	}

	return link_mode;
}

static void bnxt_get_ethtool_modes(struct bnxt_link_info *link_info,
				   struct ethtool_link_ksettings *lk_ksettings)
{
	struct bnxt *bp = container_of(link_info, struct bnxt, link_info);

	if (!(bp->phy_flags & BNXT_PHY_FL_NO_PAUSE)) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				 lk_ksettings->link_modes.supported);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				 lk_ksettings->link_modes.supported);
	}

	if (link_info->support_auto_speeds || link_info->support_auto_speeds2 ||
	    link_info->support_pam4_auto_speeds)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT,
				 lk_ksettings->link_modes.supported);

	if (~link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL)
		return;

	if (link_info->auto_pause_setting & BNXT_LINK_PAUSE_RX)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				 lk_ksettings->link_modes.advertising);
	if (hweight8(link_info->auto_pause_setting & BNXT_LINK_PAUSE_BOTH) == 1)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				 lk_ksettings->link_modes.advertising);
	if (link_info->lp_pause & BNXT_LINK_PAUSE_RX)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				 lk_ksettings->link_modes.lp_advertising);
	if (hweight8(link_info->lp_pause & BNXT_LINK_PAUSE_BOTH) == 1)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				 lk_ksettings->link_modes.lp_advertising);
}

static const u16 bnxt_nrz_speed_masks[] = {
	[BNXT_LINK_SPEED_100MB_IDX] = BNXT_LINK_SPEED_MSK_100MB,
	[BNXT_LINK_SPEED_1GB_IDX] = BNXT_LINK_SPEED_MSK_1GB,
	[BNXT_LINK_SPEED_10GB_IDX] = BNXT_LINK_SPEED_MSK_10GB,
	[BNXT_LINK_SPEED_25GB_IDX] = BNXT_LINK_SPEED_MSK_25GB,
	[BNXT_LINK_SPEED_40GB_IDX] = BNXT_LINK_SPEED_MSK_40GB,
	[BNXT_LINK_SPEED_50GB_IDX] = BNXT_LINK_SPEED_MSK_50GB,
	[BNXT_LINK_SPEED_100GB_IDX] = BNXT_LINK_SPEED_MSK_100GB,
	[__BNXT_LINK_SPEED_END - 1] = 0 /* make any legal speed a valid index */
};

static const u16 bnxt_pam4_speed_masks[] = {
	[BNXT_LINK_SPEED_50GB_IDX] = BNXT_LINK_PAM4_SPEED_MSK_50GB,
	[BNXT_LINK_SPEED_100GB_IDX] = BNXT_LINK_PAM4_SPEED_MSK_100GB,
	[BNXT_LINK_SPEED_200GB_IDX] = BNXT_LINK_PAM4_SPEED_MSK_200GB,
	[__BNXT_LINK_SPEED_END - 1] = 0 /* make any legal speed a valid index */
};

static const u16 bnxt_nrz_speeds2_masks[] = {
	[BNXT_LINK_SPEED_1GB_IDX] = BNXT_LINK_SPEEDS2_MSK_1GB,
	[BNXT_LINK_SPEED_10GB_IDX] = BNXT_LINK_SPEEDS2_MSK_10GB,
	[BNXT_LINK_SPEED_25GB_IDX] = BNXT_LINK_SPEEDS2_MSK_25GB,
	[BNXT_LINK_SPEED_40GB_IDX] = BNXT_LINK_SPEEDS2_MSK_40GB,
	[BNXT_LINK_SPEED_50GB_IDX] = BNXT_LINK_SPEEDS2_MSK_50GB,
	[BNXT_LINK_SPEED_100GB_IDX] = BNXT_LINK_SPEEDS2_MSK_100GB,
	[__BNXT_LINK_SPEED_END - 1] = 0 /* make any legal speed a valid index */
};

static const u16 bnxt_pam4_speeds2_masks[] = {
	[BNXT_LINK_SPEED_50GB_IDX] = BNXT_LINK_SPEEDS2_MSK_50GB_PAM4,
	[BNXT_LINK_SPEED_100GB_IDX] = BNXT_LINK_SPEEDS2_MSK_100GB_PAM4,
	[BNXT_LINK_SPEED_200GB_IDX] = BNXT_LINK_SPEEDS2_MSK_200GB_PAM4,
	[BNXT_LINK_SPEED_400GB_IDX] = BNXT_LINK_SPEEDS2_MSK_400GB_PAM4,
};

static const u16 bnxt_pam4_112_speeds2_masks[] = {
	[BNXT_LINK_SPEED_100GB_IDX] = BNXT_LINK_SPEEDS2_MSK_100GB_PAM4_112,
	[BNXT_LINK_SPEED_200GB_IDX] = BNXT_LINK_SPEEDS2_MSK_200GB_PAM4_112,
	[BNXT_LINK_SPEED_400GB_IDX] = BNXT_LINK_SPEEDS2_MSK_400GB_PAM4_112,
};

static enum bnxt_link_speed_indices
bnxt_encoding_speed_idx(u8 sig_mode, u16 phy_flags, u16 speed_msk)
{
	const u16 *speeds;
	int idx, len;

	switch (sig_mode) {
	case BNXT_SIG_MODE_NRZ:
		if (phy_flags & BNXT_PHY_FL_SPEEDS2) {
			speeds = bnxt_nrz_speeds2_masks;
			len = ARRAY_SIZE(bnxt_nrz_speeds2_masks);
		} else {
			speeds = bnxt_nrz_speed_masks;
			len = ARRAY_SIZE(bnxt_nrz_speed_masks);
		}
		break;
	case BNXT_SIG_MODE_PAM4:
		if (phy_flags & BNXT_PHY_FL_SPEEDS2) {
			speeds = bnxt_pam4_speeds2_masks;
			len = ARRAY_SIZE(bnxt_pam4_speeds2_masks);
		} else {
			speeds = bnxt_pam4_speed_masks;
			len = ARRAY_SIZE(bnxt_pam4_speed_masks);
		}
		break;
	case BNXT_SIG_MODE_PAM4_112:
		speeds = bnxt_pam4_112_speeds2_masks;
		len = ARRAY_SIZE(bnxt_pam4_112_speeds2_masks);
		break;
	default:
		return BNXT_LINK_SPEED_UNKNOWN;
	}

	for (idx = 0; idx < len; idx++) {
		if (speeds[idx] == speed_msk)
			return idx;
	}

	return BNXT_LINK_SPEED_UNKNOWN;
}

#define BNXT_FW_SPEED_MSK_BITS 16
static void
__bnxt_get_ethtool_speeds(unsigned long fw_mask, enum bnxt_media_type media,
			  u8 sig_mode, u16 phy_flags, unsigned long *et_mask)
{
	enum ethtool_link_mode_bit_indices link_mode;
	enum bnxt_link_speed_indices speed;
	u8 bit;

	for_each_set_bit(bit, &fw_mask, BNXT_FW_SPEED_MSK_BITS) {
		speed = bnxt_encoding_speed_idx(sig_mode, phy_flags, 1 << bit);
		if (!speed)
			continue;

		link_mode = bnxt_link_modes[speed][sig_mode][media];
		if (!link_mode)
			continue;

		linkmode_set_bit(link_mode, et_mask);
	}
}

static void
bnxt_get_ethtool_speeds(unsigned long fw_mask, enum bnxt_media_type media,
			u8 sig_mode, u16 phy_flags, unsigned long *et_mask)
{
	if (media) {
		__bnxt_get_ethtool_speeds(fw_mask, media, sig_mode, phy_flags,
					  et_mask);
		return;
	}

	/* list speeds for all media if unknown */
	for (media = 1; media < __BNXT_MEDIA_END; media++)
		__bnxt_get_ethtool_speeds(fw_mask, media, sig_mode, phy_flags,
					  et_mask);
}

static void
bnxt_get_all_ethtool_support_speeds(struct bnxt_link_info *link_info,
				    enum bnxt_media_type media,
				    struct ethtool_link_ksettings *lk_ksettings)
{
	struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
	u16 sp_nrz, sp_pam4, sp_pam4_112 = 0;
	u16 phy_flags = bp->phy_flags;

	if (phy_flags & BNXT_PHY_FL_SPEEDS2) {
		sp_nrz = link_info->support_speeds2;
		sp_pam4 = link_info->support_speeds2;
		sp_pam4_112 = link_info->support_speeds2;
	} else {
		sp_nrz = link_info->support_speeds;
		sp_pam4 = link_info->support_pam4_speeds;
	}
	bnxt_get_ethtool_speeds(sp_nrz, media, BNXT_SIG_MODE_NRZ, phy_flags,
				lk_ksettings->link_modes.supported);
	bnxt_get_ethtool_speeds(sp_pam4, media, BNXT_SIG_MODE_PAM4, phy_flags,
				lk_ksettings->link_modes.supported);
	bnxt_get_ethtool_speeds(sp_pam4_112, media, BNXT_SIG_MODE_PAM4_112,
				phy_flags, lk_ksettings->link_modes.supported);
}

static void
bnxt_get_all_ethtool_adv_speeds(struct bnxt_link_info *link_info,
				enum bnxt_media_type media,
				struct ethtool_link_ksettings *lk_ksettings)
{
	struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
	u16 sp_nrz, sp_pam4, sp_pam4_112 = 0;
	u16 phy_flags = bp->phy_flags;

	sp_nrz = link_info->advertising;
	if (phy_flags & BNXT_PHY_FL_SPEEDS2) {
		sp_pam4 = link_info->advertising;
		sp_pam4_112 = link_info->advertising;
	} else {
		sp_pam4 = link_info->advertising_pam4;
	}
	bnxt_get_ethtool_speeds(sp_nrz, media, BNXT_SIG_MODE_NRZ, phy_flags,
				lk_ksettings->link_modes.advertising);
	bnxt_get_ethtool_speeds(sp_pam4, media, BNXT_SIG_MODE_PAM4, phy_flags,
				lk_ksettings->link_modes.advertising);
	bnxt_get_ethtool_speeds(sp_pam4_112, media, BNXT_SIG_MODE_PAM4_112,
				phy_flags, lk_ksettings->link_modes.advertising);
}

static void
bnxt_get_all_ethtool_lp_speeds(struct bnxt_link_info *link_info,
			       enum bnxt_media_type media,
			       struct ethtool_link_ksettings *lk_ksettings)
{
	struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
	u16 phy_flags = bp->phy_flags;

	bnxt_get_ethtool_speeds(link_info->lp_auto_link_speeds, media,
				BNXT_SIG_MODE_NRZ, phy_flags,
				lk_ksettings->link_modes.lp_advertising);
	bnxt_get_ethtool_speeds(link_info->lp_auto_pam4_link_speeds, media,
				BNXT_SIG_MODE_PAM4, phy_flags,
				lk_ksettings->link_modes.lp_advertising);
}

static void bnxt_update_speed(u32 *delta, bool installed_media, u16 *speeds,
			      u16 speed_msk, const unsigned long *et_mask,
			      enum ethtool_link_mode_bit_indices mode)
{
	bool mode_desired = linkmode_test_bit(mode, et_mask);

	if (!mode)
		return;

	/* enabled speeds for installed media should override */
	if (installed_media && mode_desired) {
		*speeds |= speed_msk;
		*delta |= speed_msk;
		return;
	}

	/* many to one mapping, only allow one change per fw_speed bit */
	if (!(*delta & speed_msk) && (mode_desired == !(*speeds & speed_msk))) {
		*speeds ^= speed_msk;
		*delta |= speed_msk;
	}
}

static void bnxt_set_ethtool_speeds(struct bnxt_link_info *link_info,
				    const unsigned long *et_mask)
{
	struct bnxt *bp = container_of(link_info, struct bnxt, link_info);
	u16 const *sp_msks, *sp_pam4_msks, *sp_pam4_112_msks;
	enum bnxt_media_type media = bnxt_get_media(link_info);
	u16 *adv, *adv_pam4, *adv_pam4_112 = NULL;
	u32 delta_pam4_112 = 0;
	u32 delta_pam4 = 0;
	u32 delta_nrz = 0;
	int i, m;

	adv = &link_info->advertising;
	if (bp->phy_flags & BNXT_PHY_FL_SPEEDS2) {
		adv_pam4 = &link_info->advertising;
		adv_pam4_112 = &link_info->advertising;
		sp_msks = bnxt_nrz_speeds2_masks;
		sp_pam4_msks = bnxt_pam4_speeds2_masks;
		sp_pam4_112_msks = bnxt_pam4_112_speeds2_masks;
	} else {
		adv_pam4 = &link_info->advertising_pam4;
		sp_msks = bnxt_nrz_speed_masks;
		sp_pam4_msks = bnxt_pam4_speed_masks;
	}
	for (i = 1; i < __BNXT_LINK_SPEED_END; i++) {
		/* accept any legal media from user */
		for (m = 1; m < __BNXT_MEDIA_END; m++) {
			bnxt_update_speed(&delta_nrz, m == media,
					  adv, sp_msks[i], et_mask,
					  bnxt_link_modes[i][BNXT_SIG_MODE_NRZ][m]);
			bnxt_update_speed(&delta_pam4, m == media,
					  adv_pam4, sp_pam4_msks[i], et_mask,
					  bnxt_link_modes[i][BNXT_SIG_MODE_PAM4][m]);
			if (!adv_pam4_112)
				continue;

			bnxt_update_speed(&delta_pam4_112, m == media,
					  adv_pam4_112, sp_pam4_112_msks[i], et_mask,
					  bnxt_link_modes[i][BNXT_SIG_MODE_PAM4_112][m]);
		}
	}
}

static void bnxt_fw_to_ethtool_advertised_fec(struct bnxt_link_info *link_info,
				struct ethtool_link_ksettings *lk_ksettings)
{
	u16 fec_cfg = link_info->fec_cfg;

	if ((fec_cfg & BNXT_FEC_NONE) || !(fec_cfg & BNXT_FEC_AUTONEG)) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT,
				 lk_ksettings->link_modes.advertising);
		return;
	}
	if (fec_cfg & BNXT_FEC_ENC_BASE_R)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_BASER_BIT,
				 lk_ksettings->link_modes.advertising);
	if (fec_cfg & BNXT_FEC_ENC_RS)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT,
				 lk_ksettings->link_modes.advertising);
	if (fec_cfg & BNXT_FEC_ENC_LLRS)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_LLRS_BIT,
				 lk_ksettings->link_modes.advertising);
}

static void bnxt_fw_to_ethtool_support_fec(struct bnxt_link_info *link_info,
				struct ethtool_link_ksettings *lk_ksettings)
{
	u16 fec_cfg = link_info->fec_cfg;

	if (fec_cfg & BNXT_FEC_NONE) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT,
				 lk_ksettings->link_modes.supported);
		return;
	}
	if (fec_cfg & BNXT_FEC_ENC_BASE_R_CAP)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_BASER_BIT,
				 lk_ksettings->link_modes.supported);
	if (fec_cfg & BNXT_FEC_ENC_RS_CAP)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT,
				 lk_ksettings->link_modes.supported);
	if (fec_cfg & BNXT_FEC_ENC_LLRS_CAP)
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_LLRS_BIT,
				 lk_ksettings->link_modes.supported);
}

u32 bnxt_fw_to_ethtool_speed(u16 fw_link_speed)
{
	switch (fw_link_speed) {
	case BNXT_LINK_SPEED_100MB:
		return SPEED_100;
	case BNXT_LINK_SPEED_1GB:
		return SPEED_1000;
	case BNXT_LINK_SPEED_2_5GB:
		return SPEED_2500;
	case BNXT_LINK_SPEED_10GB:
		return SPEED_10000;
	case BNXT_LINK_SPEED_20GB:
		return SPEED_20000;
	case BNXT_LINK_SPEED_25GB:
		return SPEED_25000;
	case BNXT_LINK_SPEED_40GB:
		return SPEED_40000;
	case BNXT_LINK_SPEED_50GB:
	case BNXT_LINK_SPEED_50GB_PAM4:
		return SPEED_50000;
	case BNXT_LINK_SPEED_100GB:
	case BNXT_LINK_SPEED_100GB_PAM4:
	case BNXT_LINK_SPEED_100GB_PAM4_112:
		return SPEED_100000;
	case BNXT_LINK_SPEED_200GB:
	case BNXT_LINK_SPEED_200GB_PAM4:
	case BNXT_LINK_SPEED_200GB_PAM4_112:
		return SPEED_200000;
	case BNXT_LINK_SPEED_400GB:
	case BNXT_LINK_SPEED_400GB_PAM4:
	case BNXT_LINK_SPEED_400GB_PAM4_112:
		return SPEED_400000;
	default:
		return SPEED_UNKNOWN;
	}
}

static void bnxt_get_default_speeds(struct ethtool_link_ksettings *lk_ksettings,
				    struct bnxt_link_info *link_info)
{
	struct ethtool_link_settings *base = &lk_ksettings->base;

	if (link_info->link_state == BNXT_LINK_STATE_UP) {
		base->speed = bnxt_fw_to_ethtool_speed(link_info->link_speed);
		base->duplex = DUPLEX_HALF;
		if (link_info->duplex & BNXT_LINK_DUPLEX_FULL)
			base->duplex = DUPLEX_FULL;
#ifdef HAVE_ETHTOOL_A_LINKMODES_LANES
		lk_ksettings->lanes = link_info->active_lanes;
#endif
	} else if (!link_info->autoneg) {
		base->speed = bnxt_fw_to_ethtool_speed(link_info->req_link_speed);
		base->duplex = DUPLEX_HALF;
		if (link_info->req_duplex == BNXT_LINK_DUPLEX_FULL)
			base->duplex = DUPLEX_FULL;
	}
}

static int bnxt_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *lk_ksettings)
{
	struct ethtool_link_settings *base = &lk_ksettings->base;
	enum ethtool_link_mode_bit_indices link_mode;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info;
	enum bnxt_media_type media;

	ethtool_link_ksettings_zero_link_mode(lk_ksettings, lp_advertising);
	ethtool_link_ksettings_zero_link_mode(lk_ksettings, advertising);
	ethtool_link_ksettings_zero_link_mode(lk_ksettings, supported);
	base->duplex = DUPLEX_UNKNOWN;
	base->speed = SPEED_UNKNOWN;
	link_info = &bp->link_info;

	mutex_lock(&bp->link_lock);
	bnxt_get_ethtool_modes(link_info, lk_ksettings);
	media = bnxt_get_media(link_info);
	bnxt_get_all_ethtool_support_speeds(link_info, media, lk_ksettings);
	bnxt_fw_to_ethtool_support_fec(link_info, lk_ksettings);
	link_mode = bnxt_get_link_mode(link_info);
	if (link_mode != BNXT_LINK_MODE_UNKNOWN)
		ethtool_params_from_link_mode(lk_ksettings, link_mode);
	else
		bnxt_get_default_speeds(lk_ksettings, link_info);

	if (link_info->autoneg) {
		bnxt_fw_to_ethtool_advertised_fec(link_info, lk_ksettings);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT,
				 lk_ksettings->link_modes.advertising);
		base->autoneg = AUTONEG_ENABLE;
		bnxt_get_all_ethtool_adv_speeds(link_info, media, lk_ksettings);
		if (link_info->phy_link_status == BNXT_LINK_LINK)
			bnxt_get_all_ethtool_lp_speeds(link_info, media,
						       lk_ksettings);
	} else {
		base->autoneg = AUTONEG_DISABLE;
	}

	base->port = PORT_NONE;
	if (media == BNXT_MEDIA_TP) {
		base->port = PORT_TP;
		linkmode_set_bit(ETHTOOL_LINK_MODE_TP_BIT,
				 lk_ksettings->link_modes.supported);
		linkmode_set_bit(ETHTOOL_LINK_MODE_TP_BIT,
				 lk_ksettings->link_modes.advertising);
	} else if (media == BNXT_MEDIA_KR) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_Backplane_BIT,
				 lk_ksettings->link_modes.supported);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Backplane_BIT,
				 lk_ksettings->link_modes.advertising);
	} else {
		linkmode_set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT,
				 lk_ksettings->link_modes.supported);
		linkmode_set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT,
				 lk_ksettings->link_modes.advertising);

		if (media == BNXT_MEDIA_CR)
			base->port = PORT_DA;
		else
			base->port = PORT_FIBRE;
	}
	base->phy_address = link_info->phy_addr;
	mutex_unlock(&bp->link_lock);

	return 0;
}

static int
bnxt_force_link_speed(struct net_device *dev, u32 ethtool_speed, u32 lanes)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;
	u16 support_pam4_spds = link_info->support_pam4_speeds;
	u16 support_spds2 = link_info->support_speeds2;
	u16 support_spds = link_info->support_speeds;
	u8 sig_mode = BNXT_SIG_MODE_NRZ;
	u32 lanes_needed = 1;
	u16 fw_speed = 0;

	switch (ethtool_speed) {
	case SPEED_100:
		if (support_spds & BNXT_LINK_SPEED_MSK_100MB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_100MB;
		break;
	case SPEED_1000:
		if ((support_spds & BNXT_LINK_SPEED_MSK_1GB) ||
		    (support_spds2 & BNXT_LINK_SPEEDS2_MSK_1GB))
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_1GB;
		break;
	case SPEED_2500:
		if (support_spds & BNXT_LINK_SPEED_MSK_2_5GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_2_5GB;
		break;
	case SPEED_10000:
		if ((support_spds & BNXT_LINK_SPEED_MSK_10GB) ||
		    (support_spds2 & BNXT_LINK_SPEEDS2_MSK_10GB))
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_10GB;
		break;
	case SPEED_20000:
		if (support_spds & BNXT_LINK_SPEED_MSK_20GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_20GB;
			lanes_needed = 2;
		}
		break;
	case SPEED_25000:
		if ((support_spds & BNXT_LINK_SPEED_MSK_25GB) ||
		    (support_spds2 & BNXT_LINK_SPEEDS2_MSK_25GB))
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_25GB;
		break;
	case SPEED_40000:
		if ((support_spds & BNXT_LINK_SPEED_MSK_40GB) ||
		    (support_spds2 & BNXT_LINK_SPEEDS2_MSK_40GB)) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_40GB;
			lanes_needed = 4;
		}
		break;
	case SPEED_50000:
		if (((support_spds & BNXT_LINK_SPEED_MSK_50GB) ||
		     (support_spds2 & BNXT_LINK_SPEEDS2_MSK_50GB)) &&
		    lanes != 1) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_50GB;
			lanes_needed = 2;
		} else if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_50GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_50GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
		} else if (support_spds2 & BNXT_LINK_SPEEDS2_MSK_50GB_PAM4) {
			fw_speed = BNXT_LINK_SPEED_50GB_PAM4;
			sig_mode = BNXT_SIG_MODE_PAM4;
		}
		break;
	case SPEED_100000:
		if (((support_spds & BNXT_LINK_SPEED_MSK_100GB) ||
		     (support_spds2 & BNXT_LINK_SPEEDS2_MSK_100GB)) &&
		    lanes != 2 && lanes != 1) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_100GB;
			lanes_needed = 4;
		} else if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_100GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_100GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
			lanes_needed = 2;
		} else if ((support_spds2 & BNXT_LINK_SPEEDS2_MSK_100GB_PAM4) &&
			   lanes != 1) {
			fw_speed = BNXT_LINK_SPEED_100GB_PAM4;
			sig_mode = BNXT_SIG_MODE_PAM4;
			lanes_needed = 2;
		} else if (support_spds2 & BNXT_LINK_SPEEDS2_MSK_100GB_PAM4_112) {
			fw_speed = BNXT_LINK_SPEED_100GB_PAM4_112;
			sig_mode = BNXT_SIG_MODE_PAM4_112;
		}
		break;
	case SPEED_200000:
		if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_200GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_200GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
			lanes_needed = 4;
		} else if ((support_spds2 & BNXT_LINK_SPEEDS2_MSK_200GB_PAM4) &&
			   lanes != 2) {
			fw_speed = BNXT_LINK_SPEED_200GB_PAM4;
			sig_mode = BNXT_SIG_MODE_PAM4;
			lanes_needed = 4;
		} else if (support_spds2 & BNXT_LINK_SPEEDS2_MSK_200GB_PAM4_112) {
			fw_speed = BNXT_LINK_SPEED_200GB_PAM4_112;
			sig_mode = BNXT_SIG_MODE_PAM4_112;
			lanes_needed = 2;
		}
		break;
	case SPEED_400000:
		if ((support_spds2 & BNXT_LINK_SPEEDS2_MSK_400GB_PAM4) &&
		    lanes != 4) {
			fw_speed = BNXT_LINK_SPEED_400GB_PAM4;
			sig_mode = BNXT_SIG_MODE_PAM4;
			lanes_needed = 8;
		} else if (support_spds2 & BNXT_LINK_SPEEDS2_MSK_400GB_PAM4_112) {
			fw_speed = BNXT_LINK_SPEED_400GB_PAM4_112;
			sig_mode = BNXT_SIG_MODE_PAM4_112;
			lanes_needed = 4;
		}
		break;
	}

	if (!fw_speed) {
		netdev_err(dev, "unsupported speed!\n");
		return -EINVAL;
	}

	if (lanes && lanes != lanes_needed) {
		netdev_err(dev, "unsupported number of lanes for speed\n");
		return -EINVAL;
	}

	if (link_info->req_link_speed == fw_speed &&
	    link_info->req_signal_mode == sig_mode &&
	    link_info->autoneg == 0)
		return -EALREADY;

	link_info->req_link_speed = fw_speed;
	link_info->req_signal_mode = sig_mode;
	link_info->req_duplex = BNXT_LINK_DUPLEX_FULL;
	link_info->autoneg = 0;
	link_info->advertising = 0;
	link_info->advertising_pam4 = 0;

	return 0;
}

#ifdef HAVE_ETHTOOL_KEEE
u16 bnxt_get_fw_auto_link_speeds(const unsigned long *mode)
{
	u16 fw_speed_mask = 0;

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, mode) ||
	    linkmode_test_bit(ETHTOOL_LINK_MODE_100baseT_Half_BIT, mode))
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_100MB;

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, mode) ||
	    linkmode_test_bit(ETHTOOL_LINK_MODE_1000baseT_Half_BIT, mode))
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_1GB;

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, mode))
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_10GB;

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT, mode))
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_40GB;

	return fw_speed_mask;
}
#endif /* HAVE_ETHTOOL_KEEE */

static int bnxt_set_link_ksettings(struct net_device *dev,
			   const struct ethtool_link_ksettings *lk_ksettings)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;
	const struct ethtool_link_settings *base = &lk_ksettings->base;
	bool set_pause = false;
	u32 speed, lanes = 0;
	int rc = 0;

	if (!BNXT_PHY_CFG_ABLE(bp))
		return -EOPNOTSUPP;

	mutex_lock(&bp->link_lock);
	if (base->autoneg == AUTONEG_ENABLE) {
		bnxt_set_ethtool_speeds(link_info,
					lk_ksettings->link_modes.advertising);
		link_info->autoneg |= BNXT_AUTONEG_SPEED;
		if (!link_info->advertising && !link_info->advertising_pam4) {
			link_info->advertising = link_info->support_auto_speeds;
			link_info->advertising_pam4 =
				link_info->support_pam4_auto_speeds;
		}
		/* any change to autoneg will cause link change, therefore the
		 * driver should put back the original pause setting in autoneg
		 */
		if (!(bp->phy_flags & BNXT_PHY_FL_NO_PAUSE))
			set_pause = true;
	} else {
		u8 phy_type = link_info->phy_type;

		if (phy_type == PORT_PHY_QCFG_RESP_PHY_TYPE_BASET  ||
		    phy_type == PORT_PHY_QCFG_RESP_PHY_TYPE_BASETE ||
		    link_info->media_type == PORT_PHY_QCFG_RESP_MEDIA_TYPE_TP) {

			netdev_err(dev, "10GBase-T devices must autoneg\n");
			rc = -EINVAL;
			goto set_setting_exit;
		}
		if (base->duplex == DUPLEX_HALF) {
			netdev_err(dev, "HALF DUPLEX is not supported!\n");
			rc = -EINVAL;
			goto set_setting_exit;
		}
		speed = base->speed;
#ifdef HAVE_ETHTOOL_LANES
		lanes = lk_ksettings->lanes;
#endif
		rc = bnxt_force_link_speed(dev, speed, lanes);
		if (rc) {
			if (rc == -EALREADY)
				rc = 0;
			goto set_setting_exit;
		}
	}
	if (netif_running(dev))
		rc = bnxt_hwrm_set_link_setting(bp, set_pause, false);

set_setting_exit:
	mutex_unlock(&bp->link_lock);
	return rc;
}

#ifdef ETHTOOL_GFECPARAM
static int bnxt_get_fecparam(struct net_device *dev,
			     struct ethtool_fecparam *fec)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info;
	u8 active_fec;
	u16 fec_cfg;

	link_info = &bp->link_info;
	fec_cfg = link_info->fec_cfg;
	active_fec = link_info->active_fec_sig_mode &
		     PORT_PHY_QCFG_RESP_ACTIVE_FEC_MASK;
	if (fec_cfg & BNXT_FEC_NONE) {
		fec->fec = ETHTOOL_FEC_NONE;
		fec->active_fec = ETHTOOL_FEC_NONE;
		return 0;
	}
	if (fec_cfg & BNXT_FEC_AUTONEG)
		fec->fec |= ETHTOOL_FEC_AUTO;
	if (fec_cfg & BNXT_FEC_ENC_BASE_R)
		fec->fec |= ETHTOOL_FEC_BASER;
	if (fec_cfg & BNXT_FEC_ENC_RS)
		fec->fec |= ETHTOOL_FEC_RS;
	if (fec_cfg & BNXT_FEC_ENC_LLRS)
		fec->fec |= ETHTOOL_FEC_LLRS;

	switch (active_fec) {
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_CLAUSE74_ACTIVE:
		fec->active_fec |= ETHTOOL_FEC_BASER;
		break;
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_CLAUSE91_ACTIVE:
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_RS544_1XN_ACTIVE:
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_RS544_IEEE_ACTIVE:
		fec->active_fec |= ETHTOOL_FEC_RS;
		break;
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_RS272_1XN_ACTIVE:
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_RS272_IEEE_ACTIVE:
		fec->active_fec |= ETHTOOL_FEC_LLRS;
		break;
	case PORT_PHY_QCFG_RESP_ACTIVE_FEC_FEC_NONE_ACTIVE:
		fec->active_fec |= ETHTOOL_FEC_OFF;
		break;
	}
	return 0;
}

#ifdef ETHTOOL_MAX_LANES
static void bnxt_get_fec_stats(struct net_device *dev,
			       struct ethtool_fec_stats *fec_stats)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS_EXT))
		return;

	rx = bp->rx_port_stats_ext.sw_stats;
	fec_stats->corrected_bits.total =
		*(rx + BNXT_RX_STATS_EXT_OFFSET(rx_corrected_bits));

	if (bp->fw_rx_stats_ext_size <= BNXT_RX_STATS_EXT_NUM_LEGACY)
		return;

	fec_stats->corrected_blocks.total =
		*(rx + BNXT_RX_STATS_EXT_OFFSET(rx_fec_corrected_blocks));
	fec_stats->uncorrectable_blocks.total =
		*(rx + BNXT_RX_STATS_EXT_OFFSET(rx_fec_uncorrectable_blocks));
}
#endif

static u32 bnxt_ethtool_forced_fec_to_fw(struct bnxt_link_info *link_info,
					 u32 fec)
{
	u32 fw_fec = PORT_PHY_CFG_REQ_FLAGS_FEC_AUTONEG_DISABLE;

	if (fec & ETHTOOL_FEC_BASER)
		fw_fec |= BNXT_FEC_BASE_R_ON(link_info);
	else if (fec & ETHTOOL_FEC_RS)
		fw_fec |= BNXT_FEC_RS_ON(link_info);
	else if (fec & ETHTOOL_FEC_LLRS)
		fw_fec |= BNXT_FEC_LLRS_ON;
	return fw_fec;
}

static int bnxt_set_fecparam(struct net_device *dev,
			     struct ethtool_fecparam *fecparam)
{
	struct hwrm_port_phy_cfg_input *req;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info;
	u32 new_cfg, fec = fecparam->fec;
	u16 fec_cfg;
	int rc;

	link_info = &bp->link_info;
	fec_cfg = link_info->fec_cfg;
	if (fec_cfg & BNXT_FEC_NONE)
		return -EOPNOTSUPP;

	if (fec & ETHTOOL_FEC_OFF) {
		new_cfg = PORT_PHY_CFG_REQ_FLAGS_FEC_AUTONEG_DISABLE |
			  BNXT_FEC_ALL_OFF(link_info);
		goto apply_fec;
	}
	if (((fec & ETHTOOL_FEC_AUTO) && !(fec_cfg & BNXT_FEC_AUTONEG_CAP)) ||
	    ((fec & ETHTOOL_FEC_RS) && !(fec_cfg & BNXT_FEC_ENC_RS_CAP)) ||
	    ((fec & ETHTOOL_FEC_LLRS) && !(fec_cfg & BNXT_FEC_ENC_LLRS_CAP)) ||
	    ((fec & ETHTOOL_FEC_BASER) && !(fec_cfg & BNXT_FEC_ENC_BASE_R_CAP)))
		return -EINVAL;

	if (fec & ETHTOOL_FEC_AUTO) {
		if (!link_info->autoneg)
			return -EINVAL;
		new_cfg = PORT_PHY_CFG_REQ_FLAGS_FEC_AUTONEG_ENABLE;
	} else {
		new_cfg = bnxt_ethtool_forced_fec_to_fw(link_info, fec);
	}

apply_fec:
	rc = hwrm_req_init(bp, req, HWRM_PORT_PHY_CFG);
	if (rc)
		return rc;
	req->flags = cpu_to_le32(new_cfg | PORT_PHY_CFG_REQ_FLAGS_RESET_PHY);
	rc = hwrm_req_send(bp, req);
	/* update current settings */
	if (!rc) {
		mutex_lock(&bp->link_lock);
		bnxt_update_link(bp, false);
		mutex_unlock(&bp->link_lock);
	}
	return rc;
}
#endif

static void bnxt_get_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *epause)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;

	if (BNXT_VF(bp))
		return;
	epause->autoneg = !!(link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL);
	epause->rx_pause = !!(link_info->req_flow_ctrl & BNXT_LINK_PAUSE_RX);
	epause->tx_pause = !!(link_info->req_flow_ctrl & BNXT_LINK_PAUSE_TX);
}

#ifdef HAVE_GET_PAUSE_STATS
static void bnxt_get_pause_stats(struct net_device *dev,
				 struct ethtool_pause_stats *epstat)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx, *tx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS))
		return;

	rx = bp->port_stats.sw_stats;
	tx = bp->port_stats.sw_stats + BNXT_TX_PORT_STATS_BYTE_OFFSET / 8;

	epstat->rx_pause_frames = BNXT_GET_RX_PORT_STATS64(rx, rx_pause_frames);
	epstat->tx_pause_frames = BNXT_GET_TX_PORT_STATS64(tx, tx_pause_frames);
}
#endif /* HAVE_GET_PAUSE_STATS */

static int bnxt_set_pauseparam(struct net_device *dev,
			       struct ethtool_pauseparam *epause)
{
	int rc = 0;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;

	if (!BNXT_PHY_CFG_ABLE(bp) || (bp->phy_flags & BNXT_PHY_FL_NO_PAUSE))
		return -EOPNOTSUPP;

	mutex_lock(&bp->link_lock);
	if (epause->autoneg) {
		if (!(link_info->autoneg & BNXT_AUTONEG_SPEED)) {
			rc = -EINVAL;
			goto pause_exit;
		}

		link_info->autoneg |= BNXT_AUTONEG_FLOW_CTRL;
		link_info->req_flow_ctrl = 0;
	} else {
		/* when transition from auto pause to force pause,
		 * force a link change
		 */
		if (link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL)
			link_info->force_link_chng = true;
		link_info->autoneg &= ~BNXT_AUTONEG_FLOW_CTRL;
		link_info->req_flow_ctrl = 0;
	}
	if (epause->rx_pause)
		link_info->req_flow_ctrl |= BNXT_LINK_PAUSE_RX;

	if (epause->tx_pause)
		link_info->req_flow_ctrl |= BNXT_LINK_PAUSE_TX;

	if (netif_running(dev))
		rc = bnxt_hwrm_set_pause(bp);

pause_exit:
	mutex_unlock(&bp->link_lock);
	return rc;
}

static u32 bnxt_get_link(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	/* TODO: handle MF, VF, driver close case */
	return BNXT_LINK_IS_UP(bp);
}

int bnxt_hwrm_fw_sync(struct bnxt *bp, u16 fw_status)
{
	struct hwrm_fw_sync_output *resp;
	struct hwrm_fw_sync_input *req;
	u32 sync_action, sync_status;
	int rc;

	if (!BNXT_CHIP_P5_PLUS(bp))
		return 0;

	rc = hwrm_req_init(bp, req, HWRM_FW_SYNC);
	if (rc)
		return rc;

	hwrm_req_timeout(bp, req, FW_SYNC_TIMEOUT);

	sync_action = FW_SYNC_REQ_SYNC_ACTION_ACTION;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_SBI_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_SBI;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_SRT_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_SRT;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_CRT_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_CRT;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_CFG_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_CFG;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_FRU_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_FRU;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_DIR_HDR_MISMATCH)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_SYNC_DIR_HDR;
	if (fw_status & FW_HEALTH_CHECK_RESP_FW_STATUS_MBR_CORRUPT)
		sync_action |= FW_SYNC_REQ_SYNC_ACTION_WRITE_MBR;

	req->sync_action = cpu_to_le32(sync_action);

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc) {
		sync_status = le32_to_cpu(resp->sync_status);
		if (sync_status &
		    (FW_SYNC_RESP_SYNC_STATUS_ERR_CODE_GENERAL | FW_SYNC_RESP_SYNC_STATUS_SYNC_ERR))
			rc = -EIO;
	}

	hwrm_req_drop(bp, req);
	return rc;
}

int bnxt_hwrm_get_fw_sync_status(struct bnxt *bp, u16 *fw_status)
{
	struct hwrm_fw_health_check_output *resp;
	struct hwrm_fw_health_check_input *req;
	int rc;

	if (!BNXT_CHIP_P5_PLUS(bp))
		return 0;

	rc = hwrm_req_init(bp, req, HWRM_FW_HEALTH_CHECK);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		*fw_status = le16_to_cpu(resp->fw_status);

	hwrm_req_drop(bp, req);
	return rc;
}

#define BNXT_FW_SYNC_STATUS_MISMATCH	(FW_HEALTH_CHECK_RESP_FW_STATUS_SBI_MISMATCH |	\
					 FW_HEALTH_CHECK_RESP_FW_STATUS_SRT_MISMATCH |	\
					 FW_HEALTH_CHECK_RESP_FW_STATUS_CRT_MISMATCH |	\
					 FW_HEALTH_CHECK_RESP_FW_STATUS_DIR_HDR_MISMATCH | \
					 FW_HEALTH_CHECK_RESP_FW_STATUS_MBR_CORRUPT |	\
					 FW_HEALTH_CHECK_RESP_FW_STATUS_CFG_MISMATCH |	\
					 FW_HEALTH_CHECK_RESP_FW_STATUS_FRU_MISMATCH)

int bnxt_sync_firmware(struct bnxt *bp)
{
	u16 fw_status = 0;
	int rc;

	if (!BNXT_CHIP_P5_PLUS(bp))
		return 0;

	rc = bnxt_hwrm_get_fw_sync_status(bp, &fw_status);
	if (rc)
		return rc;

	if (fw_status & BNXT_FW_SYNC_STATUS_MISMATCH)
		rc = bnxt_hwrm_fw_sync(bp, fw_status);

	return rc;
}

int bnxt_hwrm_nvm_get_dev_info(struct bnxt *bp,
			       struct hwrm_nvm_get_dev_info_output *nvm_dev_info)
{
	struct hwrm_nvm_get_dev_info_output *resp;
	struct hwrm_nvm_get_dev_info_input *req;
	int rc;

	if (BNXT_VF(bp))
		return -EOPNOTSUPP;

	rc = hwrm_req_init(bp, req, HWRM_NVM_GET_DEV_INFO);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		memcpy(nvm_dev_info, resp, sizeof(struct hwrm_nvm_get_dev_info_output));
	hwrm_req_drop(bp, req);
	return rc;
}

static void bnxt_print_admin_err(struct bnxt *bp)
{
	netdev_info(bp->dev, "PF does not have admin privileges to flash the device\n");
}

int bnxt_find_nvram_item(struct net_device *dev, u16 type, u16 ordinal,
			 u16 ext, u16 *index, u32 *item_length,
			 u32 *data_length);

int bnxt_flash_nvram(struct net_device *dev, u16 dir_type,
		     u16 dir_ordinal, u16 dir_ext, u16 dir_attr,
		     u32 dir_item_len, const u8 *data,
		     size_t data_len)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_nvm_write_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_NVM_WRITE);
	if (rc)
		return rc;

	if (data_len && data) {
		dma_addr_t dma_handle;
		u8 *kmem;

		kmem = hwrm_req_dma_slice(bp, req, data_len, &dma_handle);
		if (!kmem) {
			hwrm_req_drop(bp, req);
			return -ENOMEM;
		}

		req->dir_data_length = cpu_to_le32(data_len);

		memcpy(kmem, data, data_len);
		req->host_src_addr = cpu_to_le64(dma_handle);
	}

	hwrm_req_timeout(bp, req, FLASH_NVRAM_TIMEOUT);
	req->dir_type = cpu_to_le16(dir_type);
	req->dir_ordinal = cpu_to_le16(dir_ordinal);
	req->dir_ext = cpu_to_le16(dir_ext);
	req->dir_attr = cpu_to_le16(dir_attr);
	req->dir_item_length = cpu_to_le32(dir_item_len);
	rc = hwrm_req_send(bp, req);

	if (rc == -EACCES)
		bnxt_print_admin_err(bp);
	return rc;
}

int bnxt_hwrm_firmware_reset(struct net_device *dev, u8 proc_type,
			     u8 self_reset, u8 flags)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_fw_reset_input *req;
	int rc;

	if (!bnxt_hwrm_reset_permitted(bp)) {
		netdev_warn(bp->dev, "Reset denied by firmware, it may be inhibited by remote driver");
		return -EPERM;
	}

	rc = hwrm_req_init(bp, req, HWRM_FW_RESET);
	if (rc)
		return rc;

	req->embedded_proc_type = proc_type;
	req->selfrst_status = self_reset;
	req->flags = flags;

	if (proc_type == FW_RESET_REQ_EMBEDDED_PROC_TYPE_AP) {
		rc = hwrm_req_send_silent(bp, req);
	} else {
		rc = hwrm_req_send(bp, req);
		if (rc == -EACCES)
			bnxt_print_admin_err(bp);
	}
	return rc;
}

static int bnxt_firmware_reset(struct net_device *dev,
			       enum bnxt_nvm_directory_type dir_type)
{
	u8 self_reset = FW_RESET_REQ_SELFRST_STATUS_SELFRSTNONE;
	u8 proc_type;

	/* TODO: Address self-reset of APE/KONG/BONO/TANG or ungraceful reset */
	/*       (e.g. when firmware isn't already running) */
	switch (dir_type) {
	case BNX_DIR_TYPE_CHIMP_PATCH:
	case BNX_DIR_TYPE_BOOTCODE:
	case BNX_DIR_TYPE_BOOTCODE_2:
		proc_type = FW_RESET_REQ_EMBEDDED_PROC_TYPE_BOOT;
		/* Self-reset ChiMP upon next PCIe reset: */
		self_reset = FW_RESET_REQ_SELFRST_STATUS_SELFRSTPCIERST;
		break;
	case BNX_DIR_TYPE_APE_FW:
	case BNX_DIR_TYPE_APE_PATCH:
		proc_type = FW_RESET_REQ_EMBEDDED_PROC_TYPE_MGMT;
		/* Self-reset APE upon next PCIe reset: */
		self_reset = FW_RESET_REQ_SELFRST_STATUS_SELFRSTPCIERST;
		break;
	case BNX_DIR_TYPE_KONG_FW:
	case BNX_DIR_TYPE_KONG_PATCH:
		proc_type = FW_RESET_REQ_EMBEDDED_PROC_TYPE_NETCTRL;
		break;
	case BNX_DIR_TYPE_BONO_FW:
	case BNX_DIR_TYPE_BONO_PATCH:
		proc_type = FW_RESET_REQ_EMBEDDED_PROC_TYPE_ROCE;
		break;
	default:
		return -EINVAL;
	}

	return bnxt_hwrm_firmware_reset(dev, proc_type, self_reset, 0);
}

static int __bnxt_firmware_reset_chip(struct net_device *dev, u8 flags)
{
	return bnxt_hwrm_firmware_reset(dev,
					FW_RESET_REQ_EMBEDDED_PROC_TYPE_CHIP,
					FW_RESET_REQ_SELFRST_STATUS_SELFRSTASAP,
					flags);
}

int bnxt_firmware_reset_chip(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);
	u8 flags = 0;

	if (bp->fw_cap & BNXT_FW_CAP_HOT_RESET)
		flags = FW_RESET_REQ_FLAGS_RESET_GRACEFUL;

	return __bnxt_firmware_reset_chip(dev, flags);
}

int bnxt_firmware_reset_ap(struct net_device *dev)
{
	return bnxt_hwrm_firmware_reset(dev, FW_RESET_REQ_EMBEDDED_PROC_TYPE_AP,
					FW_RESET_REQ_SELFRST_STATUS_SELFRSTNONE,
					0);
}

static int bnxt_flash_firmware(struct net_device *dev,
			       u16 dir_type,
			       const u8 *fw_data,
			       size_t fw_size)
{
	int	rc = 0;
	u16	code_type;
	u32	stored_crc;
	u32	calculated_crc;
	struct bnxt_fw_header *header = (struct bnxt_fw_header *)fw_data;

	switch (dir_type) {
	case BNX_DIR_TYPE_BOOTCODE:
	case BNX_DIR_TYPE_BOOTCODE_2:
		code_type = CODE_BOOT;
		break;
	case BNX_DIR_TYPE_CHIMP_PATCH:
		code_type = CODE_CHIMP_PATCH;
		break;
	case BNX_DIR_TYPE_APE_FW:
		code_type = CODE_MCTP_PASSTHRU;
		break;
	case BNX_DIR_TYPE_APE_PATCH:
		code_type = CODE_APE_PATCH;
		break;
	case BNX_DIR_TYPE_KONG_FW:
		code_type = CODE_KONG_FW;
		break;
	case BNX_DIR_TYPE_KONG_PATCH:
		code_type = CODE_KONG_PATCH;
		break;
	case BNX_DIR_TYPE_BONO_FW:
		code_type = CODE_BONO_FW;
		break;
	case BNX_DIR_TYPE_BONO_PATCH:
		code_type = CODE_BONO_PATCH;
		break;
	default:
		netdev_err(dev, "Unsupported directory entry type: %u\n",
			   dir_type);
		return -EINVAL;
	}
	if (fw_size < sizeof(struct bnxt_fw_header)) {
		netdev_err(dev, "Invalid firmware file size: %u\n",
			   (unsigned int)fw_size);
		return -EINVAL;
	}
	if (header->signature != cpu_to_le32(BNXT_FIRMWARE_BIN_SIGNATURE)) {
		netdev_err(dev, "Invalid firmware signature: %08X\n",
			   le32_to_cpu(header->signature));
		return -EINVAL;
	}
	if (header->code_type != code_type) {
		netdev_err(dev, "Expected firmware type: %d, read: %d\n",
			   code_type, header->code_type);
		return -EINVAL;
	}
	if (header->device != DEVICE_CUMULUS_FAMILY) {
		netdev_err(dev, "Expected firmware device family %d, read: %d\n",
			   DEVICE_CUMULUS_FAMILY, header->device);
		return -EINVAL;
	}
	/* Confirm the CRC32 checksum of the file: */
	stored_crc = le32_to_cpu(*(__le32 *)(fw_data + fw_size -
					     sizeof(stored_crc)));
	calculated_crc = ~crc32(~0, fw_data, fw_size - sizeof(stored_crc));
	if (calculated_crc != stored_crc) {
		netdev_err(dev, "Firmware file CRC32 checksum (%08lX) does not match calculated checksum (%08lX)\n",
			   (unsigned long)stored_crc,
			   (unsigned long)calculated_crc);
		return -EINVAL;
	}
	rc = bnxt_flash_nvram(dev, dir_type, BNX_DIR_ORDINAL_FIRST,
			      0, 0, 0, fw_data, fw_size);
	if (rc == 0)	/* Firmware update successful */
		rc = bnxt_firmware_reset(dev, dir_type);

	return rc;
}

static int bnxt_flash_microcode(struct net_device *dev,
				u16 dir_type,
				const u8 *fw_data,
				size_t fw_size)
{
	struct bnxt_ucode_trailer *trailer;
	u32 calculated_crc;
	u32 stored_crc;
	int rc = 0;

	if (fw_size < sizeof(struct bnxt_ucode_trailer)) {
		netdev_err(dev, "Invalid microcode file size: %u\n",
			   (unsigned int)fw_size);
		return -EINVAL;
	}
	trailer = (struct bnxt_ucode_trailer *)(fw_data + (fw_size -
						sizeof(*trailer)));
	if (trailer->sig != cpu_to_le32(BNXT_UCODE_TRAILER_SIGNATURE)) {
		netdev_err(dev, "Invalid microcode trailer signature: %08X\n",
			   le32_to_cpu(trailer->sig));
		return -EINVAL;
	}
	if (le16_to_cpu(trailer->dir_type) != dir_type) {
		netdev_err(dev, "Expected microcode type: %d, read: %d\n",
			   dir_type, le16_to_cpu(trailer->dir_type));
		return -EINVAL;
	}
	if (le16_to_cpu(trailer->trailer_length) <
		sizeof(struct bnxt_ucode_trailer)) {
		netdev_err(dev, "Invalid microcode trailer length: %d\n",
			   le16_to_cpu(trailer->trailer_length));
		return -EINVAL;
	}

	/* Confirm the CRC32 checksum of the file: */
	stored_crc = le32_to_cpu(*(__le32 *)(fw_data + fw_size -
					     sizeof(stored_crc)));
	calculated_crc = ~crc32(~0, fw_data, fw_size - sizeof(stored_crc));
	if (calculated_crc != stored_crc) {
		netdev_err(dev,
			   "CRC32 (%08lX) does not match calculated: %08lX\n",
			   (unsigned long)stored_crc,
			   (unsigned long)calculated_crc);
		return -EINVAL;
	}
	rc = bnxt_flash_nvram(dev, dir_type, BNX_DIR_ORDINAL_FIRST,
			      0, 0, 0, fw_data, fw_size);

	return rc;
}

static bool bnxt_dir_type_is_ape_bin_format(u16 dir_type)
{
	switch (dir_type) {
	case BNX_DIR_TYPE_CHIMP_PATCH:
	case BNX_DIR_TYPE_BOOTCODE:
	case BNX_DIR_TYPE_BOOTCODE_2:
	case BNX_DIR_TYPE_APE_FW:
	case BNX_DIR_TYPE_APE_PATCH:
	case BNX_DIR_TYPE_KONG_FW:
	case BNX_DIR_TYPE_KONG_PATCH:
	case BNX_DIR_TYPE_BONO_FW:
	case BNX_DIR_TYPE_BONO_PATCH:
		return true;
	}

	return false;
}

static bool bnxt_dir_type_is_other_exec_format(u16 dir_type)
{
	switch (dir_type) {
	case BNX_DIR_TYPE_AVS:
	case BNX_DIR_TYPE_EXP_ROM_MBA:
	case BNX_DIR_TYPE_PCIE:
	case BNX_DIR_TYPE_TSCF_UCODE:
	case BNX_DIR_TYPE_EXT_PHY:
	case BNX_DIR_TYPE_CCM:
	case BNX_DIR_TYPE_ISCSI_BOOT:
	case BNX_DIR_TYPE_ISCSI_BOOT_IPV6:
	case BNX_DIR_TYPE_ISCSI_BOOT_IPV4N6:
		return true;
	}

	return false;
}

static bool bnxt_dir_type_is_executable(u16 dir_type)
{
	return bnxt_dir_type_is_ape_bin_format(dir_type) ||
		bnxt_dir_type_is_other_exec_format(dir_type);
}

static int bnxt_flash_firmware_from_file(struct net_device *dev,
					 u16 dir_type,
					 const char *filename)
{
	const struct firmware  *fw;
	int			rc;

	rc = request_firmware(&fw, filename, &dev->dev);
	if (rc != 0) {
		netdev_err(dev, "Error %d requesting firmware file: %s\n",
			   rc, filename);
		return rc;
	}
	if (bnxt_dir_type_is_ape_bin_format(dir_type))
		rc = bnxt_flash_firmware(dev, dir_type, fw->data, fw->size);
	else if (bnxt_dir_type_is_other_exec_format(dir_type))
		rc = bnxt_flash_microcode(dev, dir_type, fw->data, fw->size);
	else
		rc = bnxt_flash_nvram(dev, dir_type, BNX_DIR_ORDINAL_FIRST,
				      0, 0, 0, fw->data, fw->size);
	release_firmware(fw);
	return rc;
}

#define MSG_INTEGRITY_ERR "PKG install error : Data integrity on NVM"
#define MSG_INVALID_PKG "PKG install error : Invalid package"
#define MSG_AUTHENTICATION_ERR "PKG install error : Authentication error"
#define MSG_INVALID_DEV "PKG install error : Invalid device"
#define MSG_INTERNAL_ERR "PKG install error : Internal error"
#define MSG_NO_PKG_UPDATE_AREA_ERR "PKG update area not created in nvram"
#define MSG_NO_SPACE_ERR "PKG insufficient update area in nvram"
#define MSG_RESIZE_UPDATE_ERR "Resize UPDATE entry error"
#define MSG_ANTI_ROLLBACK_ERR "HWRM_NVM_INSTALL_UPDATE failure due to Anti-rollback detected"
#define MSG_GENERIC_FAILURE_ERR "HWRM_NVM_INSTALL_UPDATE failure"

static int nvm_update_err_to_stderr(struct net_device *dev, u8 result,
				    struct netlink_ext_ack *extack)
{
	switch (result) {
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_TYPE_PARAMETER:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_INDEX_PARAMETER:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INSTALL_DATA_ERROR:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INSTALL_CHECKSUM_ERROR:
	case NVM_INSTALL_UPDATE_RESP_RESULT_ITEM_NOT_FOUND:
	case NVM_INSTALL_UPDATE_RESP_RESULT_ITEM_LOCKED:
		BNXT_NVM_ERR_MSG(dev, extack, MSG_INTEGRITY_ERR);
		return -EINVAL;
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_PREREQUISITE:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_FILE_HEADER:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_SIGNATURE:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_PROP_STREAM:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_PROP_LENGTH:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_MANIFEST:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_TRAILER:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_CHECKSUM:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_ITEM_CHECKSUM:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_DATA_LENGTH:
	case NVM_INSTALL_UPDATE_RESP_RESULT_INVALID_DIRECTIVE:
	case NVM_INSTALL_UPDATE_RESP_RESULT_DUPLICATE_ITEM:
	case NVM_INSTALL_UPDATE_RESP_RESULT_ZERO_LENGTH_ITEM:
		BNXT_NVM_ERR_MSG(dev, extack, MSG_INVALID_PKG);
		return -ENOPKG;
	case NVM_INSTALL_UPDATE_RESP_RESULT_INSTALL_AUTHENTICATION_ERROR:
		BNXT_NVM_ERR_MSG(dev, extack, MSG_AUTHENTICATION_ERR);
		return -EPERM;
	case NVM_INSTALL_UPDATE_RESP_RESULT_UNSUPPORTED_CHIP_REV:
	case NVM_INSTALL_UPDATE_RESP_RESULT_UNSUPPORTED_DEVICE_ID:
	case NVM_INSTALL_UPDATE_RESP_RESULT_UNSUPPORTED_SUBSYS_VENDOR:
	case NVM_INSTALL_UPDATE_RESP_RESULT_UNSUPPORTED_SUBSYS_ID:
	case NVM_INSTALL_UPDATE_RESP_RESULT_UNSUPPORTED_PLATFORM:
		BNXT_NVM_ERR_MSG(dev, extack, MSG_INVALID_DEV);
		return -EOPNOTSUPP;
	default:
		BNXT_NVM_ERR_MSG(dev, extack, MSG_INTERNAL_ERR);
		return -EIO;
	}
}

#define BNXT_PKG_DMA_SIZE	0x40000
#define BNXT_NVM_MORE_FLAG	(cpu_to_le16(NVM_MODIFY_REQ_FLAGS_BATCH_MODE))
#define BNXT_NVM_LAST_FLAG	(cpu_to_le16(NVM_MODIFY_REQ_FLAGS_BATCH_LAST))

static int bnxt_resize_update_entry(struct net_device *dev, size_t fw_size,
				    struct netlink_ext_ack *extack)
{
	u32 item_len;
	int rc;

	rc = bnxt_find_nvram_item(dev, BNX_DIR_TYPE_UPDATE,
				  BNX_DIR_ORDINAL_FIRST, BNX_DIR_EXT_NONE, NULL,
				  &item_len, NULL);
	if (rc) {
		BNXT_NVM_ERR_MSG(dev, extack, MSG_NO_PKG_UPDATE_AREA_ERR);
		return rc;
	}

	if (fw_size > item_len) {
		rc = bnxt_flash_nvram(dev, BNX_DIR_TYPE_UPDATE,
				      BNX_DIR_ORDINAL_FIRST, 0, 1,
				      round_up(fw_size, 4096), NULL, 0);
		if (rc) {
			BNXT_NVM_ERR_MSG(dev, extack, MSG_RESIZE_UPDATE_ERR);
			return rc;
		}
	}
	return 0;
}

int bnxt_flash_package_from_fw_obj(struct net_device *dev, const struct firmware *fw,
				   u32 install_type, struct netlink_ext_ack *extack)
{
	struct hwrm_nvm_install_update_input *install;
	struct hwrm_nvm_install_update_output *resp;
	struct hwrm_nvm_modify_input *modify;
	struct bnxt *bp = netdev_priv(dev);
	bool defrag_attempted = false;
	dma_addr_t dma_handle;
	u8 *kmem = NULL;
	u32 modify_len;
	u32 item_len;
	u8 cmd_err;
	u16 index;
	int rc;

	/* resize before flashing larger image than available space */
	rc = bnxt_resize_update_entry(dev, fw->size, extack);
	if (rc)
		return rc;

	bnxt_hwrm_fw_set_time(bp);

	rc = hwrm_req_init(bp, modify, HWRM_NVM_MODIFY);
	if (rc)
		return rc;

	/* Try allocating a large DMA buffer first.  Older fw will
	 * cause excessive NVRAM erases when using small blocks.
	 */
	modify_len = roundup_pow_of_two(fw->size);
	modify_len = min_t(u32, modify_len, BNXT_PKG_DMA_SIZE);
	while (1) {
		kmem = hwrm_req_dma_slice(bp, modify, modify_len, &dma_handle);
		if (!kmem && modify_len > PAGE_SIZE)
			modify_len /= 2;
		else
			break;
	}
	if (!kmem) {
		hwrm_req_drop(bp, modify);
		return -ENOMEM;
	}

	rc = hwrm_req_init(bp, install, HWRM_NVM_INSTALL_UPDATE);
	if (rc) {
		hwrm_req_drop(bp, modify);
		return rc;
	}

	hwrm_req_timeout(bp, modify, FLASH_PACKAGE_TIMEOUT);
	hwrm_req_timeout(bp, install, INSTALL_PACKAGE_TIMEOUT);

	hwrm_req_hold(bp, modify);
	modify->host_src_addr = cpu_to_le64(dma_handle);

	resp = hwrm_req_hold(bp, install);
	if ((install_type & 0xffff) == 0)
		install_type >>= 16;
	install->install_type = cpu_to_le32(install_type);

	do {
		u32 copied = 0, len = modify_len;

		rc = bnxt_find_nvram_item(dev, BNX_DIR_TYPE_UPDATE,
					  BNX_DIR_ORDINAL_FIRST,
					  BNX_DIR_EXT_NONE,
					  &index, &item_len, NULL);
		if (rc) {
			BNXT_NVM_ERR_MSG(dev, extack, MSG_NO_PKG_UPDATE_AREA_ERR);
			break;
		}
		if (fw->size > item_len) {
			BNXT_NVM_ERR_MSG(dev, extack, MSG_NO_SPACE_ERR);
			rc = -EFBIG;
			break;
		}

		modify->dir_idx = cpu_to_le16(index);

		if (fw->size > modify_len)
			modify->flags = BNXT_NVM_MORE_FLAG;
		while (copied < fw->size) {
			u32 balance = fw->size - copied;

			if (balance <= modify_len) {
				len = balance;
				if (copied)
					modify->flags |= BNXT_NVM_LAST_FLAG;
			}
			memcpy(kmem, fw->data + copied, len);
			modify->len = cpu_to_le32(len);
			modify->offset = cpu_to_le32(copied);
			rc = hwrm_req_send(bp, modify);
			if (rc)
				goto pkg_abort;
			copied += len;
		}

		rc = hwrm_req_send_silent(bp, install);
		if (!rc)
			break;

		if (defrag_attempted)
			break;

		cmd_err = ((struct hwrm_err_output *)resp)->cmd_err;

		switch (cmd_err) {
		case NVM_INSTALL_UPDATE_CMD_ERR_CODE_ANTI_ROLLBACK:
			BNXT_NVM_ERR_MSG(dev, extack, MSG_ANTI_ROLLBACK_ERR);
			rc = -EALREADY;
			break;
		case NVM_INSTALL_UPDATE_CMD_ERR_CODE_FRAG_ERR:
			install->flags =
				cpu_to_le16(NVM_INSTALL_UPDATE_REQ_FLAGS_ALLOWED_TO_DEFRAG);

			rc = hwrm_req_send_silent(bp, install);
			if (!rc)
				break;

			cmd_err = ((struct hwrm_err_output *)resp)->cmd_err;

			if (cmd_err == NVM_INSTALL_UPDATE_CMD_ERR_CODE_NO_SPACE) {
				/* FW has cleared NVM area, driver will create
				 * UPDATE directory and try the flash again
				 */
				defrag_attempted = true;
				install->flags = 0;
				rc = bnxt_flash_nvram(bp->dev,
						      BNX_DIR_TYPE_UPDATE,
						      BNX_DIR_ORDINAL_FIRST,
						      0, 0, item_len, NULL, 0);
				if (!rc)
					break;
			}
			fallthrough;
		default:
			BNXT_NVM_ERR_MSG(dev, extack, MSG_GENERIC_FAILURE_ERR);
		}
	} while (defrag_attempted && !rc);

pkg_abort:
	hwrm_req_drop(bp, modify);
	hwrm_req_drop(bp, install);

	if (resp->result) {
		netdev_err(dev, "PKG install error = %#x, problem_item = %#x\n",
			   resp->result, resp->problem_item);
		rc = nvm_update_err_to_stderr(dev, resp->result, extack);
	}

	if (rc == -EACCES)
		bnxt_print_admin_err(bp);
	return rc;
}

int bnxt_flash_package_from_file(struct net_device *dev, const char *filename,
				 u32 install_type, struct netlink_ext_ack *extack)
{
	const struct firmware *fw;
	int rc;

	rc = request_firmware(&fw, filename, &dev->dev);
	if (rc) {
		netdev_err(dev, "PKG error %d requesting file: %s\n",
			   rc, filename);
		return rc;
	}

	rc = bnxt_flash_package_from_fw_obj(dev, fw, install_type, extack);

	release_firmware(fw);

	return rc;
}

static int bnxt_flash_device(struct net_device *dev,
			     struct ethtool_flash *flash)
{
	if (!BNXT_PF((struct bnxt *)netdev_priv(dev))) {
		netdev_err(dev, "flashdev not supported from a virtual function\n");
		return -EINVAL;
	}

	if (flash->region == ETHTOOL_FLASH_ALL_REGIONS ||
	    flash->region > 0xffff)
		return bnxt_flash_package_from_file(dev, flash->data,
						    flash->region, NULL);

	return bnxt_flash_firmware_from_file(dev, flash->region, flash->data);
}

static int nvm_get_dir_info(struct net_device *dev, u32 *entries, u32 *length)
{
	struct hwrm_nvm_get_dir_info_output *output;
	struct hwrm_nvm_get_dir_info_input *req;
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_NVM_GET_DIR_INFO);
	if (rc)
		return rc;

	output = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc) {
		*entries = le32_to_cpu(output->entries);
		*length = le32_to_cpu(output->entry_length);
	}
	hwrm_req_drop(bp, req);
	return rc;
}

static int bnxt_get_eeprom_len(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	if (BNXT_VF(bp))
		return 0;

	/* The -1 return value allows the entire 32-bit range of offsets to be
	 * passed via the ethtool command-line utility.
	 */
	return -1;
}

static int bnxt_get_nvram_directory(struct net_device *dev, u32 len, u8 *data)
{
	struct hwrm_nvm_get_dir_entries_input *req;
	struct bnxt *bp = netdev_priv(dev);
	dma_addr_t dma_handle;
	u32 entry_length;
	u32 dir_entries;
	size_t buflen;
	u8 *buf;
	int rc;

	rc = nvm_get_dir_info(dev, &dir_entries, &entry_length);
	if (rc != 0)
		return rc;

	if (!dir_entries || !entry_length)
		return -EIO;

	/* Insert 2 bytes of directory info (count and size of entries) */
	if (len < 2)
		return -EINVAL;

	*data++ = dir_entries;
	*data++ = entry_length;
	len -= 2;
	memset(data, 0xff, len);

	rc = hwrm_req_init(bp, req, HWRM_NVM_GET_DIR_ENTRIES);
	if (rc)
		return rc;

	buflen = mul_u32_u32(dir_entries, entry_length);
	buf = hwrm_req_dma_slice(bp, req, buflen, &dma_handle);
	if (!buf) {
		hwrm_req_drop(bp, req);
		return -ENOMEM;
	}
	req->host_dest_addr = cpu_to_le64(dma_handle);

	hwrm_req_hold(bp, req); /* hold the slice */
	rc = hwrm_req_send(bp, req);
	if (rc == 0)
		memcpy(data, buf, len > buflen ? buflen : len);
	hwrm_req_drop(bp, req);
	return rc;
}

int bnxt_get_nvram_item(struct net_device *dev, u32 index, u32 offset,
			u32 length, u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_nvm_read_input *req;
	dma_addr_t dma_handle;
	u8 *buf;
	int rc;

	if (!length)
		return -EINVAL;

	rc = hwrm_req_init(bp, req, HWRM_NVM_READ);
	if (rc)
		return rc;

	buf = hwrm_req_dma_slice(bp, req, length, &dma_handle);
	if (!buf) {
		hwrm_req_drop(bp, req);
		return -ENOMEM;
	}

	req->host_dest_addr = cpu_to_le64(dma_handle);
	req->dir_idx = cpu_to_le16(index);
	req->offset = cpu_to_le32(offset);
	req->len = cpu_to_le32(length);

	hwrm_req_hold(bp, req); /* hold the slice */
	rc = hwrm_req_send(bp, req);
	if (rc == 0)
		memcpy(data, buf, length);
	hwrm_req_drop(bp, req);
	return rc;
}

int bnxt_find_nvram_item(struct net_device *dev, u16 type, u16 ordinal,
			 u16 ext, u16 *index, u32 *item_length,
			 u32 *data_length)
{
	struct hwrm_nvm_find_dir_entry_output *output;
	struct hwrm_nvm_find_dir_entry_input *req;
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_NVM_FIND_DIR_ENTRY);
	if (rc)
		return rc;

	req->enables = 0;
	req->dir_idx = 0;
	req->dir_type = cpu_to_le16(type);
	req->dir_ordinal = cpu_to_le16(ordinal);
	req->dir_ext = cpu_to_le16(ext);
	req->opt_ordinal = NVM_FIND_DIR_ENTRY_REQ_OPT_ORDINAL_EQ;
	output = hwrm_req_hold(bp, req);
	rc = hwrm_req_send_silent(bp, req);
	if (rc == 0) {
		if (index)
			*index = le16_to_cpu(output->dir_idx);
		if (item_length)
			*item_length = le32_to_cpu(output->dir_item_length);
		if (data_length)
			*data_length = le32_to_cpu(output->dir_data_length);
	}
	hwrm_req_drop(bp, req);
	return rc;
}

static char *bnxt_parse_pkglog(int desired_field, u8 *data, size_t datalen)
{
	char	*retval = NULL;
	char	*p;
	char	*value;
	int	field = 0;

	if (datalen < 1)
		return NULL;
	/* null-terminate the log data (removing last '\n'): */
	data[datalen - 1] = 0;
	for (p = data; *p != 0; p++) {
		field = 0;
		retval = NULL;
		while (*p != 0 && *p != '\n') {
			value = p;
			while (*p != 0 && *p != '\t' && *p != '\n')
				p++;
			if (field == desired_field)
				retval = value;
			if (*p != '\t')
				break;
			*p = 0;
			field++;
			p++;
		}
		if (*p == 0)
			break;
		*p = 0;
	}
	return retval;
}

int bnxt_get_pkginfo(struct net_device *dev, char *ver, int size)
{
	struct bnxt *bp = netdev_priv(dev);
	u16 index = 0;
	char *pkgver;
	u32 pkglen;
	u8 *pkgbuf;
	int rc;

	rc = bnxt_find_nvram_item(dev, BNX_DIR_TYPE_PKG_LOG,
				  BNX_DIR_ORDINAL_FIRST, BNX_DIR_EXT_NONE,
				  &index, NULL, &pkglen);
	if (rc)
		return rc;

	pkgbuf = kzalloc(pkglen, GFP_KERNEL);
	if (!pkgbuf) {
		dev_err(&bp->pdev->dev, "Unable to allocate memory for pkg version, length = %u\n",
			pkglen);
		return -ENOMEM;
	}

	rc = bnxt_get_nvram_item(dev, index, 0, pkglen, pkgbuf);
	if (rc)
		goto err;

	pkgver = bnxt_parse_pkglog(BNX_PKG_LOG_FIELD_IDX_PKG_VERSION, pkgbuf,
				   pkglen);
	if (pkgver && *pkgver != 0 && isdigit(*pkgver))
		strscpy(ver, pkgver, size);
	else
		rc = -ENOENT;

err:
	kfree(pkgbuf);

	return rc;
}

static void bnxt_get_pkgver(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);
	char buf[FW_VER_STR_LEN];
	int len;

	if (!bnxt_get_pkginfo(dev, buf, sizeof(buf))) {
		len = strlen(bp->fw_ver_str);
		snprintf(bp->fw_ver_str + len, FW_VER_STR_LEN - len - 1,
			 "/pkg %s", buf);
	}
}

static int bnxt_get_eeprom(struct net_device *dev,
			   struct ethtool_eeprom *eeprom,
			   u8 *data)
{
	struct hwrm_nvm_get_dev_info_output nvm_dev_info;
	struct hwrm_fw_qstatus_output *fw_status_resp;
	struct hwrm_fw_qstatus_input *fw_status_req;
	struct bnxt *bp = netdev_priv(dev);
	u32 size, index, offset;
	int rc, i;

	if (eeprom->len < 1)
		return -EINVAL;

	if (eeprom->offset == 0) /* special offset value to get directory */
		return bnxt_get_nvram_directory(dev, eeprom->len, data);

	index = eeprom->offset >> 24;
	offset = eeprom->offset & 0xffffff;

	if (index != 0)
		return bnxt_get_nvram_item(dev, index - 1, offset, eeprom->len,
					   data);

	switch (offset) {
	case 1:	/* Query firmware reset status */
		if (eeprom->len < 5)
			return -EINVAL;
		size = 4; /* procs: BOOT, MGMT, NETCTRL, and ROCE */
		*(data++) = size;
		rc = hwrm_req_init(bp, fw_status_req, HWRM_FW_QSTATUS);
		if (rc)
			return rc;

		fw_status_resp = hwrm_req_hold(bp, fw_status_req);
		for (i = 0; i < size; i++) {
			fw_status_req->embedded_proc_type = i;
			rc = hwrm_req_send(bp, fw_status_req);
			if (rc == 0)
				*(data++) = fw_status_resp->selfrst_status;
			else
				break;
		}
		hwrm_req_drop(bp, fw_status_req);
		return rc;
	case 2: /* Query firmware version information */
		size = sizeof(bp->ver_resp);
		*(data++) = size;
		memcpy(data, &bp->ver_resp, min(size, eeprom->len - 1));
		return 0;
	case 3: /* Query NVM device information */
		rc = bnxt_hwrm_nvm_get_dev_info(bp, &nvm_dev_info);
		if (rc)
			return rc;

		size = sizeof(nvm_dev_info);
		*(data++) = size;
		memcpy(data, &nvm_dev_info, min(size, eeprom->len - 1));
		return 0;
	}
	return -EINVAL;
}

static int bnxt_erase_nvram_directory(struct net_device *dev, u8 index)
{
	struct hwrm_nvm_erase_dir_entry_input *req;
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_NVM_ERASE_DIR_ENTRY);
	if (rc)
		return rc;

	req->dir_idx = cpu_to_le16(index);
	return hwrm_req_send(bp, req);
}

static int bnxt_set_eeprom(struct net_device *dev,
			   struct ethtool_eeprom *eeprom,
			   u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	u8 index, dir_op;
	u16 type, ext, ordinal, attr;

	if (!BNXT_PF(bp)) {
		netdev_err(dev, "NVM write not supported from a virtual function\n");
		return -EINVAL;
	}

	type = eeprom->magic >> 16;

	if (type == 0xffff) { /* special value for directory operations */
		index = eeprom->magic & 0xff;
		dir_op = eeprom->magic >> 8;
		if (index == 0)
			return -EINVAL;
		switch (dir_op) {
		case 0x0e: /* erase */
			if (eeprom->offset != ~eeprom->magic)
				return -EINVAL;
			return bnxt_erase_nvram_directory(dev, index - 1);
		default:
			return -EINVAL;
		}
	}

	/* Create or re-write an NVM item: */
	if (bnxt_dir_type_is_executable(type))
		return -EOPNOTSUPP;
	ext = eeprom->magic & 0xffff;
	ordinal = eeprom->offset >> 16;
	attr = eeprom->offset & 0xffff;

	return bnxt_flash_nvram(dev, type, ordinal, ext, attr, 0, data,
				eeprom->len);
}

#if defined(HAVE_ETHTOOL_KEEE)
static int bnxt_set_eee(struct net_device *dev, struct ethtool_keee *edata)
{
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(tmp);
	struct bnxt *bp = netdev_priv(dev);
	struct ethtool_keee *eee = &bp->eee;
	struct bnxt_link_info *link_info = &bp->link_info;
	int rc = 0;

	if (!BNXT_PHY_CFG_ABLE(bp))
		return -EOPNOTSUPP;

	if (!(bp->phy_flags & BNXT_PHY_FL_EEE_CAP))
		return -EOPNOTSUPP;

	mutex_lock(&bp->link_lock);
	_bnxt_fw_to_linkmode(advertising, link_info->advertising);
	if (!edata->eee_enabled)
		goto eee_ok;

	if (!(link_info->autoneg & BNXT_AUTONEG_SPEED)) {
		netdev_warn(dev, "EEE requires autoneg\n");
		rc = -EINVAL;
		goto eee_exit;
	}
	if (edata->tx_lpi_enabled) {
		if (bp->lpi_tmr_hi && (edata->tx_lpi_timer > bp->lpi_tmr_hi ||
				       edata->tx_lpi_timer < bp->lpi_tmr_lo)) {
			netdev_warn(dev, "Valid LPI timer range is %d and %d microsecs\n",
				    bp->lpi_tmr_lo, bp->lpi_tmr_hi);
			rc = -EINVAL;
			goto eee_exit;
		} else if (!bp->lpi_tmr_hi) {
			edata->tx_lpi_timer = eee->tx_lpi_timer;
		}
	}
	if (linkmode_empty(edata->advertised)) {
		linkmode_and(edata->advertised, advertising, eee->supported);
	} else if (linkmode_andnot(tmp, edata->advertised, advertising)) {
		netdev_warn(dev, "EEE advertised must be a subset of autoneg advertised speeds\n");
		rc = -EINVAL;
		goto eee_exit;
	}

	linkmode_copy(eee->advertised, edata->advertised);
	eee->tx_lpi_enabled = edata->tx_lpi_enabled;
	eee->tx_lpi_timer = edata->tx_lpi_timer;
eee_ok:
	eee->eee_enabled = edata->eee_enabled;

	if (netif_running(dev))
		rc = bnxt_hwrm_set_link_setting(bp, false, true);

eee_exit:
	mutex_unlock(&bp->link_lock);
	return rc;
}

static int bnxt_get_eee(struct net_device *dev, struct ethtool_keee *edata)
{
	struct bnxt *bp = netdev_priv(dev);

	if (!(bp->phy_flags & BNXT_PHY_FL_EEE_CAP))
		return -EOPNOTSUPP;

	*edata = bp->eee;
	if (!bp->eee.eee_enabled) {
		/* Preserve tx_lpi_timer so that the last value will be used
		 * by default when it is re-enabled.
		 */
		linkmode_zero(edata->advertised);
		edata->tx_lpi_enabled = 0;
	}

	if (!bp->eee.eee_active)
		linkmode_zero(edata->lp_advertised);

	return 0;
}
#endif

#if (defined(ETHTOOL_GMODULEEEPROM) && !defined(GET_ETHTOOL_OP_EXT)) || \
	defined(HAVE_MODULE_EEPROM_BY_PAGE)
static int bnxt_read_sfp_module_eeprom_info(struct bnxt *bp, u16 i2c_addr,
					    u16 page_number, u8 bank,
					    u16 start_addr, u16 data_length,
					    u8 *buf)
{
	struct hwrm_port_phy_i2c_read_output *output;
	struct hwrm_port_phy_i2c_read_input *req;
	int rc, byte_offset = 0;

	rc = hwrm_req_init(bp, req, HWRM_PORT_PHY_I2C_READ);
	if (rc)
		return rc;

	output = hwrm_req_hold(bp, req);
	req->i2c_slave_addr = i2c_addr;
	req->page_number = cpu_to_le16(page_number);
	req->port_id = cpu_to_le16(bp->pf.port_id);
	do {
		u16 xfer_size;

		xfer_size = min_t(u16, data_length, BNXT_MAX_PHY_I2C_RESP_SIZE);
		data_length -= xfer_size;
		req->page_offset = cpu_to_le16(start_addr + byte_offset);
		req->data_length = xfer_size;
		req->enables =
			cpu_to_le32((start_addr + byte_offset ?
				     PORT_PHY_I2C_READ_REQ_ENABLES_PAGE_OFFSET :
				     0) |
				    (bank ?
				     PORT_PHY_I2C_READ_REQ_ENABLES_BANK_NUMBER :
				     0));
		rc = hwrm_req_send(bp, req);
		if (!rc)
			memcpy(buf + byte_offset, output->data, xfer_size);
		byte_offset += xfer_size;
	} while (!rc && data_length > 0);
	hwrm_req_drop(bp, req);

	return rc;
}

static int bnxt_get_module_info(struct net_device *dev,
				struct ethtool_modinfo *modinfo)
{
	u8 data[SFF_DIAG_SUPPORT_OFFSET + 1];
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	if (BNXT_VF(bp) && !BNXT_VF_IS_TRUSTED(bp))
		return -EPERM;

	/* No point in going further if phy status indicates
	 * module is not inserted or if it is powered down or
	 * if it is of type 10GBase-T
	 */
	if (bp->link_info.module_status >
		PORT_PHY_QCFG_RESP_MODULE_STATUS_WARNINGMSG)
		return -EOPNOTSUPP;

	/* This feature is not supported in older firmware versions */
	if (bp->hwrm_spec_code < 0x10202)
		return -EOPNOTSUPP;

	rc = bnxt_read_sfp_module_eeprom_info(bp, I2C_DEV_ADDR_A0, 0, 0, 0,
					      SFF_DIAG_SUPPORT_OFFSET + 1,
					      data);
	if (!rc) {
		u8 module_id = data[0];
		u8 diag_supported = data[SFF_DIAG_SUPPORT_OFFSET];

		switch (module_id) {
		case SFF_MODULE_ID_SFP:
			modinfo->type = ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
			if (!diag_supported)
				modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP:
		case SFF_MODULE_ID_QSFP_PLUS:
			modinfo->type = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP28:
			modinfo->type = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_LEN;
			break;
		case SFF_MODULE_ID_QSFP56:
			modinfo->type = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_LEN;
			break;
		default:
			rc = -EOPNOTSUPP;
			break;
		}
	}
	return rc;
}

static int bnxt_get_module_eeprom(struct net_device *dev,
				  struct ethtool_eeprom *eeprom,
				  u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	u16  start = eeprom->offset, length = eeprom->len;
	int rc = 0;

	if (BNXT_VF(bp) && !BNXT_VF_IS_TRUSTED(bp))
		return -EPERM;

	memset(data, 0, eeprom->len);

	/* Read A0 portion of the EEPROM */
	if (start < ETH_MODULE_SFF_8436_LEN) {
		if (start + eeprom->len > ETH_MODULE_SFF_8436_LEN)
			length = ETH_MODULE_SFF_8436_LEN - start;
		rc = bnxt_read_sfp_module_eeprom_info(bp, I2C_DEV_ADDR_A0, 0, 0,
						      start, length, data);
		if (rc)
			return rc;
		start += length;
		data += start;
		length = eeprom->len - length;
	}

	/* Read A2 portion of the EEPROM */
	if (length) {
		start -= ETH_MODULE_SFF_8436_LEN;
		rc = bnxt_read_sfp_module_eeprom_info(bp, I2C_DEV_ADDR_A2, 0, 0,
						      start, length, data);
	}
	return rc;
}
#endif

#if defined(HAVE_MODULE_EEPROM_BY_PAGE)
static int bnxt_get_module_status(struct bnxt *bp, struct netlink_ext_ack *extack)
{
	if (bp->link_info.module_status <=
	    PORT_PHY_QCFG_RESP_MODULE_STATUS_WARNINGMSG)
		return 0;

	switch (bp->link_info.module_status) {
	case PORT_PHY_QCFG_RESP_MODULE_STATUS_PWRDOWN:
		NL_SET_ERR_MSG_MOD(extack, "Transceiver module is powering down");
		break;
	case PORT_PHY_QCFG_RESP_MODULE_STATUS_NOTINSERTED:
		NL_SET_ERR_MSG_MOD(extack, "Transceiver module not inserted");
		break;
	case PORT_PHY_QCFG_RESP_MODULE_STATUS_CURRENTFAULT:
		NL_SET_ERR_MSG_MOD(extack, "Transceiver module disabled due to current fault");
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown error");
		break;
	}
	return -EINVAL;
}

static int bnxt_get_module_eeprom_by_page(struct net_device *dev,
					  const struct ethtool_module_eeprom *page_data,
					  struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	if (BNXT_VF(bp) && !BNXT_VF_IS_TRUSTED(bp))
		return -EPERM;

	rc = bnxt_get_module_status(bp, extack);
	if (rc)
		return rc;

	if (bp->hwrm_spec_code < 0x10202) {
		NL_SET_ERR_MSG_MOD(extack, "Firmware version too old");
		return -EINVAL;
	}

	if (page_data->bank && !(bp->phy_flags & BNXT_PHY_FL_BANK_SEL)) {
		NL_SET_ERR_MSG_MOD(extack, "Firmware not capable for bank selection");
		return -EINVAL;
	}

	rc = bnxt_read_sfp_module_eeprom_info(bp, page_data->i2c_address << 1,
					      page_data->page, page_data->bank,
					      page_data->offset,
					      page_data->length,
					      page_data->data);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Module`s eeprom read failed");
		return rc;
	}
	return page_data->length;
}
#endif

static int bnxt_nway_reset(struct net_device *dev)
{
	int rc = 0;

	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;

	if (!BNXT_PHY_CFG_ABLE(bp))
		return -EOPNOTSUPP;

	if (!(link_info->autoneg & BNXT_AUTONEG_SPEED))
		return -EINVAL;

	if (netif_running(dev))
		rc = bnxt_hwrm_set_link_setting(bp, true, false);

	return rc;
}

#if (LINUX_VERSION_CODE < 0x30000)
static int bnxt_phys_id(struct net_device *dev, u32 data)
{
	struct hwrm_port_led_cfg_input *req;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_led_cfg *led_cfg;
	u8 led_state;
	u16 duration;
	int i, rc;

	if (!bp->num_leds || BNXT_VF(bp))
		return -EOPNOTSUPP;

	if (!data)
		data = 2;

	led_state = PORT_LED_CFG_REQ_LED0_STATE_BLINKALT;
	duration = 500;

	while (1) {
		/* reinit, don't hold onto the HWRM resources during delay */
		rc = hwrm_req_init(bp, req, HWRM_PORT_LED_CFG);
		if (rc)
			return rc;

		req->port_id = cpu_to_le16(pf->port_id);
		req->num_leds = bp->num_leds;
		led_cfg = (struct bnxt_led_cfg *)&req->led0_id;
		for (i = 0; i < bp->num_leds; i++, led_cfg++) {
			req->enables |= BNXT_LED_DFLT_ENABLES(i);
			led_cfg->led_id = bp->leds[i].led_id;
			led_cfg->led_state = led_state;
			led_cfg->led_blink_on = cpu_to_le16(duration);
			led_cfg->led_blink_off = cpu_to_le16(duration);
			led_cfg->led_group_id = bp->leds[i].led_group_id;
		}
		rc = hwrm_req_send(bp, req);

		if (!duration || rc)
			break;

		msleep_interruptible(data * 1000);
		led_state = PORT_LED_CFG_REQ_LED1_STATE_DEFAULT;
		duration = 0;
	}
	return rc;
}

#else
#if defined(HAVE_SET_PHYS_ID) && !defined(GET_ETHTOOL_OP_EXT)
static int bnxt_set_phys_id(struct net_device *dev,
			    enum ethtool_phys_id_state state)
{
	struct hwrm_port_led_cfg_input *req;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_led_cfg *led_cfg;
	__le16 duration;
	u8 led_state;
	int rc, i;

	if (!bp->num_leds || BNXT_VF(bp))
		return -EOPNOTSUPP;

	if (state == ETHTOOL_ID_ACTIVE) {
		led_state = PORT_LED_CFG_REQ_LED0_STATE_BLINKALT;
		duration = cpu_to_le16(500);
	} else if (state == ETHTOOL_ID_INACTIVE) {
		led_state = PORT_LED_CFG_REQ_LED1_STATE_DEFAULT;
		duration = cpu_to_le16(0);
	} else {
		return -EINVAL;
	}

	rc = hwrm_req_init(bp, req, HWRM_PORT_LED_CFG);
	if (rc)
		return rc;

	req->port_id = cpu_to_le16(pf->port_id);
	req->num_leds = bp->num_leds;
	led_cfg = (struct bnxt_led_cfg *)&req->led0_id;
	for (i = 0; i < bp->num_leds; i++, led_cfg++) {
		req->enables |= BNXT_LED_DFLT_ENABLES(i);
		led_cfg->led_id = bp->leds[i].led_id;
		led_cfg->led_state = led_state;
		led_cfg->led_blink_on = duration;
		led_cfg->led_blink_off = duration;
		led_cfg->led_group_id = bp->leds[i].led_group_id;
	}
	return hwrm_req_send(bp, req);
}
#endif
#endif

static int bnxt_hwrm_selftest_irq(struct bnxt *bp, u16 cmpl_ring)
{
	struct hwrm_selftest_irq_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_SELFTEST_IRQ);
	if (rc)
		return rc;

	req->cmpl_ring = cpu_to_le16(cmpl_ring);
	return hwrm_req_send(bp, req);
}

static int bnxt_test_irq(struct bnxt *bp)
{
	int i;

	for (i = 0; i < bp->cp_nr_rings; i++) {
		u16 cmpl_ring = bp->grp_info[i].cp_fw_ring_id;
		int rc;

		rc = bnxt_hwrm_selftest_irq(bp, cmpl_ring);
		if (rc)
			return rc;
	}
	return 0;
}

static int bnxt_hwrm_mac_loopback(struct bnxt *bp, bool enable)
{
	struct hwrm_port_mac_cfg_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_PORT_MAC_CFG);
	if (rc)
		return rc;

	req->enables = cpu_to_le32(PORT_MAC_CFG_REQ_ENABLES_LPBK);
	if (enable)
		req->lpbk = PORT_MAC_CFG_REQ_LPBK_LOCAL;
	else
		req->lpbk = PORT_MAC_CFG_REQ_LPBK_NONE;
	return hwrm_req_send(bp, req);
}

static int bnxt_query_force_speeds(struct bnxt *bp, u16 *force_speeds)
{
	struct hwrm_port_phy_qcaps_output *resp;
	struct hwrm_port_phy_qcaps_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_PORT_PHY_QCAPS);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		*force_speeds = le16_to_cpu(resp->supported_speeds_force_mode);

	hwrm_req_drop(bp, req);
	return rc;
}

static int bnxt_disable_an_for_lpbk(struct bnxt *bp,
				    struct hwrm_port_phy_cfg_input *req)
{
	struct bnxt_link_info *link_info = &bp->link_info;
	u16 fw_advertising;
	u16 fw_speed;
	int rc;

	if (!link_info->autoneg ||
	    (bp->phy_flags & BNXT_PHY_FL_AN_PHY_LPBK))
		return 0;

	rc = bnxt_query_force_speeds(bp, &fw_advertising);
	if (rc)
		return rc;

	fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_1GB;
	if (BNXT_LINK_IS_UP(bp))
		fw_speed = bp->link_info.link_speed;
	else if (fw_advertising & BNXT_LINK_SPEED_MSK_10GB)
		fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_10GB;
	else if (fw_advertising & BNXT_LINK_SPEED_MSK_25GB)
		fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_25GB;
	else if (fw_advertising & BNXT_LINK_SPEED_MSK_40GB)
		fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_40GB;
	else if (fw_advertising & BNXT_LINK_SPEED_MSK_50GB)
		fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_50GB;

	req->force_link_speed = cpu_to_le16(fw_speed);
	req->flags |= cpu_to_le32(PORT_PHY_CFG_REQ_FLAGS_FORCE |
				  PORT_PHY_CFG_REQ_FLAGS_RESET_PHY);
	rc = hwrm_req_send(bp, req);
	req->flags = 0;
	req->force_link_speed = cpu_to_le16(0);
	return rc;
}

static int bnxt_hwrm_phy_loopback(struct bnxt *bp, bool enable, bool ext)
{
	struct hwrm_port_phy_cfg_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_PORT_PHY_CFG);
	if (rc)
		return rc;

	/* prevent bnxt_disable_an_for_lpbk() from consuming the request */
	hwrm_req_hold(bp, req);

	if (enable) {
		bnxt_disable_an_for_lpbk(bp, req);
		if (ext)
			req->lpbk = PORT_PHY_CFG_REQ_LPBK_EXTERNAL;
		else
			req->lpbk = PORT_PHY_CFG_REQ_LPBK_LOCAL;
	} else {
		req->lpbk = PORT_PHY_CFG_REQ_LPBK_NONE;
	}
	req->enables = cpu_to_le32(PORT_PHY_CFG_REQ_ENABLES_LPBK);
	rc = hwrm_req_send(bp, req);
	hwrm_req_drop(bp, req);
	return rc;
}

static int bnxt_rx_loopback(struct bnxt *bp, struct bnxt_cp_ring_info *cpr,
			    u32 raw_cons, int pkt_size)
{
	struct bnxt_napi *bnapi = cpr->bnapi;
	struct bnxt_rx_ring_info *rxr;
	struct bnxt_sw_rx_bd *rx_buf;
	struct rx_cmp *rxcmp;
	u16 cp_cons, cons;
	u8 *data;
	u32 len;
	int i;

	rxr = bnapi->rx_ring;
	cp_cons = RING_CMP(raw_cons);
	rxcmp = (struct rx_cmp *)
		&cpr->cp_desc_ring[CP_RING(cp_cons)][CP_IDX(cp_cons)];
	cons = rxcmp->rx_cmp_opaque;
	rx_buf = &rxr->rx_buf_ring[cons];
	data = rx_buf->data_ptr;
	len = le32_to_cpu(rxcmp->rx_cmp_len_flags_type) >> RX_CMP_LEN_SHIFT;
	if (len != pkt_size)
		return -EIO;
	i = ETH_ALEN;
	if (!ether_addr_equal(data + i, bnapi->bp->dev->dev_addr))
		return -EIO;
	i += ETH_ALEN;
	for (  ; i < pkt_size; i++) {
		if (data[i] != (u8)(i & 0xff))
			return -EIO;
	}
	return 0;
}

static int bnxt_poll_loopback(struct bnxt *bp, struct bnxt_cp_ring_info *cpr,
			      int pkt_size)
{
	struct tx_cmp *txcmp;
	int rc = -EIO;
	u32 raw_cons;
	u32 cons;
	int i;

	raw_cons = cpr->cp_raw_cons;
	for (i = 0; i < 200; i++) {
		cons = RING_CMP(raw_cons);
		txcmp = &cpr->cp_desc_ring[CP_RING(cons)][CP_IDX(cons)];

		if (!TX_CMP_VALID(txcmp, raw_cons)) {
			udelay(5);
			continue;
		}

		/* The valid test of the entry must be done first before
		 * reading any further.
		 */
		dma_rmb();
		if (TX_CMP_TYPE(txcmp) == CMP_TYPE_RX_L2_CMP ||
		    TX_CMP_TYPE(txcmp) == CMP_TYPE_RX_L2_V3_CMP) {
			rc = bnxt_rx_loopback(bp, cpr, raw_cons, pkt_size);
			raw_cons = NEXT_RAW_CMP(raw_cons);
			raw_cons = NEXT_RAW_CMP(raw_cons);
			break;
		}
		raw_cons = NEXT_RAW_CMP(raw_cons);
	}
	cpr->cp_raw_cons = raw_cons;
	return rc;
}

static int bnxt_run_loopback(struct bnxt *bp)
{
	struct bnxt_tx_ring_info *txr = &bp->tx_ring[0];
	struct bnxt_rx_ring_info *rxr = &bp->rx_ring[0];
	struct bnxt_cp_ring_info *cpr;
	int pkt_size, i = 0;
	struct sk_buff *skb;
	dma_addr_t map;
	u8 *data;
	int rc;

	cpr = &rxr->bnapi->cp_ring;
	if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
		cpr = rxr->rx_cpr;
	pkt_size = min_t(u32, bp->dev->mtu + ETH_HLEN, BNXT_RX_COPY_THRESH);
	skb = netdev_alloc_skb(bp->dev, pkt_size);
	if (!skb)
		return -ENOMEM;
	data = skb_put(skb, pkt_size);
	ether_addr_copy(&data[i], bp->dev->dev_addr);
	i += ETH_ALEN;
	ether_addr_copy(&data[i], bp->dev->dev_addr);
	i += ETH_ALEN;
	for ( ; i < pkt_size; i++)
		data[i] = (u8)(i & 0xff);

	map = dma_map_single(&bp->pdev->dev, skb->data, pkt_size,
			     DMA_TO_DEVICE);
	if (dma_mapping_error(&bp->pdev->dev, map)) {
		dev_kfree_skb(skb);
		return -EIO;
	}
	bnxt_xmit_bd(bp, txr, map, pkt_size, NULL);

	/* Sync BD data before updating doorbell */
	wmb();

	netdev_dbg(bp->dev, "%s: db_key 0x%llX, tx_prod 0x%x\n",
		   __func__, txr->tx_db.db_key64, txr->tx_prod);
	bnxt_db_write(bp, &txr->tx_db, txr->tx_prod);
	rc = bnxt_poll_loopback(bp, cpr, pkt_size);

	dma_unmap_single(&bp->pdev->dev, map, pkt_size, DMA_TO_DEVICE);
	dev_kfree_skb(skb);
	return rc;
}

static int bnxt_run_fw_tests(struct bnxt *bp, u8 test_mask, u8 *test_results)
{
	struct hwrm_selftest_exec_output *resp;
	struct hwrm_selftest_exec_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_SELFTEST_EXEC);
	if (rc)
		return rc;

	hwrm_req_timeout(bp, req, bp->test_info->timeout);
	req->flags = test_mask;

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	*test_results = resp->test_success;
	hwrm_req_drop(bp, req);
	return rc;
}

#define BNXT_DRV_TESTS			4
#define BNXT_MACLPBK_TEST_IDX		(bp->num_tests - BNXT_DRV_TESTS)
#define BNXT_PHYLPBK_TEST_IDX		(BNXT_MACLPBK_TEST_IDX + 1)
#define BNXT_EXTLPBK_TEST_IDX		(BNXT_MACLPBK_TEST_IDX + 2)
#define BNXT_IRQ_TEST_IDX		(BNXT_MACLPBK_TEST_IDX + 3)

static void bnxt_self_test(struct net_device *dev, struct ethtool_test *etest,
			   u64 *buf)
{
	struct bnxt *bp = netdev_priv(dev);
	bool do_ext_lpbk = false;
	bool offline = false;
	u8 test_results = 0;
	u8 test_mask = 0;
	int rc = 0, i;

	if (!bp->num_tests || !BNXT_PF(bp))
		return;

	memset(buf, 0, sizeof(u64) * bp->num_tests);
	if (etest->flags & ETH_TEST_FL_OFFLINE &&
	    bnxt_ulp_registered(bp->edev)) {
		etest->flags |= ETH_TEST_FL_FAILED;
		netdev_warn(dev, "Offline tests cannot be run with RoCE driver loaded\n");
		return;
	}

	if (!netif_running(dev)) {
		etest->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	if ((etest->flags & ETH_TEST_FL_EXTERNAL_LB) &&
	    (bp->phy_flags & BNXT_PHY_FL_EXT_LPBK))
		do_ext_lpbk = true;

	if (etest->flags & ETH_TEST_FL_OFFLINE) {
		if (bp->pf.active_vfs || !BNXT_SINGLE_PF(bp)) {
			etest->flags |= ETH_TEST_FL_FAILED;
			netdev_warn(dev, "Offline tests cannot be run with active VFs or on shared PF\n");
			return;
		}
		offline = true;
	}

	for (i = 0; i < bp->num_tests - BNXT_DRV_TESTS; i++) {
		u8 bit_val = 1 << i;

		if (!(bp->test_info->offline_mask & bit_val))
			test_mask |= bit_val;
		else if (offline)
			test_mask |= bit_val;
	}
	if (!offline) {
		bnxt_run_fw_tests(bp, test_mask, &test_results);
	} else {
		bnxt_close_nic(bp, true, false);
		bnxt_free_persistent_mpc_rings(bp, true);
		bnxt_free_one_cpr(bp, true);
		bnxt_run_fw_tests(bp, test_mask, &test_results);

		rc = bnxt_half_open_nic(bp);
		if (rc) {
			etest->flags |= ETH_TEST_FL_FAILED;
			return;
		}
		if (bp->mac_flags & BNXT_MAC_FL_NO_MAC_LPBK)
			goto skip_mac_loopback;

		buf[BNXT_MACLPBK_TEST_IDX] = 1;
		bnxt_hwrm_mac_loopback(bp, true);
		msleep(250);
		if (bnxt_run_loopback(bp))
			etest->flags |= ETH_TEST_FL_FAILED;
		else
			buf[BNXT_MACLPBK_TEST_IDX] = 0;

		bnxt_hwrm_mac_loopback(bp, false);
skip_mac_loopback:
		if (bp->phy_flags & BNXT_PHY_FL_NO_PHY_LPBK)
			goto skip_phy_loopback;

		bnxt_hwrm_phy_loopback(bp, true, false);
		msleep(1000);
		if (bnxt_run_loopback(bp)) {
			buf[BNXT_PHYLPBK_TEST_IDX] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
skip_phy_loopback:
		if (do_ext_lpbk) {
			etest->flags |= ETH_TEST_FL_EXTERNAL_LB_DONE;
			bnxt_hwrm_phy_loopback(bp, true, true);
			msleep(1000);
			if (bnxt_run_loopback(bp)) {
				buf[BNXT_EXTLPBK_TEST_IDX] = 1;
				etest->flags |= ETH_TEST_FL_FAILED;
			}
		}
		bnxt_hwrm_phy_loopback(bp, false, false);
		bnxt_half_close_nic(bp);
		bnxt_setup_one_cpr(bp, true);
		bnxt_create_persistent_mpc_rings(bp, true);
		rc = bnxt_open_nic(bp, true, true);
	}
	if (rc || bnxt_test_irq(bp)) {
		buf[BNXT_IRQ_TEST_IDX] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;
	}
	for (i = 0; i < bp->num_tests - BNXT_DRV_TESTS; i++) {
		u8 bit_val = 1 << i;

		if ((test_mask & bit_val) && !(test_results & bit_val)) {
			buf[i] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
	}
}

#if defined(ETHTOOL_GET_TS_INFO) && defined(HAVE_IEEE1588_SUPPORT)
static int bnxt_get_ts_info(struct net_device *dev,
			    struct kernel_ethtool_ts_info *info)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_ptp_cfg *ptp;

	ptp = bp->ptp_cfg;
	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE;

	info->phc_index = -1;
	if (!ptp)
		return 0;

	info->so_timestamping |= SOF_TIMESTAMPING_TX_HARDWARE |
				 SOF_TIMESTAMPING_RX_HARDWARE |
				 SOF_TIMESTAMPING_RAW_HARDWARE;
	if (ptp->ptp_clock)
		info->phc_index = ptp_clock_index(ptp->ptp_clock);

	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
			   (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
			   (1 << HWTSTAMP_FILTER_PTP_V2_L4_EVENT);

	if (bp->fw_cap & BNXT_FW_CAP_RX_ALL_PKT_TS)
		info->rx_filters |= (1 << HWTSTAMP_FILTER_ALL);
	return 0;
}
#endif

#if defined(ETHTOOL_RESET) && !defined(GET_ETHTOOL_OP_EXT)
static int bnxt_hwrm_crashdump_erase(struct net_device *dev, u8 scope)
{
	struct hwrm_dbg_crashdump_erase_input *req;
	struct bnxt *bp = netdev_priv(dev);
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_DBG_CRASHDUMP_ERASE);
	if (rc)
		return rc;

	req->scope = scope;
	hwrm_req_timeout(bp, req, HWRM_COREDUMP_TIMEOUT);
	return hwrm_req_send(bp, req);
}

static int bnxt_reset(struct net_device *dev, u32 *flags)
{
	struct bnxt *bp = netdev_priv(dev);
	u32 req = *flags;

	if (!req)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		netdev_err(dev, "Reset is not supported from a VF\n");
		return -EOPNOTSUPP;
	}

	if (req & BNXT_FW_RESET_CRASHDUMP) {
		if (bp->fw_cap & BNXT_FW_CAP_CRASHDUMP) {
			u8 scope = DBG_CRASHDUMP_ERASE_REQ_SCOPE_INVALIDATE;

			if (!bnxt_hwrm_crashdump_erase(dev, scope)) {
				netdev_info(dev, "Crashdump data erased.\n");
				*flags &= ~BNXT_FW_RESET_CRASHDUMP;
				if (!*flags)
					return 0; /* done, skip VF check */
			}
		} else if (req == BNXT_FW_RESET_CRASHDUMP) {
			return -EOPNOTSUPP; /* only request, fail hard */
		}
	}

	if (pci_vfs_assigned(bp->pdev) &&
	    !(bp->fw_cap & BNXT_FW_CAP_HOT_RESET)) {
		netdev_err(dev,
			   "Reset not allowed when VFs are assigned to VMs\n");
		return -EBUSY;
	}

	if ((req & BNXT_FW_RESET_CHIP) == BNXT_FW_RESET_CHIP) {
		/* This feature is not supported in older firmware versions */
		if (bp->hwrm_spec_code >= 0x10803) {
			if (!__bnxt_firmware_reset_chip(dev, 0)) {
				netdev_info(dev, "Firmware reset request successful.\n");
				netdev_info(dev, "Reload driver to complete reset\n");
				*flags &= ~BNXT_FW_RESET_CHIP;
			}
		} else if (req == BNXT_FW_RESET_CHIP) {
			return -EOPNOTSUPP; /* only request, fail hard */
		}
	}

	if (!BNXT_CHIP_P4_PLUS(bp) && (req & BNXT_FW_RESET_AP)) {
		/* This feature is not supported in older firmware versions */
		if (bp->hwrm_spec_code >= 0x10803) {
			if (!bnxt_firmware_reset_ap(dev)) {
				netdev_info(dev, "Reset application processor successful.\n");
				*flags &= ~BNXT_FW_RESET_AP;
			}
		} else if (req == BNXT_FW_RESET_AP) {
			return -EOPNOTSUPP; /* only request, fail hard */
		}
	}

	return 0;
}
#endif

#if defined(ETHTOOL_GET_DUMP_FLAG) && !defined(GET_ETHTOOL_OP_EXT)
static int bnxt_set_dump(struct net_device *dev, struct ethtool_dump *dump)
{
	struct bnxt *bp = netdev_priv(dev);

	if (dump->flag > BNXT_DUMP_LIVE_WITH_CTX_L1_CACHE) {
		netdev_info(dev,
			    "Supports only Live(0), Crash(1), Driver(2), Live with cached context(3) dumps.\n");
		return -EINVAL;
	}

	if (dump->flag == BNXT_DUMP_CRASH) {
		if (bp->fw_dbg_cap & DBG_QCAPS_RESP_FLAGS_CRASHDUMP_SOC_DDR &&
		    (!IS_ENABLED(CONFIG_TEE_BNXT_FW))) {
			netdev_info(dev,
				    "Cannot collect crash dump as TEE_BNXT_FW config option is not enabled.\n");
			return -EOPNOTSUPP;
		} else if (!(bp->fw_dbg_cap & DBG_QCAPS_RESP_FLAGS_CRASHDUMP_HOST_DDR)) {
			netdev_info(dev, "Crash dump collection from host memory is not supported on this interface.\n");
			return -EOPNOTSUPP;
		}
	}

	bp->dump_flag = dump->flag;
	return 0;
}

static int bnxt_get_dump_flag(struct net_device *dev, struct ethtool_dump *dump)
{
	struct bnxt *bp = netdev_priv(dev);

	if (bp->hwrm_spec_code < 0x10801)
		return -EOPNOTSUPP;

	dump->version = bp->ver_resp.hwrm_fw_maj_8b << 24 |
			bp->ver_resp.hwrm_fw_min_8b << 16 |
			bp->ver_resp.hwrm_fw_bld_8b << 8 |
			bp->ver_resp.hwrm_fw_rsvd_8b;

	dump->flag = bp->dump_flag;
	dump->len = bnxt_get_coredump_length(bp, bp->dump_flag);
	return 0;
}

static int bnxt_get_dump_data(struct net_device *dev, struct ethtool_dump *dump,
			      void *buf)
{
	struct bnxt *bp = netdev_priv(dev);

	if (bp->hwrm_spec_code < 0x10801)
		return -EOPNOTSUPP;

	memset(buf, 0, dump->len);

	dump->flag = bp->dump_flag;
	return bnxt_get_coredump(bp, dump->flag, buf, &dump->len);
}
#endif /* ETHTOOL_GET_DUMP_FLAG */

void bnxt_ethtool_init(struct bnxt *bp)
{
	struct hwrm_selftest_qlist_output *resp;
	struct hwrm_selftest_qlist_input *req;
	struct bnxt_test_info *test_info;
	struct net_device *dev = bp->dev;
	int i, rc;

	if (!(bp->fw_cap & BNXT_FW_CAP_PKG_VER))
		bnxt_get_pkgver(dev);

	bp->num_tests = 0;
	if (bp->hwrm_spec_code < 0x10704 || !BNXT_PF(bp))
		return;

	test_info = bp->test_info;
	if (!test_info) {
		test_info = kzalloc(sizeof(*bp->test_info), GFP_KERNEL);
		if (!test_info)
			return;
		bp->test_info = test_info;
	}

	if (hwrm_req_init(bp, req, HWRM_SELFTEST_QLIST))
		return;

	hwrm_req_flags(bp, req, BNXT_HWRM_CTX_SILENT);
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (rc) {
		if (rc != -EACCES)
			netdev_warn(bp->dev,
				    "Expected firmware self tests unavailable (err: %d)\n",
				    rc);
		goto ethtool_init_exit;
	}

	bp->num_tests = resp->num_tests + BNXT_DRV_TESTS;
	if (bp->num_tests > BNXT_MAX_TEST)
		bp->num_tests = BNXT_MAX_TEST;

	test_info->offline_mask = resp->offline_tests;
	test_info->timeout = le16_to_cpu(resp->test_timeout);
	if (!test_info->timeout)
		test_info->timeout = HWRM_CMD_TIMEOUT;
	for (i = 0; i < bp->num_tests; i++) {
		char *str = test_info->string[i];
		char *fw_str = resp->test_name[i];

		if (i == BNXT_MACLPBK_TEST_IDX) {
			strcpy(str, "Mac loopback test (offline)");
		} else if (i == BNXT_PHYLPBK_TEST_IDX) {
			strcpy(str, "Phy loopback test (offline)");
		} else if (i == BNXT_EXTLPBK_TEST_IDX) {
			strcpy(str, "Ext loopback test (offline)");
		} else if (i == BNXT_IRQ_TEST_IDX) {
			strcpy(str, "Interrupt_test (online)");
		} else {
			snprintf(str, ETH_GSTRING_LEN, "%s test (%s)",
				 fw_str, test_info->offline_mask & (1 << i) ?
					"offline" : "online");
		}
	}

ethtool_init_exit:
	hwrm_req_drop(bp, req);
}

#ifdef ETHTOOL_RMON_HIST_MAX
static void bnxt_get_eth_phy_stats(struct net_device *dev,
				   struct ethtool_eth_phy_stats *phy_stats)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS_EXT))
		return;

	rx = bp->rx_port_stats_ext.sw_stats;
	phy_stats->SymbolErrorDuringCarrier =
		*(rx + BNXT_RX_STATS_EXT_OFFSET(rx_pcs_symbol_err));
}

static void bnxt_get_eth_mac_stats(struct net_device *dev,
				   struct ethtool_eth_mac_stats *mac_stats)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx, *tx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS))
		return;

	rx = bp->port_stats.sw_stats;
	tx = bp->port_stats.sw_stats + BNXT_TX_PORT_STATS_BYTE_OFFSET / 8;

	mac_stats->FramesReceivedOK =
		BNXT_GET_RX_PORT_STATS64(rx, rx_good_frames);
	mac_stats->FramesTransmittedOK =
		BNXT_GET_TX_PORT_STATS64(tx, tx_good_frames);
	mac_stats->FrameCheckSequenceErrors =
		BNXT_GET_RX_PORT_STATS64(rx, rx_fcs_err_frames);
	mac_stats->AlignmentErrors =
		BNXT_GET_RX_PORT_STATS64(rx, rx_align_err_frames);
	mac_stats->OutOfRangeLengthField =
		BNXT_GET_RX_PORT_STATS64(rx, rx_oor_len_frames);
}

static void bnxt_get_eth_ctrl_stats(struct net_device *dev,
				    struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS))
		return;

	rx = bp->port_stats.sw_stats;
	ctrl_stats->MACControlFramesReceived =
		BNXT_GET_RX_PORT_STATS64(rx, rx_ctrl_frames);
}

static const struct ethtool_rmon_hist_range bnxt_rmon_ranges[] = {
	{    0,    64 },
	{   65,   127 },
	{  128,   255 },
	{  256,   511 },
	{  512,  1023 },
	{ 1024,  1518 },
	{ 1519,  2047 },
	{ 2048,  4095 },
	{ 4096,  9216 },
	{ 9217, 16383 },
	{}
};

static void bnxt_get_rmon_stats(struct net_device *dev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx, *tx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS))
		return;

	rx = bp->port_stats.sw_stats;
	tx = bp->port_stats.sw_stats + BNXT_TX_PORT_STATS_BYTE_OFFSET / 8;

	rmon_stats->jabbers =
		BNXT_GET_RX_PORT_STATS64(rx, rx_jbr_frames);
	rmon_stats->oversize_pkts =
		BNXT_GET_RX_PORT_STATS64(rx, rx_ovrsz_frames);
	rmon_stats->undersize_pkts =
		BNXT_GET_RX_PORT_STATS64(rx, rx_undrsz_frames);

	rmon_stats->hist[0] = BNXT_GET_RX_PORT_STATS64(rx, rx_64b_frames);
	rmon_stats->hist[1] = BNXT_GET_RX_PORT_STATS64(rx, rx_65b_127b_frames);
	rmon_stats->hist[2] = BNXT_GET_RX_PORT_STATS64(rx, rx_128b_255b_frames);
	rmon_stats->hist[3] = BNXT_GET_RX_PORT_STATS64(rx, rx_256b_511b_frames);
	rmon_stats->hist[4] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_512b_1023b_frames);
	rmon_stats->hist[5] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_1024b_1518b_frames);
	rmon_stats->hist[6] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_1519b_2047b_frames);
	rmon_stats->hist[7] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_2048b_4095b_frames);
	rmon_stats->hist[8] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_4096b_9216b_frames);
	rmon_stats->hist[9] =
		BNXT_GET_RX_PORT_STATS64(rx, rx_9217b_16383b_frames);

	rmon_stats->hist_tx[0] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_64b_frames);
	rmon_stats->hist_tx[1] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_65b_127b_frames);
	rmon_stats->hist_tx[2] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_128b_255b_frames);
	rmon_stats->hist_tx[3] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_256b_511b_frames);
	rmon_stats->hist_tx[4] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_512b_1023b_frames);
	rmon_stats->hist_tx[5] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_1024b_1518b_frames);
	rmon_stats->hist_tx[6] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_1519b_2047b_frames);
	rmon_stats->hist_tx[7] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_2048b_4095b_frames);
	rmon_stats->hist_tx[8] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_4096b_9216b_frames);
	rmon_stats->hist_tx[9] =
		BNXT_GET_TX_PORT_STATS64(tx, tx_9217b_16383b_frames);

	*ranges = bnxt_rmon_ranges;
}
#endif

#ifdef ETHTOOL_PTP_STATS
static void bnxt_get_ptp_stats(struct net_device *dev,
			       struct ethtool_ts_stats *ts_stats)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;

	if (ptp) {
		ts_stats->pkts = ptp->stats.ts_pkts;
		ts_stats->lost = ptp->stats.ts_lost;
		ts_stats->err = atomic64_read(&ptp->stats.ts_err);
	}
}
#endif

static int bnxt_set_priv_flags(struct net_device *dev, u32 flags)
{
	struct bnxt *bp = netdev_priv(dev);
	bool reload = false;
	int rc = 0;

	if (flags >> ARRAY_SIZE(bnxt_priv_flags))
		return -EINVAL;

	if (flags & (1 << BNXT_PRIV_FLAG_CORE_RESET_TX_TIMEOUT)) {
		if (!bnxt_core_reset_avail(bp))
			return -EOPNOTSUPP;
		bp->flags |= BNXT_FLAG_CORE_RESET_TX_TIMEOUT;
	} else {
		bp->flags &= ~BNXT_FLAG_CORE_RESET_TX_TIMEOUT;
	}

	if (flags & (1 << BNXT_PRIV_FLAG_NUMA_DIRECT)) {
		if (~bp->flags & BNXT_FLAG_MULTI_ROOT)
			return -EOPNOTSUPP;
		reload |= !(bp->flags & BNXT_FLAG_NUMA_DIRECT);
		bp->flags |= BNXT_FLAG_NUMA_DIRECT;
	} else {
		reload |= !!(bp->flags & BNXT_FLAG_NUMA_DIRECT);
		bp->flags &= ~BNXT_FLAG_NUMA_DIRECT;
	}

	/* Check this flag while configuring ipv6 n-tuple */
	if (flags & (1 << BNXT_PRIV_FLAG_RSS_IPV6_FLOW_LABEL_EN)) {
		/* Reject if HW in-capable */
		if (!(bp->rss_cap & BNXT_RSS_CAP_IPV6_FLOW_LABEL_CAP))
			return -EOPNOTSUPP;
		bp->ipv6_flow_lbl_rss_en = 1;
	} else {
		bp->ipv6_flow_lbl_rss_en = 0;
	}

	if (reload && netif_running(dev)) {
		bnxt_close_nic(bp, true, false);
		rc = bnxt_open_nic(bp, true, false);
	}

	return rc;
}

static u32 bnxt_get_priv_flags(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);
	u32 flags = 0;

	if (bp->flags & BNXT_FLAG_NUMA_DIRECT)
		flags |= 1 << BNXT_PRIV_FLAG_NUMA_DIRECT;

	if (bp->flags & BNXT_FLAG_CORE_RESET_TX_TIMEOUT)
		flags |= 1 << BNXT_PRIV_FLAG_CORE_RESET_TX_TIMEOUT;

	if (bp->ipv6_flow_lbl_rss_en)
		flags |= 1 << BNXT_PRIV_FLAG_RSS_IPV6_FLOW_LABEL_EN;

	return flags;
}

#ifdef HAVE_ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT
static void bnxt_get_link_ext_stats(struct net_device *dev,
				    struct ethtool_link_ext_stats *stats)
{
	struct bnxt *bp = netdev_priv(dev);
	u64 *rx;

	if (BNXT_VF(bp) || !(bp->flags & BNXT_FLAG_PORT_STATS_EXT))
		return;

	rx = bp->rx_port_stats_ext.sw_stats;
	stats->link_down_events =
		*(rx + BNXT_RX_STATS_EXT_OFFSET(link_down_events));
}
#endif

static int bnxt_hwrm_pfcwd_qcfg(struct bnxt *bp)
{
	struct hwrm_queue_pfcwd_timeout_qcfg_output *resp;
	struct hwrm_queue_pfcwd_timeout_qcfg_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_QUEUE_PFCWD_TIMEOUT_QCFG);
	if (rc)
		return rc;
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		rc = le16_to_cpu(resp->pfcwd_timeout_value);
	hwrm_req_drop(bp, req);
	return rc;
}

static int bnxt_hwrm_pfcwd_cfg(struct bnxt *bp, u16 val)
{
	struct hwrm_queue_pfcwd_timeout_cfg_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_QUEUE_PFCWD_TIMEOUT_CFG);
	if (rc)
		return rc;
	req->pfcwd_timeout_value = cpu_to_le16(val);
	rc = hwrm_req_send(bp, req);
	return rc;
}

static int bnxt_set_tunable(struct net_device *dev,
			    const struct ethtool_tunable *tuna,
			    const void *data)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc = 0;
	u32 val;

	switch (tuna->id) {
	case ETHTOOL_RX_COPYBREAK:
		val = *(u32 *)data;
		if ((val < BNXT_RX_MIN_COPY_THRESH && val) ||
		    val > BNXT_RX_MAX_COPY_THRESH)
			return -EINVAL;

		if (val != bp->rx_copy_thresh) {
			bp->rx_copy_thresh = val;
			bnxt_close_nic(bp, false, false);
			rc = bnxt_open_nic(bp, false, false);
		}
		return rc;
	case ETHTOOL_PFC_PREVENTION_TOUT: {
		int rc;

		if (BNXT_VF(bp) || !bp->max_pfcwd_tmo_ms)
			return -EOPNOTSUPP;

		val = *(u16 *)data;
		if (val > bp->max_pfcwd_tmo_ms &&
		    val != PFC_STORM_PREVENTION_AUTO)
			return -EINVAL;
		rc = bnxt_hwrm_pfcwd_cfg(bp, val);
		return rc;
	}
	default:
		return -EOPNOTSUPP;
	}
}

static int bnxt_get_tunable(struct net_device *dev,
			    const struct ethtool_tunable *tuna, void *data)
{
	struct bnxt *bp = netdev_priv(dev);

	switch (tuna->id) {
	case ETHTOOL_RX_COPYBREAK:
		*(u32 *)data = bp->rx_copy_thresh;
		return 0;
	case ETHTOOL_PFC_PREVENTION_TOUT: {
		int rc;

		if (!bp->max_pfcwd_tmo_ms)
			return -EOPNOTSUPP;
		rc = bnxt_hwrm_pfcwd_qcfg(bp);
		if (rc < 0)
			return rc;
		*(u16 *)data = rc;
		return 0;
	}
	default:
		return -EOPNOTSUPP;
	}
}

void bnxt_ethtool_free(struct bnxt *bp)
{
	kfree(bp->test_info);
	bp->test_info = NULL;
}

const struct ethtool_ops bnxt_ethtool_ops = {
#ifdef HAVE_ETHTOOL_LANES
	.cap_link_lanes_supported	= 1,
#endif
#ifdef HAVE_NEW_RSSCTX_INTERFACE
	.rxfh_max_num_contexts		= BNXT_MAX_ETH_RSS_CTX + 1,
	.rxfh_indir_space		= BNXT_MAX_RSS_TABLE_ENTRIES_P5,
	.rxfh_priv_size			= sizeof(struct bnxt_rss_ctx),
	.cap_rss_ctx_supported		= 1,
#endif
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params	= ETHTOOL_COALESCE_USECS |
					  ETHTOOL_COALESCE_MAX_FRAMES |
					  ETHTOOL_COALESCE_USECS_IRQ |
					  ETHTOOL_COALESCE_MAX_FRAMES_IRQ |
					  ETHTOOL_COALESCE_STATS_BLOCK_USECS |
					  ETHTOOL_COALESCE_USE_ADAPTIVE_RX |
					  ETHTOOL_COALESCE_USE_CQE,
#endif
#ifdef HAVE_ETHTOOL_LINK_KSETTINGS
	.get_link_ksettings	= bnxt_get_link_ksettings,
	.set_link_ksettings	= bnxt_set_link_ksettings,
#else
	.get_settings		= bnxt_get_settings,
	.set_settings		= bnxt_set_settings,
#endif
#ifdef ETHTOOL_MAX_LANES
	.get_fec_stats		= bnxt_get_fec_stats,
#endif
#ifdef ETHTOOL_GFECPARAM
	.get_fecparam		= bnxt_get_fecparam,
	.set_fecparam		= bnxt_set_fecparam,
#endif
#ifdef HAVE_GET_PAUSE_STATS
	.get_pause_stats	= bnxt_get_pause_stats,
#endif
	.get_pauseparam		= bnxt_get_pauseparam,
	.set_pauseparam		= bnxt_set_pauseparam,
	.get_drvinfo		= bnxt_get_drvinfo,
	.get_regs_len		= bnxt_get_regs_len,
	.get_regs		= bnxt_get_regs,
	.get_wol		= bnxt_get_wol,
	.set_wol		= bnxt_set_wol,
	.get_coalesce		= bnxt_get_coalesce,
	.set_coalesce		= bnxt_set_coalesce,
#ifdef HAVE_ETHTOOL_GET_PER_QUEUE_COAL
	.get_per_queue_coalesce = bnxt_get_per_queue_coalesce,
#endif
	.get_msglevel		= bnxt_get_msglevel,
	.set_msglevel		= bnxt_set_msglevel,
	.get_sset_count		= bnxt_get_sset_count,
	.get_strings		= bnxt_get_strings,
	.get_ethtool_stats	= bnxt_get_ethtool_stats,
	.set_ringparam		= bnxt_set_ringparam,
	.get_ringparam		= bnxt_get_ringparam,
#if defined(ETHTOOL_GCHANNELS) && !defined(GET_ETHTOOL_OP_EXT)
	.get_channels		= bnxt_get_channels,
	.set_channels		= bnxt_set_channels,
#endif
#ifdef HAVE_RXNFC
	.get_rxnfc		= bnxt_get_rxnfc,
	.set_rxnfc		= bnxt_set_rxnfc,
#endif
#if defined(HAVE_RXFH_INDIR_SIZE) && !defined(GET_ETHTOOL_OP_EXT)
	.get_rxfh_indir_size    = bnxt_get_rxfh_indir_size,
#endif
#if defined(HAVE_GET_RXFH_KEY_SIZE) && !defined(GET_ETHTOOL_OP_EXT)
	.get_rxfh_key_size      = bnxt_get_rxfh_key_size,
	.get_rxfh               = bnxt_get_rxfh,
#endif
#if defined(HAVE_SET_RXFH) && defined(ETH_RSS_HASH_TOP) && !defined(GET_ETHTOOL_OP_EXT)
	.set_rxfh		= bnxt_set_rxfh,
#endif
#ifdef HAVE_NEW_RSSCTX_INTERFACE
	.create_rxfh_context	= bnxt_create_rxfh_context,
	.modify_rxfh_context	= bnxt_modify_rxfh_context,
	.remove_rxfh_context	= bnxt_remove_rxfh_context,
#endif
	.flash_device		= bnxt_flash_device,
	.get_eeprom_len         = bnxt_get_eeprom_len,
	.get_eeprom             = bnxt_get_eeprom,
	.set_eeprom		= bnxt_set_eeprom,
	.get_link		= bnxt_get_link,
#ifdef HAVE_ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT
	.get_link_ext_stats	= bnxt_get_link_ext_stats,
#endif
#if defined(ETHTOOL_GEEE) && !defined(GET_ETHTOOL_OP_EXT)
	.get_eee		= bnxt_get_eee,
	.set_eee		= bnxt_set_eee,
#endif
#if defined(ETHTOOL_GMODULEEEPROM) && !defined(GET_ETHTOOL_OP_EXT)
	.get_module_info	= bnxt_get_module_info,
	.get_module_eeprom	= bnxt_get_module_eeprom,
#endif
#if defined(HAVE_MODULE_EEPROM_BY_PAGE)
	.get_module_eeprom_by_page = bnxt_get_module_eeprom_by_page,
#endif
	.nway_reset		= bnxt_nway_reset,
#if (LINUX_VERSION_CODE < 0x30000)
	.phys_id		= bnxt_phys_id,
#else
#if defined(HAVE_SET_PHYS_ID) && !defined(GET_ETHTOOL_OP_EXT)
	.set_phys_id		= bnxt_set_phys_id,
#endif
#endif
	.self_test		= bnxt_self_test,
#if defined(ETHTOOL_GET_TS_INFO) && defined(HAVE_IEEE1588_SUPPORT)
	.get_ts_info		= bnxt_get_ts_info,
#endif
#if defined(ETHTOOL_RESET) && !defined(GET_ETHTOOL_OP_EXT)
	.reset			= bnxt_reset,
#endif
#if defined(ETHTOOL_GET_DUMP_FLAG) && !defined(GET_ETHTOOL_OP_EXT)
	.set_dump		= bnxt_set_dump,
	.get_dump_flag		= bnxt_get_dump_flag,
	.get_dump_data		= bnxt_get_dump_data,
#endif
#ifdef ETHTOOL_RMON_HIST_MAX
	.get_eth_phy_stats	= bnxt_get_eth_phy_stats,
	.get_eth_mac_stats	= bnxt_get_eth_mac_stats,
	.get_eth_ctrl_stats	= bnxt_get_eth_ctrl_stats,
	.get_rmon_stats		= bnxt_get_rmon_stats,
#endif
#ifdef ETHTOOL_PTP_STATS
	.get_ts_stats		= bnxt_get_ptp_stats,
#endif
	.get_priv_flags		= bnxt_get_priv_flags,
	.set_priv_flags		= bnxt_set_priv_flags,
#if defined(HAVE_ETH_RXFH_CONTEXT_ALLOC) && defined(ETH_RSS_HASH_TOP) && \
	!defined(GET_ETHTOOL_OP_EXT)
	.set_rxfh_context	= bnxt_set_rxfh_context,
	.get_rxfh_context	= bnxt_get_rxfh_context,
#endif
	.set_tunable		= bnxt_set_tunable,
	.get_tunable		= bnxt_get_tunable,
};
