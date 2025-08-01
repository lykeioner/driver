/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2017-2018 Broadcom Limited
 * Copyright (c) 2018-2024 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_PTP_H
#define BNXT_PTP_H

#ifdef HAVE_IEEE1588_SUPPORT
#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>
#endif

#define BNXT_PTP_GRC_WIN	6
#define BNXT_PTP_GRC_WIN_BASE	0x6000

#define BNXT_PTP_GRC_WIN_VF		1
#define BNXT_PTP_GRC_WIN_BASE_VF	0x1000

#define BNXT_MAX_PHC_DRIFT	31000000
#define BNXT_CYCLES_SHIFT	23
#define BNXT_DEVCLK_FREQ	1000000
#define BNXT_LO_TIMER_MASK	0x0000ffffffffUL
#define BNXT_HI_TIMER_MASK	0xffff00000000UL
#define BNXT_HI_TIMER_MASK64	0xffff000000000000UL

#define BNXT_PTP_DFLT_TX_TMO	1000 /* ms */
#define BNXT_PTP_QTS_TIMEOUT(bp)	(((bp)->flags & BNXT_FLAG_CHIP_P5_PLUS) ? 1000 : 62000)
#define BNXT_PTP_QTS_MAX_TMO_US	65535U
#define BNXT_PTP_QTS_TX_ENABLES	(PORT_TS_QUERY_REQ_ENABLES_PTP_SEQ_ID |	\
				 PORT_TS_QUERY_REQ_ENABLES_TS_REQ_TIMEOUT | \
				 PORT_TS_QUERY_REQ_ENABLES_PTP_HDR_OFFSET)

#define BNXT_PTP_QTS_RX_ENABLES        (PORT_TS_QUERY_REQ_ENABLES_PTP_SEQ_ID)
struct pps_pin {
	u8 event;
	u8 usage;
	u8 state;
};

#define TSIO_PIN_VALID(pin) ((pin) >= 0 && (pin) < (BNXT_MAX_TSIO_PINS))

#define EVENT_DATA2_PPS_EVENT_TYPE(data2)				\
	((data2) & ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_EVENT_TYPE)

#define EVENT_DATA2_PPS_PIN_NUM(data2)					\
	(((data2) &							\
	  ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PIN_NUMBER_MASK) >>\
	 ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PIN_NUMBER_SFT)

#define BNXT_DATA2_UPPER_MSK						\
	ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PPS_TIMESTAMP_UPPER_MASK

#define BNXT_DATA2_UPPER_SFT						\
	(32 -								\
	 ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PPS_TIMESTAMP_UPPER_SFT)

#define BNXT_DATA1_LOWER_MSK						\
	ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA1_PPS_TIMESTAMP_LOWER_MASK

#define BNXT_DATA1_LOWER_SFT						\
	  ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA1_PPS_TIMESTAMP_LOWER_SFT

#define EVENT_PPS_TS(data2, data1)					\
	(((u64)((data2) & BNXT_DATA2_UPPER_MSK) << BNXT_DATA2_UPPER_SFT) |\
	 (((data1) & BNXT_DATA1_LOWER_MSK) >> BNXT_DATA1_LOWER_SFT))

#define BNXT_PPS_PIN_DISABLE	0
#define BNXT_PPS_PIN_ENABLE	1
#define BNXT_PPS_PIN_NONE	0
#define BNXT_PPS_PIN_PPS_IN	1
#define BNXT_PPS_PIN_PPS_OUT	2
#define BNXT_PPS_PIN_SYNC_IN	3
#define BNXT_PPS_PIN_SYNC_OUT	4

#define BNXT_PPS_EVENT_INTERNAL	1
#define BNXT_PPS_EVENT_EXTERNAL	2

struct bnxt_pps {
	u8 num_pins;
#define BNXT_MAX_TSIO_PINS	4
	struct pps_pin pins[BNXT_MAX_TSIO_PINS];
};

#define BNXT_MAX_TX_TS		4
#define NEXT_TXTS(idx)		(((idx) + 1) & (BNXT_MAX_TX_TS - 1))

struct bnxt_ptp_tx_req {
	struct sk_buff		*tx_skb;
	u16			tx_seqid;
	u16			tx_hdr_off;
	unsigned long		abs_txts_tmo;
};

struct bnxt_ptp_stats {
	u64		ts_pkts;
	u64		ts_lost;
	atomic64_t	ts_err;
};

struct bnxt_ptp_cfg {
#ifdef HAVE_IEEE1588_SUPPORT
	struct ptp_clock_info	ptp_info;
	struct ptp_clock	*ptp_clock;
	struct cyclecounter	cc;
	struct timecounter	tc;
	struct bnxt_pps		pps_info;
	/* serialize timecounter access */
	spinlock_t		ptp_lock;
	/* serialize ts tx request queuing */
	spinlock_t		ptp_tx_lock;
	struct sk_buff          *rx_skb;
	struct bnxt_napi        *bnapi;
	u32                     vlan;
	u64			current_time;
	u64			old_time;
	u64                     skb_pre_xmit_ts;
	u64			save_ts;
#if !defined HAVE_PTP_DO_AUX_WORK
	struct work_struct	ptp_ts_task;
#else
	unsigned long		next_period;
#endif
	unsigned long		next_overflow_check;
	u32			cmult;
	/* a 23b shift cyclecounter will overflow in ~36 mins.  Check overflow every 18 mins. */
	#define BNXT_PHC_OVERFLOW_PERIOD	(18 * 60 * HZ)

	struct bnxt_ptp_tx_req	txts_req[BNXT_MAX_TX_TS];
	u16                     rx_seqid;
#endif
	struct bnxt		*bp;
	u8			tx_avail;
	u16			rxctl;
#define BNXT_PTP_MSG_SYNC			(1 << 0)
#define BNXT_PTP_MSG_DELAY_REQ			(1 << 1)
#define BNXT_PTP_MSG_PDELAY_REQ			(1 << 2)
#define BNXT_PTP_MSG_PDELAY_RESP		(1 << 3)
#define BNXT_PTP_MSG_FOLLOW_UP			(1 << 8)
#define BNXT_PTP_MSG_DELAY_RESP			(1 << 9)
#define BNXT_PTP_MSG_PDELAY_RESP_FOLLOW_UP	(1 << 10)
#define BNXT_PTP_MSG_ANNOUNCE			(1 << 11)
#define BNXT_PTP_MSG_SIGNALING			(1 << 12)
#define BNXT_PTP_MSG_MANAGEMENT			(1 << 13)
#define BNXT_PTP_MSG_EVENTS		(BNXT_PTP_MSG_SYNC |		\
					 BNXT_PTP_MSG_DELAY_REQ |	\
					 BNXT_PTP_MSG_PDELAY_REQ |	\
					 BNXT_PTP_MSG_PDELAY_RESP)
	u8			tx_tstamp_en:1;
	u8			rtc_configured:1;
	u8			shutdown:1;
	int			rx_filter;
	u32			tstamp_filters;

	u32			refclk_regs[2];
	u32			refclk_mapped_regs[2];
	u32			txts_tmo;
	u16			txts_prod;
	u16			txts_cons;
	struct bnxt_ptp_stats	stats;
};

#if BITS_PER_LONG == 32
#define BNXT_READ_TIME64(ptp, dst, src)		\
do {						\
	spin_lock_bh(&(ptp)->ptp_lock);		\
	(dst) = (src);				\
	spin_unlock_bh(&(ptp)->ptp_lock);	\
} while (0)
#else
#define BNXT_READ_TIME64(ptp, dst, src)		\
	((dst) = READ_ONCE(src))
#endif

#define BNXT_PTP_INC_TX_AVAIL(ptp)	\
do {					\
	spin_lock_bh(&(ptp)->ptp_tx_lock);	\
	(ptp)->tx_avail++;			\
	spin_unlock_bh(&(ptp)->ptp_tx_lock);	\
} while (0)

int bnxt_ptp_parse(struct sk_buff *skb, u16 *seq_id, u16 *hdr_off);
void bnxt_ptp_pps_event(struct bnxt *bp, u32 data1, u32 data2);
void bnxt_ptp_reapply_pps(struct bnxt *bp);
void bnxt_ptp_reapply_phc(struct bnxt *bp);
#ifndef HAVE_PTP_DO_AUX_WORK
void bnxt_ptp_timer(struct bnxt *bp);
#endif
int bnxt_hwtstamp_set(struct net_device *dev, struct ifreq *ifr);
int bnxt_hwtstamp_get(struct net_device *dev, struct ifreq *ifr);
int bnxt_get_rx_ts_p5(struct bnxt *bp, u64 *ts, u32 pkt_ts);
int bnxt_get_rx_ts(struct bnxt *bp, struct bnxt_napi *bnapi, u32 vlan, struct sk_buff *skb);
int bnxt_get_tx_ts(struct bnxt *bp, struct sk_buff *skb, u16 prod);
void bnxt_tx_ts_cmp(struct bnxt *bp, struct bnxt_napi *bnapi,
		    struct tx_ts_cmp *tscmp);
int bnxt_ptp_init(struct bnxt *bp);
void bnxt_ptp_clear(struct bnxt *bp);
void bnxt_ptp_rtc_timecounter_init(struct bnxt_ptp_cfg *ptp, u64 ns);
int bnxt_ptp_init_rtc(struct bnxt *bp, bool phc_cfg);
void bnxt_ptp_update_current_time(struct bnxt *bp);
void bnxt_ptp_cfg_tstamp_filters(struct bnxt *bp);
void bnxt_ptp_get_skb_pre_xmit_ts(struct bnxt *bp);
void bnxt_save_pre_reset_ts(struct bnxt *bp);
int bnxt_ptp_get_txts_prod(struct bnxt_ptp_cfg *ptp, u16 *prod);
#endif
