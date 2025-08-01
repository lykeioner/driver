/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2016-2018 Broadcom Limited
 * Copyright (c) 2018-2024 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_XDP_H
#define BNXT_XDP_H

DECLARE_STATIC_KEY_FALSE(bnxt_xdp_locking_key);

struct bnxt_sw_tx_bd *bnxt_xmit_bd(struct bnxt *bp,
				   struct bnxt_tx_ring_info *txr,
				   dma_addr_t mapping, u32 len,
				   struct xdp_buff *xdp);
void __bnxt_xmit_xdp(struct bnxt *bp, struct bnxt_tx_ring_info *txr,
		     dma_addr_t mapping, u32 len, u16 rx_prod,
		     struct xdp_buff *xdp);
void bnxt_tx_int_xdp(struct bnxt *bp, struct bnxt_napi *bnapi, int budget);
#ifdef HAVE_NDO_XDP
bool bnxt_rx_xdp(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 struct xdp_buff *xdp, struct page *page, u8 **data_ptr,
		 unsigned int *len, u8 *event);
bool bnxt_rx_xsk(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 struct xdp_buff *xdp, u8 **data_ptr,
		 unsigned int *len, u8 *event);
#else
bool bnxt_rx_xdp(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 struct xdp_buff *xdp, void *page, u8 **data_ptr,
		 unsigned int *len, u8 *event);
bool bnxt_rx_xsk(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 struct xdp_buff *xdp, u8 **data_ptr,
		 unsigned int *len, u8 *event);
#endif
int bnxt_xdp(struct net_device *dev, struct netdev_bpf *xdp);
#ifdef HAVE_XDP_FRAME
int bnxt_xdp_xmit(struct net_device *dev, int num_frames,
		  struct xdp_frame **frames, u32 flags);
#endif
bool bnxt_xdp_attached(struct bnxt *bp, struct bnxt_rx_ring_info *rxr);

void bnxt_xdp_buff_init(struct bnxt *bp, struct bnxt_rx_ring_info *rxr,
			u16 cons, u8 *data_ptr, unsigned int len,
			struct xdp_buff *xdp);
#ifdef HAVE_XDP_MULTI_BUFF
struct sk_buff *bnxt_xdp_build_skb(struct bnxt *bp, struct sk_buff *skb,
				   u8 num_frags, struct page_pool *pool,
				   struct xdp_buff *xdp,
				   struct rx_cmp_ext *rxcmp1);
void bnxt_xdp_buff_frags_free(struct bnxt_rx_ring_info *rxr,
			      struct xdp_buff *xdp);
#endif
#endif
