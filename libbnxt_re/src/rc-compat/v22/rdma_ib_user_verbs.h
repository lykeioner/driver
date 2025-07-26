/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RDMA_IB_USER_VERBS_H
#define RDMA_IB_USER_VERBS_H

#include <linux/types.h>

/*
 * Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */
#define IB_USER_VERBS_ABI_VERSION	6
#define IB_USER_VERBS_CMD_THRESHOLD    50

#ifndef IB_USER_VERBS_EX_CMD_MODIFY_CQ
#define IB_USER_VERBS_EX_CMD_MODIFY_CQ 57
#endif

#ifndef HAVE_FLOW_SPEC
struct ib_uverbs_flow_spec_action_handle {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		};
	};
	__u32			      handle;
	__u32			      reserved1;
};

struct ib_uverbs_flow_spec_action_count {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		};
	};
	__u32			      handle;
	__u32			      reserved1;
};

struct ib_uverbs_flow_spec_esp_filter {
	__u32 spi;
	__u32 seq;
};

struct ib_uverbs_flow_spec_esp {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		};
	};
	struct ib_uverbs_flow_spec_esp_filter val;
	struct ib_uverbs_flow_spec_esp_filter mask;
};

struct ib_uverbs_flow_gre_filter {
	/* c_ks_res0_ver field is bits 0-15 in offset 0 of a standard GRE header:
	 * bit 0 - C - checksum bit.
	 * bit 1 - reserved. set to 0.
	 * bit 2 - key bit.
	 * bit 3 - sequence number bit.
	 * bits 4:12 - reserved. set to 0.
	 * bits 13:15 - GRE version.
	 */
	__be16 c_ks_res0_ver;
	__be16 protocol;
	__be32 key;
};

struct ib_uverbs_flow_spec_gre {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		};
	};
	struct ib_uverbs_flow_gre_filter     val;
	struct ib_uverbs_flow_gre_filter     mask;
};


struct ib_uverbs_flow_mpls_filter {
	/* The field includes the entire MPLS label:
	 * bits 0:19 - label field.
	 * bits 20:22 - traffic class field.
	 * bits 23 - bottom of stack bit.
	 * bits 24:31 - ttl field.
	 */
	__be32 label;
};

struct ib_uverbs_flow_spec_mpls {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		};
	};
	struct ib_uverbs_flow_mpls_filter     val;
	struct ib_uverbs_flow_mpls_filter     mask;
};
#endif /* HAVE_FLOW_SPEC */

#ifndef HAVE_UVERBS_CQ_MOD_ST
struct ib_uverbs_cq_moderation {
	__u16 cq_count;
	__u16 cq_period;
};
#endif /* HAVE_UVERBS_CQ_MOD_ST */

#ifndef HAVE_UVERBS_EX_MODIFY_CQ_ST
struct ib_uverbs_ex_modify_cq {
	__u32 cq_handle;
	__u32 attr_mask;
	struct ib_uverbs_cq_moderation attr;
	__u32 reserved;
};
#endif /* HAVE_UVERBS_EX_MODIFY_CQ_ST */
#endif
