/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __XS_COMMS_H__
#define __XS_COMMS_H__

#include <xen/public/io/xs_wire.h>
#include <xen/xenbus/xenbus.h>

int xs_comms_init(struct xs_handler *hdlr);
void xenbus_main_thrd(void *p1, void *p2, void *p3);

struct xs_iovec {
	void *data;
	unsigned int len;
};

/*
 * In-flight request structure.
 */
struct xs_request {
	/**< used when queueing requests */
	sys_snode_t next;
	/**< Waiting queue for incoming reply notification */
	struct k_sem sem;
	/**< Request header */
	struct xsd_sockmsg hdr;
	/**< Request payload iovecs */
	const struct xs_iovec *payload_iovecs;
	/**< Received reply */
	struct {
		/**< Reply string + size */
		struct xs_iovec iovec;
		/**< Error number */
		int errornum;
		/**< Non-zero for incoming replies */
		int recvd;
	} reply;
};

/* Round up and count number of longs */
#define BITS_TO_LONGS(size) (BITS_PER_LONG - 1 + size)/(BITS_PER_LONG)

/*
 * Pool of in-flight requests.
 * Request IDs are reused, hence the limited set of entries.
 */
struct xs_request_pool {
	/**< Number of live requests */
	uint32_t num_live;
	/**< Last probed request index */
	uint32_t last_probed;
	/**< Lock */
	struct k_spinlock lock;
	/**< Waiting queue for 'not-full' notifications */
	struct k_sem sem;
	/**< Queue for requests to be sent */
	sys_slist_t queued;

	/* Map size is power of 2 */
#define XS_REQ_POOL_SHIFT	5
#define XS_REQ_POOL_SIZE	(1 << XS_REQ_POOL_SHIFT)
#define XS_REQ_POOL_MASK	(XS_REQ_POOL_SIZE - 1)
#define XS_REQ_BM_SIZE		BITS_TO_LONGS(XS_REQ_POOL_SIZE)

	unsigned long entries_bm[XS_REQ_BM_SIZE];
	/**< Entries */
	struct xs_request entries[XS_REQ_POOL_SIZE];
};

/*
 * Sends a message to Xenstore and blocks waiting for a reply.
 * The reply is malloc'ed and should be freed by the caller.
 *
 * @param msg_type Xenstore message type
 * @param xbt Xenbus transaction id
 * @param req_iovecs Array of request strings buffers
 * @param req_iovecs_num Request strings buffers number
 * @param rep_iovec Incoming reply string buffer (optional)
 * @return 0 on success, a negative errno value on error.
 */
int xs_msg_reply(enum xsd_sockmsg_type msg_type, xenbus_transaction_t xbt,
	const struct xs_iovec *req_iovecs, int req_iovecs_num,
	struct xs_iovec *rep_iovec);

#endif /* __XS_COMMS_H__ */
