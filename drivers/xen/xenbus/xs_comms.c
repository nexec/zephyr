/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: re-check all headers */

#include <xen/events.h>
#include <xen/generic.h>
#include <xen/public/io/xs_wire.h>
#include <xen/public/xen.h>
#include <xen/xenbus/client.h>
#include <xen/xenbus/xenbus.h>
#include <xen/xenbus/xs.h>
#include <xen/xenbus/xs_watch.h>

#include <kernel.h>
#include <errno.h>
#include <logging/log.h>
#include <kernel/thread.h>
#include <sys/slist.h>

LOG_MODULE_DECLARE(xenbus);

static struct xs_request_pool xs_req_pool;
static struct xs_handler *xs_hdlr;

/* TODO: Fix memory allocation, test with ASSERT on! */

static void xs_bitmap_init(struct xs_request_pool *pool)
{
	int i;
	/* bitmap length in bits */
	int bm_len = XS_REQ_BM_SIZE * sizeof(*pool->entries_bm) * __CHAR_BIT__;

	for (i = 0; i < XS_REQ_BM_SIZE; i++) {
		/* fill request bitmap with "1" */
		pool->entries_bm[i] = ULONG_MAX;
	}

	/* Clear last bits in bitmap, that are outside of XS_REQ_POLL_SIZE */
	for (i = XS_REQ_POOL_SIZE + 1; i < bm_len; i++) {
		sys_bitfield_clear_bit((mem_addr_t) pool->entries_bm, i);
	}
}

void xs_request_pool_init(struct xs_request_pool *pool)
{
	struct xs_request *xs_req;
	int i;

	pool->num_live = 0;
	k_sem_init(&pool->sem, 0, 1);
	sys_slist_init(&pool->queued);

	xs_bitmap_init(pool);

	for (i = 0; i < XS_REQ_POOL_SIZE; i++) {
		xs_req = &pool->entries[i];
		xs_req->hdr.req_id = i;
		k_sem_init(&xs_req->sem, 0, 1);
	}
}

/*
 * Searches first available entry in bitmap (first marked with 1).
 */
static int get_free_entry_idx(struct xs_request_pool *pool)
{
	int i, res;

	/* Bit at pos XS_REQ_POOL_SIZE is a border, it always stays "1". */
	for (i = 0; i < XS_REQ_BM_SIZE; i++) {
		if (pool->entries_bm[i]) {
			/* contain at least one fired bit ("1") */
			break;
		}
	}

	/*
	 * Now we have "i" which points to element in bitmap with
	 * free entry. Calculating offset of this element in bitmap.
	 */
	res = i * sizeof(*pool->entries_bm) * __CHAR_BIT__;

	/* Add exact fired bit position */
	res += __builtin_ctzl(pool->entries_bm[i]);

	xenbus_printk("%s: returning entry #%d, i = %d\n", __func__, res, i);
	return res;
}

/*
 * Allocate an identifier for a Xenstore request.
 * Blocks if none are available.
 */
static struct xs_request *xs_request_get(void)
{
	unsigned long entry_idx;
	k_spinlock_key_t key;

	xenbus_printk("%s: in\n", __func__);
	/* wait for an available entry */
	while (1) {
		key = k_spin_lock(&xs_req_pool.lock);

		if (xs_req_pool.num_live < XS_REQ_POOL_SIZE)
			break;

		k_spin_unlock(&xs_req_pool.lock, key);

		/* Wait for events in request pool */
		k_sem_take(&xs_req_pool.sem, K_FOREVER);
	}

	entry_idx = get_free_entry_idx(&xs_req_pool);

	/*
	 * Getting of free entry is called after num_live is less than pool
	 * size (spinlock is still held), so we do not expect to reach the
	 * bitmap border. If so, something went totally wrong.
	 */
	__ASSERT(entry_idx != XS_REQ_POOL_SIZE,
		"Received border entry index for xs_req_pool!\n");

	sys_bitfield_clear_bit((mem_addr_t) xs_req_pool.entries_bm, entry_idx);
	xs_req_pool.num_live++;

	k_spin_unlock(&xs_req_pool.lock, key);

	return &xs_req_pool.entries[entry_idx];
}

/* Release a request identifier */
static void xs_request_put(struct xs_request *xs_req)
{
	uint32_t reqid = xs_req->hdr.req_id;
	k_spinlock_key_t key;

	xenbus_printk("%s: in, reqid = %d, xs_req - %p\n", __func__,
			reqid, xs_req);
	key = k_spin_lock(&xs_req_pool.lock);

	__ASSERT(sys_test_bit((mem_addr_t) xs_req_pool.entries_bm, reqid) != 1,
			"trying to put free request!");

	sys_bitfield_set_bit((mem_addr_t) xs_req_pool.entries_bm, reqid);
	xs_req_pool.num_live--;

	/* Someone probably is now waiting for free xs_request from pool */
	if (xs_req_pool.num_live == XS_REQ_POOL_SIZE - 1) {
		k_sem_give(&xs_req_pool.sem);
	}

	k_spin_unlock(&xs_req_pool.lock, key);
}

static struct xs_request *xs_request_peek(void)
{
	struct xs_request *xs_req;
	k_spinlock_key_t key;
	sys_snode_t *node;

	key = k_spin_lock(&xs_req_pool.lock);
	node = sys_slist_get(&xs_req_pool.queued);
	xenbus_printk("%s: get request node from list - %p\n", __func__, node);
	xs_req = SYS_SLIST_CONTAINER(node, xs_req, next);
	k_spin_unlock(&xs_req_pool.lock, key);

	return xs_req;
}

static void xs_request_enqueue(struct xs_request *xs_req)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&xs_req_pool.lock);
	xenbus_printk("%s: in, xs_req->next = %p\n", __func__, &xs_req->next);
	sys_slist_append(&xs_req_pool.queued, &xs_req->next);
	k_spin_unlock(&xs_req_pool.lock, key);
}

static struct xs_request *xs_request_dequeue(void)
{
	struct xs_request *xs_req = NULL;
	sys_snode_t *node;
	k_spinlock_key_t key;

	xenbus_printk("%s: in\n", __func__);
	key = k_spin_lock(&xs_req_pool.lock);
	node = sys_slist_peek_head(&xs_req_pool.queued);
	if (node) {
		xs_req = SYS_SLIST_CONTAINER(node, xs_req, next);

		/* "node" is list head, so prev_node can be passed as NULL */
		sys_slist_remove(&xs_req_pool.queued, NULL, node);
	}
	k_spin_unlock(&xs_req_pool.lock, key);

	return xs_req;
}

static int xs_avail_to_read(void)
{
	return (xs_hdlr->buf->rsp_prod != xs_hdlr->buf->rsp_cons);
}

static int xs_avail_space_for_read(unsigned int size)
{
	return (xs_hdlr->buf->rsp_prod - xs_hdlr->buf->rsp_cons >= size);
}

static int xs_avail_to_write(void)
{
	xenbus_printk("%s: is empty = %d\n", __func__, sys_slist_is_empty(&xs_req_pool.queued));
	return (xs_hdlr->buf->req_prod - xs_hdlr->buf->req_cons != XENSTORE_RING_SIZE &&
		!sys_slist_is_empty(&xs_req_pool.queued));
}

static int xs_avail_space_for_write(unsigned int size)
{
	return (xs_hdlr->buf->req_prod - xs_hdlr->buf->req_cons +
		size <= XENSTORE_RING_SIZE);
}

static int xs_avail_work(void)
{
	return (xs_avail_to_read() || xs_avail_to_write());
}

/*
 * Send request to Xenstore. A request is made of multiple iovecs which are
 * preceded by a single iovec referencing the request header. The iovecs are
 * seen by Xenstore as if sent atomically. This can block.
 */
static int xs_msg_write(struct xsd_sockmsg *xsd_req,
	const struct xs_iovec *iovec)
{
	XENSTORE_RING_IDX prod;
	const struct xs_iovec *crnt_iovec;
	struct xs_iovec hdr_iovec;
	unsigned int req_size, req_off;
	unsigned int buf_off;
	unsigned int this_chunk_len;

	req_size = sizeof(*xsd_req) + xsd_req->len;
	if (req_size > XENSTORE_RING_SIZE)
		return -ENOSPC;

	if (!xs_avail_space_for_write(req_size))
		return -ENOSPC;

	/* We must write requests after reading the consumer index. */
	compiler_barrier();

	/*
	 * We're now guaranteed to be able to send the message
	 * without overflowing the ring. Do so.
	 */

	hdr_iovec.data = xsd_req;
	hdr_iovec.len  = sizeof(*xsd_req);

	/* The batched iovecs are preceded by a single header. */
	crnt_iovec = &hdr_iovec;

	prod = xs_hdlr->buf->req_prod;
	req_off = 0;
	buf_off = 0;
	while (req_off < req_size) {
		this_chunk_len = MIN(crnt_iovec->len - buf_off,
			XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));

		memcpy(
			(char *) xs_hdlr->buf->req + MASK_XENSTORE_IDX(prod),
			(char *) crnt_iovec->data + buf_off,
			this_chunk_len
		);

		prod += this_chunk_len;
		req_off += this_chunk_len;
		buf_off += this_chunk_len;

		if (buf_off == crnt_iovec->len) {
			buf_off = 0;
			if (crnt_iovec == &hdr_iovec)
				crnt_iovec = iovec;
			else
				crnt_iovec++;
		}
	}

	LOG_DBG("%s: complete\n", __func__);
	LOG_ERR("Complete main loop of %s.\n", __func__);
	__ASSERT_NO_MSG(buf_off == 0);
	__ASSERT_NO_MSG(req_off == req_size);
	__ASSERT_NO_MSG(prod <= xs_hdlr->buf->req_cons + XENSTORE_RING_SIZE);

	/* Remote must see entire message before updating indexes */
	compiler_barrier();

	xs_hdlr->buf->req_prod += req_size;

	/* Send evtchn to notify remote */
	notify_evtchn(xs_hdlr->evtchn);

	return 0;
}

int xs_msg_reply(enum xsd_sockmsg_type msg_type, xenbus_transaction_t xbt,
	const struct xs_iovec *req_iovecs, int req_iovecs_num,
	struct xs_iovec *rep_iovec)
{
	struct xs_request *xs_req;
	int err;

	if (req_iovecs == NULL)
		return -EINVAL;

	xs_req = xs_request_get();
	xs_req->hdr.type = msg_type;
	/* req_id was set on pool init  */
	xs_req->hdr.tx_id = xbt;
	xs_req->hdr.len = 0;
	for (int i = 0; i < req_iovecs_num; i++)
		xs_req->hdr.len += req_iovecs[i].len;

	xs_req->payload_iovecs = req_iovecs;
	xs_req->reply.recvd = 0;

	/* enqueue the request */
	xs_request_enqueue(xs_req);
	/* wake xenstore thread to send it */
	k_sem_give(&xs_hdlr->sem);

	/* wait reply */
	while (1) {
		k_sem_take(&xs_req->sem, K_FOREVER);
		if (xs_req->reply.recvd != 0) {
			break;
		}
	}

	err = -xs_req->reply.errornum;
	if (err == 0) {
		if (rep_iovec)
			*rep_iovec = xs_req->reply.iovec;
		else
			k_free(xs_req->reply.iovec.data);
	}

	xs_request_put(xs_req);

	return err;
}

void xs_send(void)
{
	struct xs_request *xs_req;
	int err;

	xs_req = xs_request_peek();
	xenbus_printk("%s: peeked req - %p\n", __func__, xs_req);
	while (xs_req != NULL) {
		err = xs_msg_write(&xs_req->hdr, xs_req->payload_iovecs);
		if (err) {
			if (err != -ENOSPC)
				LOG_WRN("Error sending message err=%d\n",
					   err);
			break;
		}

		/* remove it from queue */
		xs_request_dequeue();

		xs_req = xs_request_peek();
	}
}

/*
 * Converts a Xenstore reply error to a positive error number.
 * Returns 0 if the reply is successful.
 */
static int reply_to_errno(const char *reply)
{
	int err = 0;

	for (int i = 0; i < (int) ARRAY_SIZE(xsd_errors); i++) {
		if (!strcmp(reply, xsd_errors[i].errstring)) {
			err = xsd_errors[i].errnum;
			goto out;
		}
	}

	LOG_WRN("Unknown Xenstore error: %s\n", reply);
	err = -EINVAL;

out:
	return err;
}

/* Process an incoming xs watch event */
void process_watch_event(char *watch_msg)
{
	struct xs_watch *watch;
	char *path, *token;

	path  = watch_msg;
	token = watch_msg + strlen(path) + 1;

	watch = xs_watch_find(path, token);
	k_free(watch_msg);

	if (watch)
		xenbus_watch_notify_event(&watch->base);
	else
		LOG_ERR("Invalid watch event received!");
}

/* Process an incoming xs reply */
static void process_reply(struct xsd_sockmsg *hdr, char *payload)
{
	struct xs_request *xs_req;

	if (sys_test_bit((mem_addr_t) xs_req_pool.entries_bm, hdr->req_id)) {
		LOG_WRN("Invalid reply id=%d\n", hdr->req_id);
		k_free(payload);
		return;
	}

	xs_req = &xs_req_pool.entries[hdr->req_id];

	if (hdr->type == XS_ERROR) {
		xs_req->reply.errornum = reply_to_errno(payload);
		k_free(payload);

	} else if (hdr->type != xs_req->hdr.type) {
		LOG_WRN("Mismatching message type: %d\n", hdr->type);
		k_free(payload);
		return;

	} else {
		/* set reply */
		xs_req->reply.iovec.data = payload;
		xs_req->reply.iovec.len = hdr->len;
		xs_req->reply.errornum = 0;
	}

	xs_req->reply.recvd = 1;

	/* notify waiting requester */
	k_sem_give(&xs_req->sem);
}


static void memcpy_from_ring(const char *ring, char *dest, int off, int len)
{
	int c1, c2;

	c1 = MIN(len, XENSTORE_RING_SIZE - off);
	c2 = len - c1;

	memcpy(dest, ring + off, c1);
	if (c2)
		memcpy(dest + c1, ring, c2);
}

static void xs_msg_read(struct xsd_sockmsg *hdr)
{
	XENSTORE_RING_IDX cons;
	char *payload;

	payload = k_malloc(hdr->len + 1);
	if (payload == NULL) {
		LOG_WRN("No memory available for saving Xenstore message!\n");
		return;
	}

	cons = xs_hdlr->buf->rsp_cons;

	/* copy payload */
	memcpy_from_ring(
		xs_hdlr->buf->rsp,
		payload,
		MASK_XENSTORE_IDX(cons + sizeof(*hdr)),
		hdr->len
	);
	payload[hdr->len] = '\0';

	/* Remote must not see available space until we've copied the reply */
	compiler_barrier();
	xs_hdlr->buf->rsp_cons += sizeof(*hdr) + hdr->len;

	if (xs_hdlr->buf->rsp_prod - cons >= XENSTORE_RING_SIZE)
		notify_evtchn(xs_hdlr->evtchn);

	if (hdr->type == XS_WATCH_EVENT)
		process_watch_event(payload);
	else
		process_reply(hdr, payload);
}


static void xs_recv(void)
{
	struct xsd_sockmsg msg;

	while (1) {
		LOG_DBG("Rsp_cons %d, rsp_prod %d.\n",
			    xs_hdlr->buf->rsp_cons, xs_hdlr->buf->rsp_prod);

		if (!xs_avail_space_for_read(sizeof(msg)))
			break;

		/* Make sure data is read after reading the indexes */
		compiler_barrier();

		/* copy the message header */
		memcpy_from_ring(
			xs_hdlr->buf->rsp,
			(char *) &msg,
			MASK_XENSTORE_IDX(xs_hdlr->buf->rsp_cons),
			sizeof(msg)
		);

		LOG_DBG("Msg len %lu, %u avail, id %u.\n",
			    msg.len + sizeof(msg),
			    xs_hdlr->buf->rsp_prod - xs_hdlr->buf->rsp_cons,
			    msg.req_id);

		if (!xs_avail_space_for_read(sizeof(msg) + msg.len))
			break;

		/* Make sure data is read after reading the indexes */
		compiler_barrier();

		LOG_DBG("Message is good.\n");
		xs_msg_read(&msg);
	}
}


void xenbus_main_thrd(void *p1, void *p2, void *p3)
{
	while (1) {
		xenbus_printk("%s: taking semaphore\n", __func__);
		k_sem_take(&xs_hdlr->sem, K_FOREVER);
		if (!xs_avail_work()) {
			LOG_DBG("%s: took semaphore, queue empty!\n", __func__);
			continue;
		}

		if (xs_avail_to_write()) {
			LOG_DBG("%s: avail to write\n", __func__);
			xs_send();
		}

		if (xs_avail_to_read()) {
			LOG_DBG("%s: avail to read\n", __func__);
			xs_recv();
		}
	}
}

int xs_comms_init(struct xs_handler *hdlr)
{
	xs_hdlr = hdlr;
	xs_request_pool_init(&xs_req_pool);

	return 0;
}
