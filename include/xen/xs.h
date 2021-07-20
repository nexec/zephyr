#ifndef __XEN_XS_H__
#define __XEN_XS_H__

#include <xen/public/xen.h>
#include <xen/public/io/xs_wire.h>
#include <xen/xs_comms.h>

#include <device.h>
#include <kernel.h>
#include <kernel/thread.h>
#include <spinlock.h>
#include <sys/device_mmio.h>
#include <sys/util.h>

/*
 * Xenstore handler structure
 */
struct xs_handler {
	/* Xenstore addr, provided by Xen, *SHOULD BE FIRST* */
	DEVICE_MMIO_RAM;
	const struct device *dev;
	/**< Communication: event channel */
	evtchn_port_t evtchn;
	/**< Communication: shared memory */
	struct xenstore_domain_interface *buf;
	/**< Thread processing incoming xs replies */
	k_tid_t thread;
	/**< Waiting queue for notifying incoming xs replies */
	struct k_sem sem;
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
#define XS_REQ_POOL_SHIFT  5
#define XS_REQ_POOL_SIZE   (1 << XS_REQ_POOL_SHIFT)
#define XS_REQ_POOL_MASK   (XS_REQ_POOL_SIZE - 1)
	unsigned long entries_bm[BITS_TO_LONGS(XS_REQ_POOL_SIZE)];
	/**< Entries */
	struct xs_request entries[XS_REQ_POOL_SIZE];
};

#endif /* __XEN_XENBUS_H__ */
