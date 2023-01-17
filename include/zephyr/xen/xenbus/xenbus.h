#ifndef __XEN_XENBUS_H__
#define __XEN_XENBUS_H__

#include <xen/public/event_channel.h>
#include <xen/public/xen.h>
#include <xen/public/io/xenbus.h>
#include <xen/public/io/xs_wire.h>

#include <device.h>
#include <kernel.h>
#include <sys/device_mmio.h>

#define min(a, b)			\
	({ __typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a > _b ? _a : _b; })

typedef unsigned long xenbus_transaction_t;
#define XBT_NIL ((xenbus_transaction_t)0)

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
 * Supported device types
 */
typedef enum xenbus_dev_type {
	xenbus_dev_none = 0,
	xenbus_dev_vbd,
	xenbus_dev_9pfs,
} xenbus_dev_type_t;

struct xenbus_device;

/*
 * Xenbus driver
 */

typedef int (*xenbus_driver_init_func_t)(/*struct uk_alloc *a*/);
typedef int (*xenbus_driver_add_func_t)(struct xenbus_device *dev);

struct xenbus_driver {
	sys_snode_t next;
	const xenbus_dev_type_t *device_types;

	xenbus_driver_init_func_t init;
	xenbus_driver_add_func_t add_dev;
};

#define XS_DEV_PATH "device"

/*
 #define XENBUS_REGISTER_DRIVER(b) \
	_XENBUS_REGISTER_DRIVER(__LIBNAME__, (b))

#define _XENBUS_REGFNNAME(x, y)      x##y

#define _XENBUS_REGISTER_CTOR(ctor)  \
	UK_CTOR_PRIO(ctor, UK_PRIO_AFTER(UK_BUS_REGISTER_PRIO))

#define _XENBUS_REGISTER_DRIVER(libname, b)				\
	static void							\
	_XENBUS_REGFNNAME(libname, _xenbus_register_driver)(void)	\
	{								\
		_xenbus_register_driver((b));				\
	}								\
	_XENBUS_REGISTER_CTOR(						\
		_XENBUS_REGFNNAME(libname, _xenbus_register_driver))
*/

/* Do not use this function directly: */
void _xenbus_register_driver(struct xenbus_driver *drv);

/*
 * Xenbus watch
 */
struct xenbus_watch {
	/**< in use internally */
	sys_snode_t node;
	/**< Lock */
	struct k_spinlock lock;
	/**< Number of pending events */
	int pending_events;
	/**< Watch waiting queue */
	struct k_sem sem;
};

/*
 * Xenbus device
 */

struct xenbus_device {
	/**< in use by Xenbus handler */
	sys_snode_t node;
	/**< Device state */
	XenbusState state;
	/**< Device type */
	enum xenbus_dev_type devtype;
	/**< Xenstore path of the device */
	char *nodename;
	/**< Xenstore path of the device peer (e.g. backend for frontend) */
	char *otherend;
	/**< Domain id of the other end */
	domid_t otherend_id;
	/**< Watch for monitoring changes on other end */
	struct xenbus_watch *otherend_watch;
	/**< Xenbus driver */
	struct xenbus_driver *drv;
};

/*
 * Xenbus handler
 */
struct xenbus_handler {
	sys_slist_t drv_list;  /**< List of Xenbus drivers */
	sys_slist_t dev_list;  /**< List of Xenbus devices */
};

#endif /* __XEN_XENBUS_H__ */
