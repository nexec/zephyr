/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <xen/events.h>
#include <xen/generic.h>
#include <xen/hvm.h>
#include <xen/public/hvm/params.h>
#include <xen/public/io/xs_wire.h>
#include <xen/public/xen.h>
#include <xen/xenbus/client.h>
#include <xen/xenbus/xs.h>
#include <xen/xenbus/xs_watch.h>

#include <string.h>
#include <stdio.h>
#include <kernel.h>
#include <init.h>
#include <errno.h>
#include <device.h>
#include <logging/log.h>
#include <kernel/thread.h>
#include <sys/slist.h>

LOG_MODULE_REGISTER(xenstore);

K_KERNEL_STACK_DEFINE(xenstore_thrd_stack, 10240);
struct k_thread xenstore_thrd;
k_tid_t xenstore_tid;

K_KERNEL_STACK_DEFINE(read_thrd_stack, 10240);
struct k_thread read_thrd;
k_tid_t read_tid;

K_KERNEL_STACK_DEFINE(read_thrd2_stack, 10240);
struct k_thread read_thrd2;
k_tid_t read_tid2;

static struct xs_handler xs_hdlr;

static struct xenbus_handler xb_hdlr;

static struct xenbus_driver *xenbus_find_driver(xenbus_dev_type_t devtype)
{
	struct xenbus_driver *drv;
	const xenbus_dev_type_t *pdevtype;

	SYS_SLIST_FOR_EACH_CONTAINER(&xb_hdlr.drv_list, drv, next) {
		for (pdevtype = drv->device_types;
				*pdevtype != xenbus_dev_none; pdevtype++) {
			if (*pdevtype == devtype)
				return drv;
		}
	}

	return NULL; /* no driver found */
}

static int xenbus_probe_device(struct xenbus_driver *drv,
		xenbus_dev_type_t type, const char *name)
{
	int err, node_len = 0;
	struct xenbus_device *dev;
	char *nodename = NULL;
	XenbusState state;
	const char *str_type = xenbus_devtype_to_str(type);

	node_len = sizeof(XS_DEV_PATH) + strlen(str_type) + strlen(name);
	nodename = k_malloc(node_len + 1);
	if (!nodename) {
		LOG_ERR("%s: failed to allocate memory for node path!\n",
			__func__);
		return -ENOMEM;
	}

	/* device/type/name */
	snprintf(nodename, node_len, "%s/%s/%s",
		XS_DEV_PATH, xenbus_devtype_to_str(type), name);

	state = xenbus_read_driver_state(nodename);
	/* TODO: what it means? should we free nodename? */
	if (state != XenbusStateInitialising)
		return 0;

	LOG_INF("%s: Xenbus device: %s\n", __func__, nodename);

	dev = k_calloc(1, sizeof(*dev) + node_len);
	if (!dev) {
		LOG_ERR("%s: Failed to initialize: Out of memory!\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	dev->state = XenbusStateInitialising;
	dev->devtype = type;
	/* TODO: (dev + 1) ??? */
	dev->nodename = (char *) (dev + 1);
	strcpy(dev->nodename, nodename);

	err = drv->add_dev(dev);
	if (err) {
		LOG_ERR("%s: Failed to add device.\n", __func__);
		k_free(dev);
	}

out:
	if (nodename)
		k_free(nodename);

	return err;
}

static int xenbus_probe_device_type(const char *devtype_str)
{
	struct xenbus_driver *drv;
	xenbus_dev_type_t devtype;
	char *dirname;
	char **devices = NULL;
	int err = 0;
	int dir_len = sizeof(XS_DEV_PATH) + strlen(devtype_str);

	dirname = k_malloc(dir_len + 1);
	if (!dirname) {
		LOG_ERR("%s: failed to allocate memory for dir name!\n",
			__func__);
		return -ENOMEM;
	}

	devtype = xenbus_str_to_devtype(devtype_str);
	if (!devtype) {
		LOG_WRN("%s: Unsupported device type: %s\n", __func__,
			devtype_str);
		goto out;
	}

	drv = xenbus_find_driver(devtype);
	if (!drv) {
		LOG_WRN("%s: No driver for device type: %s\n", __func__,
			devtype_str);
		goto out;
	}

	snprintf(dirname, dir_len, "%s/%s", XS_DEV_PATH, devtype_str);

	/* Get device list */
	devices = xs_ls(XBT_NIL, dirname);
	if (!devices) {
		LOG_ERR("Error reading %s devices\n", devtype_str);
		goto out;
	}

	for (int i = 0; devices[i] != NULL; i++) {
		/* Probe only if no prior error */
		if (err == 0) {
			err = xenbus_probe_device(drv, devtype, devices[i]);
		}
	}

out:
	k_free(dirname);
	if (devices)
		k_free(devices);

	return err;
}

static int xenbus_probe(void)
{
	char **devtypes;
	int err = 0;

	/* Get device types list */
	devtypes = xs_ls(XBT_NIL, XS_DEV_PATH);
	if (!devtypes) {
		LOG_ERR("Error reading device types\n");
		return -EINVAL;
	}

	for (int i = 0; devtypes[i] != NULL; i++) {
		/* Probe only if no previous error */
		if (err == 0)
			err = xenbus_probe_device_type(devtypes[i]);
	}

out:
	if (devtypes)
		k_free(devtypes);

	return err;
}



static void xenbus_isr(void *data)
{
	struct xs_handler *xs = data;
	k_sem_give(&xs->sem);
}

void channel_state(int port)
{
	xenbus_printk(">>>>> check_channel_mask(%d) = %d\n", port, check_channel_mask(port));
	xenbus_printk(">>>>> check_channel_event(%d) = %d\n", port, check_channel_event(port));
	xenbus_printk(">>>>> check_upcall_pending(%d) = %d\n", 0, check_upcall_pending(0));
	xenbus_printk(">>>>> check_upcall_masked(%d) = %d\n", 0, check_upcall_masked(0));
}

static void cat_file(char *buf)
{
	char *pdata = xs_read(XBT_NIL, buf);
	LOG_DBG("READ %s:\n%s", buf, pdata);
	k_free(pdata);
}

static void list_dir(char *buf, int size)
{
	char **dirs;
	int x;
	dirs = xs_ls(XBT_NIL, buf);

	char buf1[128];
	for (x = 0; dirs[x]; x++) {
		if (false)
		{
			printk("ls %s[%d] -> %s\n", buf, x, dirs[x]);
		}
		else
		{
			snprintf(buf1, 128, "%s/%s", buf, dirs[x]);
			LOG_DBG("ls [%d] %s", x, buf1);
		}

		char **dirs1;
		dirs1	= xs_ls(XBT_NIL, buf1);
		int z=0;

		for(z=0;dirs1[z]; z++)
		{
			char buf2[128];
			snprintf(buf2, 128, "%s/%s", buf1, dirs1[z]);
			list_dir(buf2, 128);
		}

		if (!z)
		{
			cat_file(buf1);
		}
		k_free(dirs1);
	}

	if (!x)
	{
		cat_file(buf);
	}

	k_free(dirs);
}

static void xenbus_read_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	int port = *(int*)p1;
	channel_state(port);

	char **dirs;
	int x;

	char buf[50];
	printk("xenbus_ls test results for pre = n0n\n");
	domid_t domid = xs_get_self_id();

	if (!domid) {
		printk("NULL domid\n");
		xenbus_printk("NULL domid\n");
		printk("xenbus_ls test results for pre = NON3\n");
		k_sleep(K_SECONDS(10));
	}

	channel_state(port);

	xenbus_printk("%s: domid returned = %u\n", __func__, domid);

	snprintf(buf, 50, "/local/domain/%u", domid);
	list_dir(buf, 50);

	{
		LOG_DBG("Start watch");
		struct xenbus_watch *xw;
		xw = xs_watch_path(XBT_NIL, "memory/target");
		LOG_DBG("Watch done");
	}

	{
		LOG_DBG("XS_RESET_WATCHES start");

		struct xs_iovec req, rep;
		char *value = NULL;
		req = INIT_XS_IOVEC_STR_NULL("");
		int err = xs_msg_reply(XS_RESET_WATCHES, XBT_NIL, &req, 1, &rep);

		if (err == 0) {
			value = rep.data;
			LOG_DBG("%s: RESET_WATCHES GOT: %s", __func__, value);
		} else {
			LOG_DBG("%s: xs_msg_reply returned err = %d!", __func__, err);
		}

		LOG_DBG("XS_RESET_WATCHES end, err = %d", err);
	}

	{
		LOG_DBG("Initialization complete");
	}

	k_sleep(K_SECONDS(5));
	channel_state(port);
}


static int xenbus_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	int ret = 0;
	uint64_t xs_pfn = 0, xs_evtchn = 0;
	uintptr_t xs_addr = 0;
	struct xs_handler *data = dev->data;

	data->dev = dev;

	ret = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, &xs_evtchn);
	if (ret) {
		printk("%s: failed to get Xenbus evtchn, ret = %d\n",
				__func__, ret);
		return ret;
	}
	data->evtchn = (evtchn_port_t) xs_evtchn;
	xenbus_printk("domU listening %d\n", data->evtchn);

	ret = hvm_get_parameter(HVM_PARAM_STORE_PFN, &xs_pfn);
	if (ret) {
		printk("%s: failed to get Xenbus PFN, ret = %d\n",
				__func__, ret);
		return ret;
	}
	xs_addr = (uintptr_t) (xs_pfn << XEN_PAGE_SHIFT);
	device_map(DEVICE_MMIO_RAM_PTR(dev), xs_addr, XEN_PAGE_SIZE,
		K_MEM_CACHE_WB);
	data->buf = (struct xenstore_domain_interface *) DEVICE_MMIO_GET(dev);

	k_sem_init(&data->sem, 0, 1);

	xs_comms_init(data);

	bind_event_channel(data->evtchn, xenbus_isr, data);

	data->thread = k_thread_create(&xenstore_thrd, xenstore_thrd_stack,
			K_KERNEL_STACK_SIZEOF(xenstore_thrd_stack),
			xenbus_main_thrd, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
	if (!data->thread) {
		printk("%s: Failed to create Xenstore thread\n", __func__);
		return -1;
	}
	k_thread_name_set(data->thread, "xenstore_thread");
	printk("%s: xenstore thread inited\n", __func__);

	/* --------------------------------------------------------------- */
	/* TODO: remove this test code */

	read_tid = k_thread_create(&read_thrd, read_thrd_stack,
			K_KERNEL_STACK_SIZEOF(read_thrd_stack),
			xenbus_read_thrd, &data->evtchn, NULL, NULL, 7, 0, K_NO_WAIT);
	if (!read_tid) {
		printk("%s: Failed to create read thread\n", __func__);
		k_thread_abort(xenstore_tid);
		return -1;
	}
	k_thread_name_set(read_tid, "read_thread");
	printk("%s: read thread inited, stack defined at %p\n", __func__, read_thrd_stack);

	return ret;
}

/*
 * Xenbus logic requires threads, so it should be inited when their creation
 * will be possible (POST_KERNEL)
 */
DEVICE_DEFINE(xenbus, "xenbus", xenbus_init, NULL, &xs_hdlr, NULL,
		POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, NULL);
