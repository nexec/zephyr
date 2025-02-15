#ifndef __XEN_XS_H__
#define __XEN_XS_H__

#include <xen/public/xen.h>
#include <xen/public/io/xs_wire.h>
#include <xen/xenbus/xs_comms.h>

#include <device.h>
#include <kernel.h>
#include <kernel/thread.h>
#include <spinlock.h>
#include <sys/device_mmio.h>
#include <sys/util.h>

#define DEBUG_XENBUS

#ifdef DEBUG_XENBUS
#define xenbus_printk printk
#else
static void xenbus_printk(const char *fmt, ...) {};
#endif

/* Helper macros for initializing xs requests from strings */
#define INIT_XS_IOVEC_STR_NULL(str) \
	((struct xs_iovec) { str, strlen(str) + 1 })
#define INIT_XS_IOVEC_STR(str) \
	((struct xs_iovec) { str, strlen(str) })

/* TODO: re-check all comments before functions (return value, parameters etc.) */

/*
 * Read the value associated with a path.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param node Xenstore subdirectory
 * @return On success, returns a malloc'd copy of the value. On error, returns
 * a negative error number which should be checked using PTRISERR.
 */
char *xs_read(xenbus_transaction_t xbt, const char *path);

/*
 * Associates a value with a path.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param node Xenstore subdirectory (optional)
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xs_write(xenbus_transaction_t xbt, const char *path, const char *value);

/*
 * List the contents of a directory.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore directory path
 * @param node Xenstore subdirectory (optional)
 * @return On success, returns a malloc'd array of pointers to strings. The
 * array is NULL terminated. The caller should free only the array. On error,
 * returns a negative error number which should be checked using PTRISERR.
 * May block.
 */
char **xs_ls(xenbus_transaction_t xbt, const char *path);

/*
 * Removes the value associated with a path.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @return 0 on success, a negative errno value on error.
 */
int xs_rm(xenbus_transaction_t xbt, const char *path);

/*
 * Xenstore permissions
 */
enum xs_perm {
	XS_PERM_NONE = 0x0,
	XS_PERM_READ = 0x1,
	XS_PERM_WRITE = 0x2,
	XS_PERM_BOTH = XS_PERM_WRITE | XS_PERM_READ
};

/*
 * Converts a character to corresponding permission value.
 *
 * @param c Permission character
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xs_char_to_perm(char c, enum xs_perm *perm);

/*
 * Converts a permission value to corresponding character.
 *
 * @param perm Permission value
 * @param c Permission character
 * @return 0 on success, a negative errno value on error.
 */
int xs_perm_to_char(enum xs_perm perm, char *c);

/*
 * Extracts domid and permission value out of a permission string.
 *
 * @param str Permission string
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xs_str_to_perm(const char *str, domid_t *domid, enum xs_perm *perm);

/*
 * Returns a permission string from domid and permission value.
 *
 * @param domid Domain ID
 * @param perm Permission value
 * @return On success, returns a malloc'd string. On error, returns a negative
 * error number which should be checked using PTRISERR.
 */
char *xs_perm_to_str(domid_t domid, enum xs_perm perm);

/*
 * Xenstore ACL
 */
struct xs_acl_entry {
	domid_t domid;
	enum xs_perm perm;
};

struct xs_acl {
	domid_t ownerid;
	enum xs_perm others_perm;
	int entries_num;
	struct xs_acl_entry entries[];
};

/*
 * Returns the ACL for input path.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @return On success, returns a malloc'd ACL. On error, returns a
 * negative error number which should be checked using PTRISERR.
 */
struct xs_acl *xs_get_acl(xenbus_transaction_t xbt, const char *path);

/*
 * Sets ACL for input path.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param acl New ACL
 * @return 0 on success, a negative errno value on error.
 */
int xs_set_acl(xenbus_transaction_t xbt, const char *path, struct xs_acl *acl);

/*
 * Reads permissions for input path and domid.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xs_get_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid, enum xs_perm *perm);

/*
 * Sets permissions for input path and domid.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xs_set_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid, enum xs_perm perm);

/*
 * Deletes permissions for domid.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param domid Domain ID
 * @return 0 on success, a negative errno value on error.
 */
int xs_del_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid);

/*
 * Creates and registers a Xenbus watch
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @return On success, returns a malloc'd Xenbus watch. On error, returns
 * a negative error number which should be checked using PTRISERR.
 */
struct xenbus_watch *xs_watch_path(xenbus_transaction_t xbt, const char *path);

/*
 * Unregisters and destroys a Xenbus watch
 *
 * @param xbt Xenbus transaction id
 * @param watch Xenbus watch
 * @return 0 on success, a negative errno value on error.
 */
int xs_unwatch(xenbus_transaction_t xbt, struct xenbus_watch *watch);

/*
 * Start a xenbus transaction. Returns the transaction in xbt on
 * success or an error number otherwise.
 *
 * @param xbt Address for returning the Xenbus transaction id
 * @return 0 on success, a negative errno value on error.
 */
int xs_transaction_start(xenbus_transaction_t *xbt);

/*
 * End a xenbus transaction. Returns non-zero on failure.
 * Parameter abort says whether the transaction should be aborted.
 * Returns 1 in *retry iff the transaction should be retried.
 *
 * @param xbt Xenbus transaction id
 * @param abort Non-zero if transaction should be aborted
 * @return 0 on success, a negative errno value on error.
 */
int xs_transaction_end(xenbus_transaction_t xbt, int abort);

/*
 * Sends a debug message to the Xenstore daemon for writing it in the debug log
 *
 * @param msg The logged message
 * @return 0 on success, a negative errno value on error.
 */
int xs_debug_msg(const char *msg);

/*
 * Read path and parse it as an integer.
 *
 * @param xbt Xenbus transaction id
 * @param path Xenstore path
 * @param value Returned int value
 * @return 0 on success, a negative errno value on error.
 */
int xs_read_integer(xenbus_transaction_t xbt, const char *path, int *value);

/*
 * Contraction of sprintf and xs_write(node/path).
 *
 * @param xbt Xenbus transaction id
 * @param dir Xenstore directory
 * @param node Xenstore directory entry
 * @param fmt Path format string
 * @return On success returns the number of the number of characters printed.
 * On error returns a negative errno value.
 */
int xs_printf(xenbus_transaction_t xbt, const char *dir, const char *node,
	const char *fmt, ...);

/*
 * Utility function to figure out our domain id
 *
 * @return Our domain id
 */
domid_t xs_get_self_id(void);





#endif /* __XEN_XENBUS_H__ */
