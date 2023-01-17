# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2021 EPAM Systems

zephyr_sources(hvm.c)
zephyr_sources(events.c)
zephyr_sources(gnttab.c)
zephyr_sources(memory.c)

#add_subdirectory(xenbus)
add_subdirectory_ifdef(CONFIG_XEN_INITIAL_DOMAIN dom0)