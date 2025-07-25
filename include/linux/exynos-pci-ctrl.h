/*
 * Copyright (C) 2015 Samsung Electronics Co.Ltd
 * http://www.samsung.com
 *
 * EXYNOS MODEM CONTROL driver
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __EXYNOS_PCIE_CTRL_H
#define __EXYNOS_PCIE_CTRL_H

/* PCIe L1SS Control ID */
#define PCIE_L1SS_CTRL_ARGOS            (0x1 << 0)
#define PCIE_L1SS_CTRL_BOOT             (0x1 << 1)
#define PCIE_L1SS_CTRL_CAMERA           (0x1 << 2)
#define PCIE_L1SS_CTRL_MODEM_IF         (0x1 << 3)
#define PCIE_L1SS_CTRL_WIFI             (0x1 << 4)
#define PCIE_L1SS_CTRL_TEST             (0x1 << 31)

#if IS_ENABLED(CONFIG_PCI_EXYNOS)
extern int exynos_pcie_rc_poweron(int ch_num);
extern void exynos_pcie_rc_poweroff(int ch_num);
extern int exynos_pcie_rc_chk_link_status(int ch_num);
extern int exynos_pcie_l1ss_ctrl(int enable, int id, int ch_num);
extern int exynos_pcie_get_irq_num(int ch_num);
extern int exynos_pcie_rc_speed_change(int ch_num, int req_speed);
extern int exynos_pcie_rc_speed_check(int ch_num);
extern int exynos_pcie_rc_lane_change(int ch_num, int req_lane);
extern int exynos_pcie_rc_lane_check(int ch_num);
extern void exynos_pcie_rc_print_msi_register(int ch_num);
#else
static int exynos_pcie_rc_poweron(int ch_num) { return 0; }
static void exynos_pcie_rc_poweroff(int ch_num) { return 0; }
static int exynos_pcie_rc_chk_link_status(int ch_num) {return 0; }
static int exynos_pcie_l1ss_ctrl(int enable, int id, int ch_num) { return 0; }
static int exynos_pcie_get_irq_num(int ch_num) { return 0; }
static int exynos_pcie_rc_speed_change(int ch_num, int req_speed) { return 0; }
static int exynos_pcie_rc_speed_check(int ch_num) { return 0; }
static int exynos_pcie_rc_lane_change(int ch_num, int req_lane) { return 0; }
static int exynos_pcie_rc_lane_check(int ch_num) { return 0; }
static void exynos_pcie_rc_print_msi_register(int ch_num) { return; }
#endif

#endif
