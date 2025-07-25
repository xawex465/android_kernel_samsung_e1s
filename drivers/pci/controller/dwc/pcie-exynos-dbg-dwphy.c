/*
 * PCIe host controller driver for Samsung EXYNOS SoCs
 *
 * Copyright (C) 2019 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/resource.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/gpio.h>
#include <linux/pm_runtime.h>
#include <linux/exynos-pci-noti.h>
#include <linux/exynos-pci-ctrl.h>
#include "pcie-designware.h"
#include "pcie-exynos-rc-dwphy.h"

#include "pcie-exynos-phycal_common.h"

int exynos_pcie_rc_set_outbound_atu(int ch_num, u32 target_addr, u32 offset, u32 size);
void exynos_pcie_rc_register_dump(int ch_num);
void exynos_pcie_set_perst_gpio(int ch_num, bool on);
void remove_pcie_sys_file(struct device *dev);

void exynos_pcie_dbg_print_oatu_register(struct exynos_pcie *exynos_pcie)
{
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;
	u32 val;

	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_CR1_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_CR1_OUTBOUND2(0x400) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_LOWER_BASE_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_LOWER_BASE_OUTBOUND2(0x408) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_UPPER_BASE_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_UPPER_BASE_OUTBOUND2(0x40C) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_LIMIT_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_LIMIT_OUTBOUND2(0x410) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_LOWER_TARGET_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_LOWER_TARGET_OUTBOUND2(0x414) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_UPPER_TARGET_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_UPPER_TARGET_OUTBOUND2(0x418) = 0x%x\n", __func__, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_ATU_CR2_OUTBOUND2, 4, &val);
	pcie_info("%s:  PCIE_ATU_CR2_OUTBOUND2(0x404) = 0x%x\n", __func__, val);
}

void exynos_pcie_dbg_print_msi_register(struct exynos_pcie *exynos_pcie)
{
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;
	u32 val;

	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_ADDR_LO, 4, &val);
	pcie_info("PCIE_MSI_ADDR_LO: 0x%x\n", val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_ADDR_HI, 4, &val);
	pcie_info("PCIE_MSI_ADDR_HI: 0x%x\n", val);

	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR0_ENABLE, 4, &val);
	pcie_info("PCIE_MSI_INTR0_ENABLE(0x%x):0x%x\n", PCIE_MSI_INTR0_ENABLE, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR0_MASK, 4, &val);
	pcie_info("PCIE_MSI_INTR0_MASK(0x%x):0x%x\n", PCIE_MSI_INTR0_MASK, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR0_STATUS, 4, &val);
	pcie_info("PCIE_MSI_INTR0_STATUS: 0x%x\n", val);

	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR1_ENABLE, 4, &val);
	pcie_info("PCIE_MSI_INTR1_ENABLE(0x%x):0x%x\n", PCIE_MSI_INTR0_ENABLE, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR1_MASK, 4, &val);
	pcie_info("PCIE_MSI_INTR1_MASK(0x%x):0x%x\n", PCIE_MSI_INTR0_MASK, val);
	exynos_pcie_rc_rd_own_conf(pp, PCIE_MSI_INTR1_STATUS, 4, &val);
	pcie_info("PCIE_MSI_INTR1_STATUS: 0x%x\n", val);
}

void exynos_pcie_dbg_dump_link_down_status(struct exynos_pcie *exynos_pcie)
{
	pcie_info("LTSSM: 0x%08x\n",
		  exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE));
}

void exynos_pcie_dbg_print_link_history(struct exynos_pcie *exynos_pcie)
{
	u32 history_buffer[32];
	int i;

	for (i = 31; i >= 0; i--)
		history_buffer[i] = exynos_ctrl_read(exynos_pcie,
						     PCIE_CTRL_DEBUG_REG(i));
	for (i = 31; i >= 0; i--)
		pcie_info("LTSSM: %#04x, L1sub: %#x, Lock_Sig: %#x, PHY DTB: %#x, PHY essen: %#x, PHY fix: %#x, PHY dyn: %#x\n",
			  CTRL_DEBUG_LTSSM_STATE(history_buffer[i]),
			  CTRL_DEBUG_L1SUB_STATE(history_buffer[i]),
			  CTRL_DEBUG_LOCK_SIG_STATE(history_buffer[i]),
			  CTRL_DEBUG_PHY_DTB_STATE(history_buffer[i]),
			  CTRL_DEBUG_PHY_ESSEN_STATE(history_buffer[i]),
			  CTRL_DEBUG_PHY_FIX_STATE(history_buffer[i]),
			  CTRL_DEBUG_PHY_DYN_STATE(history_buffer[i]));
}

void exynos_pcie_dbg_register_dump(struct exynos_pcie *exynos_pcie)
{
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;
	u32 i, val_0, val_4, val_8, val_c;

	pcie_err("%s: +++\n", __func__);

	pcie_err("[Print SOC Control region]\n");
	pcie_err("offset:             0x0               0x4               0x8               0xC\n");
	for (i = 0x9200; i < 0x9280; i += 0x10) {
		pcie_err("SOC control 0x%04x:    0x%08x    0x%08x    0x%08x    0x%08x\n",
				i,
				exynos_ctrl_read(exynos_pcie, i + 0x0),
				exynos_ctrl_read(exynos_pcie, i + 0x4),
				exynos_ctrl_read(exynos_pcie, i + 0x8),
				exynos_ctrl_read(exynos_pcie, i + 0xC));
	}
	pcie_err("\n");

	pcie_err("[Print SubSystem Custom region]\n");
	pcie_err("offset:             0x0               0x4               0x8               0xC\n");
	for (i = 0x10e0; i < 0x10f0; i += 0x10) {
		pcie_err("SubSys 0x%04x:    0x%08x    0x%08x    0x%08x    0x%08x\n",
				i,
				exynos_ssc_read(exynos_pcie, i + 0x0),
				exynos_ssc_read(exynos_pcie, i + 0x4),
				exynos_ssc_read(exynos_pcie, i + 0x8),
				exynos_ssc_read(exynos_pcie, i + 0xC));
	}
	pcie_err("\n");

	/* ---------------------- */
	/* DBI : 0x0 ~ 0x8FC */
	/* ---------------------- */
	pcie_err("[Print DBI region]\n");
	pcie_err("offset:             0x0               0x4               0x8               0xC\n");
	for (i = 0x100; i < 0x150; i += 0x10) {
		exynos_pcie_rc_rd_own_conf(pp, i + 0x0, 4, &val_0);
		exynos_pcie_rc_rd_own_conf(pp, i + 0x4, 4, &val_4);
		exynos_pcie_rc_rd_own_conf(pp, i + 0x8, 4, &val_8);
		exynos_pcie_rc_rd_own_conf(pp, i + 0xC, 4, &val_c);
		pcie_err("DBI 0x%04x:    0x%08x    0x%08x    0x%08x    0x%08x\n",
				i, val_0, val_4, val_8, val_c);
	}
	pcie_err("\n");

	pcie_err("[Print PHY region]\n");
	pcie_err("PHY + 0x4024 : %#x\n", exynos_phy_read(exynos_pcie, 0x4024));
	pcie_err("PHY + 0x4234 : %#x\n", exynos_phy_read(exynos_pcie, 0x4234));
	pcie_err("PHY + 0x42bc : %#x\n", exynos_phy_read(exynos_pcie, 0x42bc));
	pcie_err("PHY + 0x42c0 : %#x\n", exynos_phy_read(exynos_pcie, 0x42c0));
	for (i = 0; i < 10; i++)
		pcie_err("pci PHY + 0x42f4 : %#x\n", exynos_phy_read(exynos_pcie, 0x42f4));
	pcie_err("\n");

	if(exynos_pcie->phy->dbg_ops != NULL)
		exynos_pcie->phy->dbg_ops(exynos_pcie, REG_DUMP);

	pcie_err("%s: ---\n", __func__);
}

static int chk_pcie_dislink(struct exynos_pcie *exynos_pcie)
{
	int test_result = 0;
	u32 val;

	exynos_pcie_rc_poweroff(exynos_pcie->ch_num);

	pm_runtime_get_sync(exynos_pcie->pci->dev);

	val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE) &
				CTRL_LINK_STATE_LTSSM;
	if (val == S_L2_IDLE || val == S_DETECT_QUIET) {
		pcie_info("PCIe link Down test Success.\n");
	} else {
		pcie_info("PCIe Link Down test Fail...\n");
		test_result = -1;
	}

	pm_runtime_put_sync(exynos_pcie->pci->dev);

	return test_result;
}

static int chk_link_recovery(struct exynos_pcie *exynos_pcie)
{
	int test_result = 0;
	u32 val;

	/* Set s/w L1 exit mode */
	val = exynos_ssc_read(exynos_pcie, PCIE_SSC_PM_CTRL);
	val |= SSC_PM_CTRL_EXIT_ASPM_L1;
	exynos_ssc_write(exynos_pcie, val, PCIE_SSC_PM_CTRL);

	/* Remove EP callback for stable test */
	exynos_pcie->rc_event_reg[0] = NULL; /* Link down event */
	exynos_pcie->rc_event_reg[1] = NULL; /* CPL timeout event */

	pcie_info("Start warm reset to make force link-down...\n");
	exynos_pcie_warm_reset(exynos_pcie);

	/* Clear s/w L1 exit mode */
	val = exynos_ssc_read(exynos_pcie, PCIE_SSC_PM_CTRL);
	val &= ~SSC_PM_CTRL_EXIT_ASPM_L1;
	exynos_ssc_write(exynos_pcie, val, PCIE_SSC_PM_CTRL);
	msleep(5000);

	val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE) &
			       CTRL_LINK_STATE_LTSSM;
	if (val >= S_RCVRY_LOCK && val <= S_L1_IDLE) {
		pcie_info("PCIe link Recovery test Success.\n");
	} else {
		/* If recovery callback is defined, pcie poweron
		 * function will not be called.
		 */
		exynos_pcie_rc_poweroff(exynos_pcie->ch_num);
		test_result = exynos_pcie_rc_poweron(exynos_pcie->ch_num);
		if (test_result != 0) {
			pcie_info("PCIe Link Recovery test Fail...\n");
			return test_result;
		}
		val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE) &
			CTRL_LINK_STATE_LTSSM;
		if (val >= S_RCVRY_LOCK && val <= S_L1_IDLE) {
			pcie_info("PCIe link Recovery test Success.\n");
		} else {
			pcie_info("PCIe Link Recovery test Fail...\n");
			test_result = -1;
		}
	}

	return test_result;
}

static int chk_epmem_access(struct exynos_pcie *exynos_pcie)
{
	u32 val, val2;
	int test_result = 0;
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;

	struct pci_bus *ep_pci_bus;
	void __iomem *reg_addr;
	struct resource_entry *tmp = NULL, *entry = NULL;

	/* Get last memory resource entry */
	resource_list_for_each_entry(tmp, &pp->bridge->windows)
		if (resource_type(tmp->res) == IORESOURCE_MEM)
			entry = tmp;

	ep_pci_bus = pci_find_bus(exynos_pcie->pci_dev->bus->domain_nr, 1);
	if (ep_pci_bus == NULL) {
		pcie_err("Can't find PCIe ep_pci_bus structure\n");
		return -1;
	}

	exynos_pcie_rc_wr_other_conf(pp, ep_pci_bus, 0, PCI_BASE_ADDRESS_0,
				4, lower_32_bits(entry->res->start));
	exynos_pcie_rc_rd_other_conf(pp, ep_pci_bus, 0, PCI_BASE_ADDRESS_0,
				4, &val);
	pcie_info("Set BAR0 to 0x%x\n", val);

	reg_addr = ioremap(entry->res->start, SZ_4K);
	val2 = readl(reg_addr);
	iounmap(reg_addr);
	pcie_info(" Read BAR0(%#x) region : Value %#x\n", val, val2);

	if (val != 0xffffffff) {
		pcie_info("PCIe EP Outbound mem access Success.\n");
	} else {
		pcie_info("PCIe EP Outbound mem access Fail...\n");
		test_result = -1;
	}

	return test_result;
}

static int chk_epconf_access(struct exynos_pcie *exynos_pcie)
{
	u32 val;
	int test_result = 0;
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;
	struct pci_bus *ep_pci_bus;

	ep_pci_bus = pci_find_bus(exynos_pcie->pci_dev->bus->domain_nr, 1);
	if (ep_pci_bus == NULL) {
		pcie_err("Can't find pci_bus.\n");
		return -1;
	}

	exynos_pcie_rc_rd_other_conf(pp, ep_pci_bus, 0, 0x0, 4, &val);
	pcie_info("PCIe EP Vendor ID/Device ID = 0x%x\n", val);

	exynos_pcie_rc_wr_other_conf(pp, ep_pci_bus,
					0, PCI_COMMAND, 4, 0x146);
	exynos_pcie_rc_rd_other_conf(pp, ep_pci_bus,
					0, PCI_COMMAND, 4, &val);
	if ((val & 0xfff) == 0x146) {
		pcie_info("PCIe EP conf access Success.\n");
	} else {
		pcie_info("PCIe EP conf access Fail...\n");
		test_result = -1;
	}

	return test_result;
}

static int chk_dbi_access(struct exynos_pcie *exynos_pcie)
{
	u32 val;
	int test_result = 0;
	struct dw_pcie *pci = exynos_pcie->pci;
	struct dw_pcie_rp *pp = &pci->pp;

	exynos_pcie_rc_wr_own_conf(pp, PCI_COMMAND, 4, 0x140);
	exynos_pcie_rc_rd_own_conf(pp, PCI_COMMAND, 4, &val);
	if ((val & 0xfff) == 0x140) {
		pcie_info("PCIe DBI access Success.\n");
	} else {
		pcie_info("PCIe DBI access Fail...\n");
		test_result = -1;
	}

	return test_result;
}

static int chk_pcie_link(struct exynos_pcie *exynos_pcie)
{
	int test_result = 0;
	u32 val;

	test_result = exynos_pcie_rc_poweron(exynos_pcie->ch_num);
	if (test_result != 0) {
		pcie_info("PCIe Link test Fail...\n");
		return test_result;
	}

	val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE) &
		CTRL_LINK_STATE_LTSSM;
	if (val >= S_RCVRY_LOCK && val <= S_L1_IDLE) {
		pcie_info("PCIe link test Success.\n");
	} else {
		pcie_info("PCIe Link test Fail...\n");
		test_result = -1;
	}

	return test_result;
}

int exynos_pcie_dbg_unit_test(struct exynos_pcie *exynos_pcie)
{
	int ret = 0;

	if (exynos_pcie->ep_power_gpio < 0) {
		pcie_warn("can't find wlan pin info. Need to check EP device power pin\n");
	} else {
		gpio_direction_output(exynos_pcie->ep_power_gpio, 0);
		gpio_set_value(exynos_pcie->ep_power_gpio, 0);
		mdelay(100);
		gpio_set_value(exynos_pcie->ep_power_gpio, 1);
		mdelay(100);
	}

	pcie_info("1. Test PCIe LINK...\n");
	/* Test PCIe Link */
	if (chk_pcie_link(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[1/6]!!!\n");
		ret = -1;
		goto done;
	}

	pcie_info("2. Test DBI access...\n");
	/* Test PCIe DBI access */
	if (chk_dbi_access(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[2/6]!!!\n");
		ret = -2;
		goto done;
	}

	pcie_info("3. Test EP configuration access...\n");
	/* Test EP configuration access */
	if (chk_epconf_access(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[3/6]!!!\n");
		ret = -3;
		goto done;
	}

	pcie_info("4. Test EP Outbound memory region...\n");
	/* Test EP Outbound memory region */
	if (chk_epmem_access(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[4/6]!!!\n");
		ret = -4;
		goto done;
	}

	pcie_info("5. Test PCIe Link recovery...\n");
	/* PCIe Link recovery test */
	if (chk_link_recovery(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[5/6]!!!\n");
		ret = -5;
		goto done;
	}

	pcie_info("6. Test PCIe Dislink...\n");
	/* PCIe DisLink Test */
	if (chk_pcie_dislink(exynos_pcie)) {
		pcie_info("PCIe UNIT test FAIL[6/6]!!!\n");
		ret = -6;
		goto done;
	}

done:
	return ret;
}

int exynos_pcie_dbg_link_test(struct device *dev,
			struct exynos_pcie *exynos_pcie, int enable)
{
	int ret;

	pcie_info("TEST PCIe %sLink Test\n", enable ? "" : "Dis");

	if (enable) {
		if (exynos_pcie->ep_power_gpio < 0) {
			pcie_warn("can't find wlan pin info. Need to check EP device power pin\n");
		} else {
			pcie_err("## make gpio direction to output\n");
			gpio_direction_output(exynos_pcie->ep_power_gpio, 0);

			pcie_err("## make gpio set high\n");
			gpio_set_value(exynos_pcie->ep_power_gpio, 1);
			mdelay(100);
		}

		mdelay(100);
		ret = exynos_pcie_rc_poweron(exynos_pcie->ch_num);
	} else {
		exynos_pcie_rc_poweroff(exynos_pcie->ch_num);

		if (exynos_pcie->ep_power_gpio < 0) {
			pcie_warn("can't find wlan pin info. Need to check EP device power pin\n");
		} else {
			gpio_set_value(exynos_pcie->ep_power_gpio, 0);
		}
		ret = 0;
	}

	return ret;

}

static ssize_t exynos_pcie_eom1_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct exynos_pcie *exynos_pcie = dev_get_drvdata(dev);
	struct pcie_eom_result **eom_result = exynos_pcie->eom_result;
	struct device_node *np = dev->of_node;
	int len = 0;
	u32 test_cnt = 0;
	static int current_cnt = 0;
	unsigned int lane_width = 1;
	int i = 0, ret;

	if (eom_result  == NULL) {
		len += snprintf(buf + len, PAGE_SIZE,
				"eom_result structure is NULL !!!\n");
		goto exit;
	}

	ret = of_property_read_u32(np, "num-lanes", &lane_width);
	if (ret)
		lane_width = 0;

	while (current_cnt != PCIE_EOM_PH_SEL_MAX * PCIE_EOM_DEF_VREF_MAX) {
		len += snprintf(buf + len, PAGE_SIZE,
				"%u %u %lu\n",
				eom_result[i][current_cnt].phase,
				eom_result[i][current_cnt].vref,
				eom_result[i][current_cnt].err_cnt);
		current_cnt++;
		test_cnt++;
		if (test_cnt == 100)
			break;
	}

	if (current_cnt == PCIE_EOM_PH_SEL_MAX * PCIE_EOM_DEF_VREF_MAX)
		current_cnt = 0;

exit:
	return len;
}

static ssize_t exynos_pcie_eom1_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int op_num;
	struct exynos_pcie *exynos_pcie = dev_get_drvdata(dev);

	if (sscanf(buf, "%10d", &op_num) == 0)
		return -EINVAL;
	switch (op_num) {
	case 0:
		if (exynos_pcie->phy->phy_ops.phy_eom != NULL)
			exynos_pcie->phy->phy_ops.phy_eom(dev,
					exynos_pcie->phy_base);
		break;
	}

	return count;
}

static ssize_t exynos_pcie_eom2_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	/* prevent to print kerenl warning message
	   eom1_store function do all operation to get eom data */

	return count;
}

static ssize_t exynos_pcie_eom2_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct exynos_pcie *exynos_pcie = dev_get_drvdata(dev);
	struct pcie_eom_result **eom_result = exynos_pcie->eom_result;
	struct device_node *np = dev->of_node;
	int len = 0;
	u32 test_cnt = 0;
	static int current_cnt = 0;
	unsigned int lane_width = 1;
	int i = 1, ret;

	if (eom_result  == NULL) {
		len += snprintf(buf + len, PAGE_SIZE,
				"eom_result structure is NULL !!!\n");
		goto exit;
	}

	ret = of_property_read_u32(np, "num-lanes", &lane_width);
	if (ret) {
		lane_width = 0;
		len += snprintf(buf + len, PAGE_SIZE,
				"can't get num of lanes !!\n");
		goto exit;
	}

	if (lane_width == 1) {
		len += snprintf(buf + len, PAGE_SIZE,
				"EOM2NULL\n");
		goto exit;
	}

	while (current_cnt != PCIE_EOM_PH_SEL_MAX * PCIE_EOM_DEF_VREF_MAX) {
		len += snprintf(buf + len, PAGE_SIZE,
				"%u %u %lu\n",
				eom_result[i][current_cnt].phase,
				eom_result[i][current_cnt].vref,
				eom_result[i][current_cnt].err_cnt);
		current_cnt++;
		test_cnt++;
		if (test_cnt == 100)
			break;
	}

	if (current_cnt == PCIE_EOM_PH_SEL_MAX * PCIE_EOM_DEF_VREF_MAX)
		current_cnt = 0;

exit:
	return len;
}

static DEVICE_ATTR(eom1, S_IWUSR | S_IWGRP | S_IRUSR | S_IRGRP,
			exynos_pcie_eom1_show, exynos_pcie_eom1_store);

static DEVICE_ATTR(eom2, S_IWUSR | S_IWGRP | S_IRUSR | S_IRGRP,
			exynos_pcie_eom2_show, exynos_pcie_eom2_store);

int create_pcie_eom_file(struct device *dev)
{
	struct device_node *np = dev->of_node;
	int ret;
	int num_lane;

	ret = of_property_read_u32(np, "num-lanes", &num_lane);
	if (ret)
		num_lane = 0;

	ret = device_create_file(dev, &dev_attr_eom1);
	if (ret) {
		dev_err(dev, "%s: couldn't create device file for eom(%d)\n",
				__func__, ret);
		return ret;
	}

	if (num_lane > 0) {
		ret = device_create_file(dev, &dev_attr_eom2);
		if (ret) {
			dev_err(dev, "%s: couldn't create device file for eom(%d)\n",
					__func__, ret);
			return ret;
		}

	}

	return 0;
}

void remove_pcie_eom_file(struct device *dev)
{
	if (dev == NULL) {
		pr_err("Can't remove EOM files.\n");
		return;
	}
	device_remove_file(dev, &dev_attr_eom1);
}

static ssize_t exynos_pcie_rc_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	int ret = 0;
	ret += snprintf(buf + ret, PAGE_SIZE - ret, ">>>> PCIe Test <<<<\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "0 : PCIe Unit Test\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "1 : Link Test\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "2 : DisLink Test\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "3 : Check LTSSM state\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "5 : Print Reg\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "6 : DBG ON/OFF\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "10 : L1.2 disable\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "11 : L1.2 enable\n");
	ret += snprintf(buf + ret, PAGE_SIZE - ret, "20 : TEM Test\n");

	return ret;
}

int exynos_pcie_rc_lane_change(int ch_num, int req_lane);
int exynos_pcie_rc_speed_change(int ch_num, int req_speed);
int exynos_pcie_rc_poweron_speed(int ch_num, int spd);
int exynos_pcie_rc_lane_check(int ch_num);
int exynos_pcie_rc_speed_check(int ch_num);
void exynos_pcie_rc_print_msi_register(int ch_num);

static ssize_t exynos_pcie_rc_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int op_num, param1;
	struct exynos_pcie *exynos_pcie = dev_get_drvdata(dev);
	int ret = 0;
	dma_addr_t phys_addr;
	void *virt_addr, *alloc;
	u32 val, val2;


	if (sscanf(buf, "%10d %10d", &op_num, &param1) == 0)
		return -EINVAL;

	switch (op_num) {
	case 0:
		pcie_info("## PCIe UNIT test START ##\n");
		if (exynos_pcie->rc_event_reg[0])
			exynos_pcie->rc_event_reg[0]->callback = NULL;
		if (exynos_pcie->rc_event_reg[1])
			exynos_pcie->rc_event_reg[1]->callback = NULL;

		ret = exynos_pcie_dbg_unit_test(exynos_pcie);
		if (ret) {
			pcie_err("PCIe UNIT test failed (%d)\n", ret);
			break;
		}
		pcie_err("## PCIe UNIT test SUCCESS!!##\n");
		break;
	case 1:
		pcie_info("## PCIe establish link test ##\n");
		ret = exynos_pcie_dbg_link_test(dev, exynos_pcie, 1);
		if (ret) {
			pcie_err("PCIe establish link test failed (%d)\n", ret);
			break;
		}
		pcie_err("PCIe establish link test success\n");
		break;
	case 2:
		pcie_info("## PCIe dis-link test ##\n");
		ret = exynos_pcie_dbg_link_test(dev, exynos_pcie, 0);
		if (ret) {
			pcie_err("PCIe dis-link test failed (%d)\n", ret);
			break;
		}
		pcie_err("PCIe dis-link test success\n");
		break;
	case 3:
		pcie_info("## LTSSM ##\n");
		if (exynos_pcie->state != STATE_LINK_UP) {
			pcie_info("PCIE_ELBI_RDLH_LINKUP : 0x0\n");
			break;
		}
		val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE) &
					CTRL_LINK_STATE_LTSSM;
		pcie_info("PCIE_ELBI_RDLH_LINKUP :0x%x\n", val);
		break;
	case 5:
		if (exynos_pcie->phy->dbg_ops != NULL) {
			pm_runtime_get_sync(dev);
			exynos_pcie->phy->dbg_ops(exynos_pcie, SYSFS);
			pm_runtime_put_sync(dev);
		}
		break;
	case 6:
		if (exynos_pcie->phy->dbg_on) {
			pcie_info("DBG ON->OFF\n");
			exynos_pcie->phy->dbg_on = 0;
		} else {
			pcie_info("DBG OFF->ON (load bin)\n");
			exynos_pcie_rc_phy_load(exynos_pcie, 1);
		}
		break;
	case 10:
		pcie_info("L1.2 Disable....\n");
		exynos_pcie_l1ss_ctrl(0, PCIE_L1SS_CTRL_TEST, exynos_pcie->ch_num);
		break;

	case 11:
		pcie_info("L1.2 Enable....\n");
		exynos_pcie_l1ss_ctrl(1, PCIE_L1SS_CTRL_TEST, exynos_pcie->ch_num);
		break;

	case 12:
		if (exynos_pcie->state != STATE_LINK_UP) {
			pcie_info("l1ss_ctrl_id_state = 0x0(LINK down)\n");
			break;
		}
		pcie_info("l1ss_ctrl_id_state = 0x%08x\n",
			  exynos_pcie->l1ss_ctrl_id_state);
		val = exynos_ctrl_read(exynos_pcie, PCIE_CTRL_LINK_STATE);
		val2 = exynos_ssc_read(exynos_pcie, PCIE_SSC_PM_STS);
		pcie_info("LTSSM: %#02lx, PM_DSTATE = %#lx, L1SS(0x3=L1.2) = %#lx(%#x)\n",
			  val & CTRL_LINK_STATE_LTSSM,
			  (val & CTRL_LINK_STATE_PM_DSTATE) >> 9,
			  (val2 & SSC_PM_STS_L1SS_CHECK_MASK) >> 19, val2);
		break;

	case 13:
		pcie_info("%s: force perst setting\n", __func__);
		exynos_pcie_set_perst_gpio(exynos_pcie->ch_num, 0);
		break;

	case 15:
		pcie_info("%s: force all pwndn", __func__);
		exynos_pcie->phy->phy_ops.phy_all_pwrdn(exynos_pcie, exynos_pcie->ch_num);
		break;

	case 16:
		exynos_pcie_rc_set_outbound_atu(1, 0x47200000, 0x0, SZ_1M);
		break;

	case 17:
		if (exynos_pcie->state != STATE_LINK_UP) {
			pcie_info("l1ss_ctrl_id_state = 0x0(LINK down)\n");
			break;
		}
		exynos_pcie_rc_register_dump(exynos_pcie->ch_num);
		break;
	case 19:
		if (exynos_pcie->state != STATE_LINK_UP) {
			pcie_info("l1ss_ctrl_id_state = 0x0(LINK down)\n");
			break;
		}
		exynos_pcie_dbg_print_link_history(exynos_pcie);
		break;
	case 20: /* For the code coverage check */
		pcie_info("Start TEM test.\n");

		pcie_info("1. Start Unit Test\n");
		exynos_pcie_l1ss_ctrl(1, PCIE_L1SS_CTRL_TEST, exynos_pcie->ch_num);
		exynos_pcie_l1ss_ctrl(0, PCIE_L1SS_CTRL_TEST, exynos_pcie->ch_num);
		exynos_pcie_dbg_unit_test(exynos_pcie);


		pm_runtime_get_sync(dev);
		pcie_info("2. PCIe Power on\n");
		exynos_pcie_dbg_link_test(dev, exynos_pcie, 1);
		exynos_pcie_dbg_print_oatu_register(exynos_pcie);

		pcie_info("3. SysMMU mapping\n");
		if (exynos_pcie->use_sysmmu) {
			virt_addr = dma_alloc_coherent(&exynos_pcie->ep_pci_dev->dev,
					SZ_4K, &phys_addr, GFP_KERNEL);
			alloc = kmalloc(SZ_4K, GFP_KERNEL);
			dma_map_single(&exynos_pcie->ep_pci_dev->dev,
					alloc,
					SZ_4K,
					DMA_FROM_DEVICE);
			dma_unmap_single(&exynos_pcie->ep_pci_dev->dev, phys_addr,
					SZ_4K, DMA_FROM_DEVICE);
			dma_free_coherent(&exynos_pcie->ep_pci_dev->dev, SZ_4K, virt_addr,
					phys_addr);
		}


		pcie_info("4. Check EP related function\n");
		exynos_pcie_rc_check_function_validity(exynos_pcie);

		pm_runtime_put_sync(dev);

		remove_pcie_sys_file(NULL);
		remove_pcie_eom_file(NULL);

		if (exynos_pcie->use_sysmmu)
			kfree(alloc);
		break;
	case 21:
		pcie_info("Change Lane to %d.\n", param1);
		exynos_pcie_rc_lane_change(exynos_pcie->ch_num, param1);
		break;
	case 22:
		pcie_info("Change speed to %d.\n", param1);
		exynos_pcie_rc_speed_change(exynos_pcie->ch_num, param1);
		break;
	case 23:
		pcie_err("## make gpio direction to output\n");
		gpio_direction_output(exynos_pcie->ep_power_gpio, 0);
		pcie_err("## make gpio set high\n");
		gpio_set_value(exynos_pcie->ep_power_gpio, 1);
		mdelay(100);

		pcie_info("Link up with speed %d.\n", param1);
		exynos_pcie_rc_poweron_speed(exynos_pcie->ch_num, param1);
		break;
	case 24:
		pcie_info("PLL off!!\n");
		val = exynos_ctrl_read(exynos_pcie, 0xa204);
		val |= (0x1 << 20);
		exynos_ctrl_write(exynos_pcie, val, 0xa204);
		udelay(1);
		val &= ~(0x3 << 20);
		exynos_ctrl_write(exynos_pcie, val, 0xa204);
		udelay(1000);
		exynos_pcie_dbg_print_link_history(exynos_pcie);
		break;
	case 25:
		pcie_info("## Checking PCIe Speed & Lane  ##\n");
		pm_runtime_get_sync(dev);
		val = exynos_ssc_read(exynos_pcie, PCIE_SSC_LINK_DBG_2) &
			                      SSC_LINK_DBG_2_LTSSM_STATE;
		if (val < S_RCVRY_LOCK || val > S_L1_IDLE) {
			pcie_err("is NOT link-up state(0x%x)\n", ret);
		} else {
			ret = exynos_pcie_rc_lane_check(exynos_pcie->ch_num);
			if (ret < 0) {
				pcie_err("PCIe lane check failed(%d)\n", ret);
			} else {
				pcie_info("Current PCIe Lane is %d\n", ret);
			}

			ret = exynos_pcie_rc_speed_check(exynos_pcie->ch_num);
			if (ret < 0) {
				pcie_err("PCIe Speed check failed(%d)\n", ret);
			} else {
				pcie_info("Current PCIe Speed is GEN %d\n", ret);
			}
		}
		pm_runtime_put_sync(dev);
		break;
	}

	return count;
}

static DEVICE_ATTR(pcie_rc_test, S_IWUSR | S_IWGRP | S_IRUSR | S_IRGRP,
			exynos_pcie_rc_show, exynos_pcie_rc_store);

int create_pcie_sys_file(struct device *dev)
{
	int ret;

	ret = device_create_file(dev, &dev_attr_pcie_rc_test);
	if (ret) {
		dev_err(dev, "%s: couldn't create device file for test(%d)\n",
				__func__, ret);
		return ret;
	}

	return 0;
}

void remove_pcie_sys_file(struct device *dev)
{
	if (dev == NULL) {
		pr_err("Can't remove pcie_rc_test file.\n");
		return;
	}
	device_remove_file(dev, &dev_attr_pcie_rc_test);
}

