// SPDX-License-Identifier: GPL-2.0
/**
 * dwc3-exynos.c - Samsung EXYNOS DWC3 Specific Glue layer
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Author: Anton Tikhomirov <av.tikhomirov@samsung.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include <linux/usb/otg.h>
#include <linux/usb/usb_phy_generic.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/regulator/consumer.h>
#include <linux/workqueue.h>
#include <linux/usb/gadget.h>

#include <linux/usb/of.h>

#include "core.h"
#include "core-exynos.h"
#include "dwc3-exynos.h"
#include "io.h"
#include "gadget.h"

#include <linux/io.h>
#include <linux/usb/otg-fsm.h>

#include <linux/suspend.h>

#include "exynos-otg.h"
#include "dwc3-exynos.h"
#include "dwc3_kret.h"
#ifdef CONFIG_OF
#include <linux/of_device.h>
#endif

#if IS_ENABLED(CONFIG_USB_TYPEC_MANAGER_NOTIFIER)
#include <linux/usb/typec/manager/usb_typec_manager_notifier.h>
#endif
#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
#include <linux/usb_notify.h>
#endif
#include <linux/kprobes.h>
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
#include <linux/usb/f_ss_mon_gadget.h>
#endif
#include <soc/samsung/exynos-cpupm.h>
#include "../host/xhci-exynos-audio.h"

#ifdef CONFIG_SND_EXYNOS_USB_AUDIO
#include "../../../sound/usb/exynos_usb_audio.h"
struct host_data xhci_data;
EXPORT_SYMBOL_GPL(xhci_data);
#endif

struct usb_xhci_pre_alloc xhci_pre_alloc;
EXPORT_SYMBOL_GPL(xhci_pre_alloc);

void __iomem		*usb3_portsc;
EXPORT_SYMBOL_GPL(usb3_portsc);

bool g_vbus_active;
EXPORT_SYMBOL_GPL(g_vbus_active);
/* -------------------------------------------------------------------------- */
/*struct dwc3_exynos_rsw {
	struct otg_fsm		*fsm;
	struct work_struct	work;
};



struct dwc3_exynos {
	struct platform_device	*usb2_phy;
	struct platform_device	*usb3_phy;
	struct device		*dev;
	struct dwc3		*dwc;

	struct clk		**clocks;

	struct regulator	*vdd33;
	struct regulator	*vdd10;

	int			idle_ip_index;

	struct dwc3_exynos_rsw	rsw;
};
*/
extern void dwc3_otg_run_sm(struct otg_fsm *fsm);

static const struct of_device_id exynos_dwc3_match[] = {
	{
		.compatible = "samsung,exynos-dwusb",
	},
	{},
};
MODULE_DEVICE_TABLE(of, exynos_dwc3_match);

inline u32 dwc3_exynos_readl(void __iomem *base, u32 offset)
{
	/*
	 * We requested the mem region starting from the Globals address
	 * space, see dwc3_probe in core.c.
	 * However, the offsets are given starting from xHCI address space.
	 */
	return readl(base + offset - DWC3_GLOBALS_REGS_START);
}
EXPORT_SYMBOL_GPL(dwc3_exynos_readl);

inline void dwc3_exynos_writel(void __iomem *base, u32 offset, u32 value)
{
	/*
	 * We requested the mem region starting from the Globals address
	 * space, see dwc3_probe in core.c.
	 * However, the offsets are given starting from xHCI address space.
	 */
	writel(value, base + offset - DWC3_GLOBALS_REGS_START);
}
EXPORT_SYMBOL_GPL(dwc3_exynos_writel);

static int dwc3_exynos_clk_get(struct dwc3_exynos *exynos)
{
	struct device *dev = exynos->dev;
	const char **clk_ids;
	struct clk *clk;
	int clk_count;
	int ret, i;

	clk_count = of_property_count_strings(dev->of_node, "clock-names");
	if (IS_ERR_VALUE((unsigned long)clk_count)) {
		dev_err(dev, "invalid clk list in %s node", dev->of_node->name);
		return -EINVAL;
	}

	clk_ids = (const char **)devm_kmalloc(dev,
				(clk_count + 1) * sizeof(const char *),
				GFP_KERNEL);
	if (!clk_ids) {
		dev_err(dev, "failed to alloc for clock ids");
		return -ENOMEM;
	}

	for (i = 0; i < clk_count; i++) {
		ret = of_property_read_string_index(dev->of_node, "clock-names",
								i, &clk_ids[i]);
		if (ret) {
			dev_err(dev, "failed to read clocks name %d from %s node\n",
					i, dev->of_node->name);
			return ret;
		}
		/*
		 * Check Bus clock to get clk node from DT.
		 * CAUTION : Bus clock SHOULD be defiend at the last.
		 */
		if (!strncmp(clk_ids[i], "bus", 3)) {
			dev_info(dev, "BUS clock is defined.\n");
			exynos->bus_clock = devm_clk_get(exynos->dev, clk_ids[i]);
			if (IS_ERR_OR_NULL(exynos->bus_clock))
				dev_err(dev, "Can't get Bus clock.\n");
		}
		if (!strncmp(clk_ids[i], "sclk", 4)) {
			dev_info(dev, "Source clock is defined.\n");
			exynos->sclk_clock = devm_clk_get(exynos->dev, clk_ids[i]);
			if (IS_ERR_OR_NULL(exynos->sclk_clock))
				dev_err(dev, "Can't get Source clock.\n");
		}
	}

	clk_ids[clk_count] = NULL;

	exynos->clocks = (struct clk **) devm_kmalloc(exynos->dev,
			clk_count * sizeof(struct clk *), GFP_KERNEL);
	if (!exynos->clocks) {
		dev_err(exynos->dev, "%s: couldn't alloc\n", __func__);
		return -ENOMEM;
	}

	for (i = 0; clk_ids[i] != NULL; i++) {
		clk = devm_clk_get(exynos->dev, clk_ids[i]);
		if (IS_ERR_OR_NULL(clk))
			goto err;

		exynos->clocks[i] = clk;
	}
	exynos->clocks[i] = NULL;

	return 0;

err:
	dev_err(exynos->dev, "couldn't get %s clock\n", clk_ids[i]);
	return -EINVAL;
}

static int dwc3_exynos_clk_prepare(struct dwc3_exynos *exynos)
{
	int i;
	int ret;

	for (i = 0; exynos->clocks[i] != NULL; i++) {
		ret = clk_prepare(exynos->clocks[i]);
		if (ret)
			goto err;
	}

	return 0;

err:
	dev_err(exynos->dev, "couldn't prepare clock[%d]\n", i);

	/* roll back */
	for (i = i - 1; i >= 0; i--)
		clk_unprepare(exynos->clocks[i]);

	return ret;
}

static int dwc3_exynos_clk_enable(struct dwc3_exynos *exynos)
{
	int i;
	int ret;

	for (i = 0; exynos->clocks[i] != NULL; i++) {
		ret = clk_enable(exynos->clocks[i]);
		if (ret)
			goto err;
	}

	return 0;

err:
	dev_err(exynos->dev, "couldn't enable clock[%d]\n", i);

	/* roll back */
	for (i = i - 1; i >= 0; i--)
		clk_disable(exynos->clocks[i]);

	return ret;
}

static void dwc3_exynos_clk_unprepare(struct dwc3_exynos *exynos)
{
	int i;

	for (i = 0; exynos->clocks[i] != NULL; i++)
		clk_unprepare(exynos->clocks[i]);
}

static void dwc3_exynos_clk_disable(struct dwc3_exynos *exynos)
{
	int i;

	for (i = 0; exynos->clocks[i] != NULL; i++)
		clk_disable(exynos->clocks[i]);
}

static void dwc3_core_config(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	u32 reg, sclk;

	/* AHB bus configuration */
	reg = dwc3_exynos_readl(dwc->regs, DWC3_GSBUSCFG0);
	reg |= DWC3_GSBUSCFG0_INCRBRSTEN;

	/**
	 * AXI Bus' cache type configuration for DMA transfer.
	 * By below setting, cache type was set to Cacheable/Modifiable.
	 * From DWC USB3.0 Link version 2.20A, this cache type could be set.
	 */
	if (!DWC3_VER_IS_PRIOR(DWC3, 220A))
		reg |= (DWC3_GSBUSCFG0_DESWRREQINFO |
			DWC3_GSBUSCFG0_DATWRREQINFO |
			DWC3_GSBUSCFG0_DESRDREQINFO |
			DWC3_GSBUSCFG0_DATRDREQINFO);
	dwc3_exynos_writel(dwc->regs, DWC3_GSBUSCFG0, reg);

	if (DWC3_VER_IS_PRIOR(DWC31, 180A)) {
		/*
		 * Setting MO request limit to 8 resolved ITMON issue on MTP and DM functions
		 * Further investigation should be done by design team.
		 */
		reg = dwc3_exynos_readl(dwc->regs, DWC3_GSBUSCFG1);
		reg |= (DWC3_GSBUSCFG1_BREQLIMIT(0x8));
		dwc3_exynos_writel(dwc->regs, DWC3_GSBUSCFG1, reg);
	}

	/*
	 * WORKAROUND:
	 * For ss bulk-in data packet, when the host detects
	 * a DPP error or the internal buffer becomes full,
	 * it retries with an ACK TP Retry=1. Under the following
	 * conditions, the Retry=1 is falsely carried over to the next
	 * DWC3_GUCTL_USBHSTINAUTORETRYEN should be set to a one
	 * regardless of revision
	 * - There is only single active asynchronous SS EP at the time.
	 * - The active asynchronous EP is a Bulk IN EP.
	 * - The burst with the correctly Retry=1 ACK TP and
	 *   the next burst belong to the same transfer.
	 */
	sclk = clk_get_rate(exynos->sclk_clock);
	pr_info("%s: sclk is %d MHz\n", __func__, sclk / 1000 / 1000);

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUCTL);
	reg |= (DWC3_GUCTL_USBHSTINAUTORETRYEN);

	if (exynos->config.sparse_transfer_control)
		reg |= DWC3_GUCTL_SPRSCTRLTRANSEN;

	if (exynos->config.no_extra_delay)
		reg |= DWC3_GUCTL_NOEXTRDL;

	if (exynos->config.usb_host_device_timeout) {
		reg &= ~DWC3_GUCTL_DTOUT_MASK;
		reg |= DWC3_GUCTL_DTOUT(exynos->config.usb_host_device_timeout);
	}

	dwc3_exynos_writel(dwc->regs, DWC3_GUCTL, reg);
	if (DWC3_VER_IS_WITHIN(DWC3, 190A, 210A)) {
		reg = dwc3_exynos_readl(dwc->regs, DWC3_GRXTHRCFG);
		reg &= ~(DWC3_GRXTHRCFG_USBRXPKTCNT_MASK |
			DWC3_GRXTHRCFG_USBMAXRXBURSTSIZE_MASK);
		reg |= (DWC3_GRXTHRCFG_USBRXPKTCNTSEL |
			DWC3_GRXTHRCFG_USBRXPKTCNT(3) |
			DWC3_GRXTHRCFG_USBMAXRXBURSTSIZE(3));
		dwc3_exynos_writel(dwc->regs, DWC3_GRXTHRCFG, reg);
	}

	if (DWC3_IP_IS(DWC31) || DWC3_IP_IS(DWC32)) {
		reg = dwc3_exynos_readl(dwc->regs, DWC3_GUCTL3);
		if (exynos->config.usb20_pkt_retry_disable)
			reg |= DWC3_GUCTL3_RETRYDISABLE;
		else
			reg &= ~DWC3_GUCTL3_RETRYDISABLE;
		dwc3_exynos_writel(dwc->regs, DWC3_GUCTL3, reg);
	}

	/*
	 * WORKAROUND: DWC3 revisions 2.10a and earlier have a bug
	 * The delay of the entry to a low power state such that
	 * for applications where the link stays in a non-U0 state
	 * for a short duration(< 1 microsecond),
	 * the local PHY does not enter the low power state prior
	 * to receiving a potential LFPS wakeup.
	 * This causes the PHY CDR (Clock and Data Recovery) operation
	 * to be unstable for some Synopsys PHYs.
	 * The proposal now is to change the default and the recommended value
	 * for GUSB3PIPECTL[21:19] in the RTL from 3'b100 to a minimum of 3'b001
	 */
	if (DWC3_VER_IS_PRIOR(DWC3, 220A)) {
		reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));
		reg &= ~(DWC3_GUSB3PIPECTL_DEP1P2P3_MASK);
		reg |= (DWC3_GUSB3PIPECTL_DEP1P2P3_EN);
		dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);
	}

	if (!DWC3_VER_IS_PRIOR(DWC3, 250A)) {
		reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));
		reg |= DWC3_GUSB3PIPECTL_DISRXDETINP3;
		dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);
	}

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));
	if (exynos->config.elastic_buf_mode_quirk)
		reg |= DWC3_ELASTIC_BUFFER_MODE;
	dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);

	if (!DWC3_VER_IS_PRIOR(DWC31, 120A)) {
		reg = dwc3_exynos_readl(dwc->regs, DWC3_LLUCTL);
		reg &= ~(DWC3_LLUCTL_TX_TS1_CNT_MASK);
		reg |= (DWC3_PENDING_HP_TIMER_US(0xb) | DWC3_EN_US_HP_TIMER) |
		    (DWC3_LLUCTL_PIPE_RESET) | (DWC3_LLUCTL_LTSSM_TIMER_OVRRD) |
		    (DWC3_LLUCTL_TX_TS1_CNT(0x7));
		if (exynos->config.force_gen1)
			reg |= DWC3_FORCE_GEN1;
		dwc3_exynos_writel(dwc->regs, DWC3_LLUCTL, reg);

		reg = dwc3_exynos_readl(dwc->regs, DWC3_LSKIPFREQ);
		reg &= ~(DWC3_PM_LC_TIMER_US_MASK | DWC3_PM_ENTRY_TIMER_US_MASK);
		reg |= (DWC3_PM_ENTRY_TIMER_US(0x9) |
			DWC3_PM_LC_TIMER_US(0x5) | DWC3_EN_PM_TIMER_US);
		dwc3_exynos_writel(dwc->regs, DWC3_LSKIPFREQ, reg);

		reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));
		reg &= ~DWC3_GUSB3PIPECTL_DISRXDETINP3;
		dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);

		reg = dwc3_exynos_readl(dwc->regs, DWC3_BU31RHBDBG);
		reg |= DWC3_BU31RHBDBG_TOUTCTL;
		dwc3_exynos_writel(dwc->regs, DWC3_BU31RHBDBG, reg);

		reg = dwc3_exynos_readl(dwc->regs, DWC3_GUCTL1);
		reg &= ~DWC3_GUCTL1_IP_GAP_ADD_ON_MASK;
		reg |= DWC3_GUCTL1_IP_GAP_ADD_ON(0x1);
		reg |= DWC3_GUCTL1_DEV_DECOUPLE_L1L2_EVT;
		reg |= DWC3_GUCTL1_DEV_L1_EXIT_BY_HW;
		dwc3_exynos_writel(dwc->regs, DWC3_GUCTL1, reg);
	}

	/* Enable interrupt moderation */
	dwc->imod_interval = 1;
}

static void dwc3_exynos_phy_setup(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	u32 reg;

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));

	if (exynos->config.ux_exit_in_px_quirk)
		reg |= DWC3_GUSB3PIPECTL_UX_EXIT_PX;

	if (exynos->config.u1u2_exitfail_to_recov_quirk)
		reg |= DWC3_GUSB3PIPECTL_U1U2EXITFAIL_TO_RECOV;

	dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB2PHYCFG(0));

	if (!dwc->dis_enblslpm_quirk)
		reg |= DWC3_GUSB2PHYCFG_ENBLSLPM;

	if (exynos->config.adj_sof_accuracy)
		reg &= ~DWC3_GUSB2PHYCFG_U2_FREECLK_EXISTS;

	dwc3_exynos_writel(dwc->regs, DWC3_GUSB2PHYCFG(0), reg);
}

/* Exynos Specific Configurations */
int dwc3_exynos_core_init(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	u32 reg, sclk;

	dwc3_exynos_phy_setup(dwc, exynos);

	dwc3_core_config(dwc, exynos);

	sclk = clk_get_rate(exynos->sclk_clock);
	pr_info("%s: sclk is %d MHz\n", __func__, sclk / 1000 / 1000);

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GCTL);

	if (dwc->dis_u2_freeclk_exists_quirk)
		reg |= DWC3_GCTL_SOFITPSYNC;
	else
		reg &= ~DWC3_GCTL_SOFITPSYNC;

	if (exynos->config.adj_sof_accuracy)
		reg &= ~DWC3_GCTL_SOFITPSYNC;

	if (exynos->config.suspend_clk_freq) {
		reg &= ~DWC3_GCTL_PWRDNSCALE_MASK;
		reg |= DWC3_GCTL_PWRDNSCALE(
				exynos->config.suspend_clk_freq / (16 * 1000));
	}

	dwc3_exynos_writel(dwc->regs, DWC3_GCTL, reg);

	pr_info("%s GUCTL: 0x%08x\n", __func__, dwc3_exynos_readl(dwc->regs, DWC3_GUCTL));
	pr_info("%s GFLADJ: 0x%08x\n", __func__, dwc3_exynos_readl(dwc->regs, DWC3_GFLADJ));

	return 0;
}

void dwc3_exynos_gadget_disconnect_proc(struct dwc3 *dwc)
{
	int			reg;

	reg = dwc3_exynos_readl(dwc->regs, DWC3_DCTL);
	reg &= ~DWC3_DCTL_INITU1ENA;
	dwc3_exynos_writel(dwc->regs, DWC3_DCTL, reg);

	reg &= ~DWC3_DCTL_INITU2ENA;
	dwc3_exynos_writel(dwc->regs, DWC3_DCTL, reg);

	if (dwc->gadget_driver && dwc->gadget_driver->disconnect)
		dwc->gadget_driver->disconnect(dwc->gadget);

	dwc->gadget->speed = USB_SPEED_UNKNOWN;
	dwc->setup_packet_pending = false;
	usb_gadget_set_state(dwc->gadget, USB_STATE_NOTATTACHED);

	dwc->connected = false;
}

int dwc3_core_susphy_set(struct dwc3 *dwc, int on)
{
	u32		reg;

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB3PIPECTL(0));
	if (on)
		reg |= DWC3_GUSB3PIPECTL_SUSPHY;
	else
		reg &= ~DWC3_GUSB3PIPECTL_SUSPHY;
	dwc3_exynos_writel(dwc->regs, DWC3_GUSB3PIPECTL(0), reg);

	reg = dwc3_exynos_readl(dwc->regs, DWC3_GUSB2PHYCFG(0));
	if (on)
		reg |= DWC3_GUSB2PHYCFG_SUSPHY;
	else
		reg &= ~DWC3_GUSB2PHYCFG_SUSPHY;
	dwc3_exynos_writel(dwc->regs, DWC3_GUSB2PHYCFG(0), reg);

	return 0;
}


/* -------------------------------------------------------------------------- */
static struct dwc3_exynos *dwc3_exynos_match(struct device *dev)
{
	const struct of_device_id *matches = NULL;
	struct dwc3_exynos *exynos = NULL;

	if (!dev)
		return NULL;

	matches = exynos_dwc3_match;

	if (of_match_device(matches, dev))
		exynos = dev_get_drvdata(dev);

	return exynos;
}

bool dwc3_exynos_rsw_available(struct device *dev)
{
	struct dwc3_exynos *exynos;

	exynos = dwc3_exynos_match(dev);
	if (!exynos)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_rsw_available);

int dwc3_exynos_rsw_start(struct device *dev)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct dwc3_exynos_rsw	*rsw = &exynos->rsw;

	dev_info(dev, "%s\n", __func__);

	/* B-device by default */
	rsw->fsm->id = 1;
	rsw->fsm->b_sess_vld = 0;

	return 0;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_rsw_start);

int dwc3_exynos_set_sclk_clock(struct device *dev)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);
	int sclk_rate;

	if(!of_property_read_u32(dev->of_node, "sclk_rate", &sclk_rate)) {
		dev_info(dev, "sclk_rate from dts node is %d\n", sclk_rate);
	}else {
		dev_info(dev, "sclk_rate is not defined...Use default value(19.2Mhz)\n");
		sclk_rate = 19500000;
	}
	dev_info(dev, "Set USB Source clock to %d hz\n", sclk_rate);
	clk_set_rate(exynos->sclk_clock, sclk_rate);
	dev_info(dev, "Changed USB Source clock %ld\n",
				clk_get_rate(exynos->sclk_clock));

	return 0;
}

static void dwc3_exynos_rsw_work(struct work_struct *w)
{
	struct dwc3_exynos_rsw	*rsw = container_of(w,
					struct dwc3_exynos_rsw, work);
	struct dwc3_exynos	*exynos = container_of(rsw,
					struct dwc3_exynos, rsw);

	dev_info(exynos->dev, "%s\n", __func__);

	dwc3_otg_run_sm(rsw->fsm);
}

int dwc3_exynos_rsw_setup(struct device *dev, struct otg_fsm *fsm)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct dwc3_exynos_rsw	*rsw = &exynos->rsw;

	dev_dbg(dev, "%s\n", __func__);

	INIT_WORK(&rsw->work, dwc3_exynos_rsw_work);

	rsw->fsm = fsm;

	return 0;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_rsw_setup);

/**
 * dwc3_exynos_id_event - receive ID pin state change event.
 * @state : New ID pin state.
 */
int dwc3_exynos_id_event(struct device *dev, int state)
{
	struct dwc3_exynos	*exynos;
	struct dwc3_exynos_rsw	*rsw;
	struct otg_fsm		*fsm;

	dev_dbg(dev, "EVENT: ID: %d\n", state);

	exynos = dev_get_drvdata(dev);
	if (!exynos)
		return -ENOENT;

	if (!exynos->usb_data_enabled) {
		dev_info(exynos->dev, "skip the notification due to USB enumeration disabled\n");
		return NOTIFY_OK;
	}

	rsw = &exynos->rsw;

	fsm = rsw->fsm;
	if (!fsm)
		return -ENOENT;

	if (fsm->id != state) {
		fsm->id = state;
		schedule_work(&rsw->work);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_id_event);

/**
 * dwc3_exynos_vbus_event - receive VBus change event.
 * vbus_active : New VBus state, true if active, false otherwise.
 */
int dwc3_exynos_vbus_event(struct device *dev, bool vbus_active)
{
	struct dwc3_exynos	*exynos;
	struct dwc3_exynos_rsw	*rsw;
	struct otg_fsm		*fsm;

	dev_dbg(dev, "EVENT: VBUS: %sactive\n", vbus_active ? "" : "in");

	exynos = dev_get_drvdata(dev);
	if (!exynos) {
		dev_err(dev, "%s: exynos is NULL!!\n", __func__);
		return -ENOENT;
	}

	g_vbus_active = vbus_active;

	if (!exynos->usb_data_enabled) {
		dev_info(exynos->dev, "skip the notification due to USB enumeration disabled\n");
		return NOTIFY_OK;
	}

	rsw = &exynos->rsw;
	fsm = rsw->fsm;
	if (!fsm) {
		dev_err(dev, "%s: fsm is NULL!!\n", __func__);
		return -ENOENT;
	}

	mutex_lock(&fsm->lock);
	if (fsm->b_sess_vld != vbus_active) {
		fsm->b_sess_vld = vbus_active;
		schedule_work(&rsw->work);
	} else {
		dev_err(dev, "%s: vbus state is unmatched!! \
		fsm->b_sess_vld: %d, vbus_active: %d\n", __func__,
		fsm->b_sess_vld, vbus_active);
	}
	mutex_unlock(&fsm->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_vbus_event);

/**
 * dwc3_exynos_phy_enable - received combo phy control.
 */
int dwc3_exynos_phy_enable(int owner, bool on)
{
	struct dwc3_exynos	*exynos;
	struct dwc3_exynos_rsw	*rsw;
	struct otg_fsm		*fsm;
	struct device_node *np = NULL;
	struct platform_device *pdev = NULL;
	struct dwc3		*dwc;
	struct device		*dev;
	struct device		*exynos_dev;
	struct dwc3_otg		*dotg;
	int wait_counter;
	int ret = 0;

	pr_info("%s owner=%d (usb:0 dp:1) on=%d +\n", __func__, owner, on);

	np = of_find_compatible_node(NULL, NULL, "samsung,exynos-dwusb");
	if (np) {
		pdev = of_find_device_by_node(np);
		if (!pdev) {
			pr_err("%s we can't get platform device\n", __func__);
			ret = -ENODEV;
			goto err;
		}
		of_node_put(np);
	} else {
		pr_err("%s we can't get np\n", __func__);
		ret = -ENODEV;
		goto err;
	}

	exynos = platform_get_drvdata(pdev);
	if (!exynos) {
		pr_err("%s we can't get drvdata\n", __func__);
		ret = -ENOENT;
		goto err;
	}

	rsw = &exynos->rsw;

	fsm = rsw->fsm;
	if (!fsm) {
		pr_err("%s we can't get fsm\n", __func__);
		ret = -ENOENT;
		goto err;
	}

	dwc = exynos->dwc;
	dev = dwc->dev;
	exynos_dev = exynos->dev;
	dotg = exynos->dotg;
	if (on) {
		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));
		wait_counter = 0;
		if (dotg->dwc3_suspended != USB_NORMAL) {
			while (!pm_runtime_suspended(exynos->dev)) {
				msleep(5);
				pr_info("%s: wait AP resume, %d!\n", __func__, wait_counter++);
				if (wait_counter >= 3) {
					pr_info("%s: Can't wait AP resume break!\n", __func__);
					break;
				}
			}
		}
		dotg->dwc3_suspended = USB_NORMAL;
		pr_info("%s %d\n", __func__, __LINE__);
		ret = pm_runtime_get_sync(exynos_dev);
		if (ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize exynos: %d\n",
					__func__, ret);
			pm_runtime_set_suspended(exynos_dev);
		}
		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
		pr_info("%s %d\n", __func__, __LINE__);
		ret = pm_runtime_get_sync(dev);
		if (ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize core: %d\n",
					__func__, ret);
			pm_runtime_set_suspended(dev);
		}
	}
	else {
		pm_runtime_put_sync_suspend(dev);
		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
		pm_runtime_put_sync_suspend(exynos_dev);
		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));
	}

err:
	pr_info("%s -\n", __func__);
	return ret;
}
EXPORT_SYMBOL_GPL(dwc3_exynos_phy_enable);

static int dwc3_exynos_register_phys(struct dwc3_exynos *exynos)
{
	struct platform_device	*pdev;
	int			ret;
	pdev = platform_device_alloc("usb_phy_generic", PLATFORM_DEVID_AUTO);

	if (!pdev)
		return -ENOMEM;

	exynos->usb2_phy = pdev;
	pdev = platform_device_alloc("usb_phy_generic", PLATFORM_DEVID_AUTO);
	if (!pdev) {
		ret = -ENOMEM;
		goto err1;
	}

	exynos->usb3_phy = pdev;
	ret = platform_device_add(exynos->usb2_phy);
	if (ret)
		goto err2;

	ret = platform_device_add(exynos->usb3_phy);
	if (ret)
		goto err3;

	return 0;

err3:
	platform_device_del(exynos->usb2_phy);

err2:
	platform_device_put(exynos->usb3_phy);

err1:
	platform_device_put(exynos->usb2_phy);

	return ret;
}

static int dwc3_exynos_remove_child(struct device *dev, void *unused)
{
	struct platform_device *pdev = to_platform_device(dev);

	platform_device_unregister(pdev);

	return 0;
}

static void dwc3_exynos_host_fill_xhci_irq_res(struct dwc3 *dwc,
					int irq, char *name)
{
	struct platform_device *pdev = to_platform_device(dwc->dev);
	struct device_node *np = dev_of_node(&pdev->dev);

	dwc->xhci_resources[1].start = irq;
	dwc->xhci_resources[1].end = irq;
	dwc->xhci_resources[1].flags = IORESOURCE_IRQ | irq_get_trigger_type(irq);
	if (!name && np)
		dwc->xhci_resources[1].name = of_node_full_name(pdev->dev.of_node);
	else
		dwc->xhci_resources[1].name = name;
}

static int dwc3_exynos_host_get_irq(struct dwc3 *dwc)
{
	struct platform_device	*dwc3_pdev = to_platform_device(dwc->dev);
	int irq;

	irq = platform_get_irq_byname_optional(dwc3_pdev, "host");
	if (irq > 0) {
		dwc3_exynos_host_fill_xhci_irq_res(dwc, irq, "host");
		goto out;
	}

	if (irq == -EPROBE_DEFER)
		goto out;

	irq = platform_get_irq_byname_optional(dwc3_pdev, "dwc_usb3");
	if (irq > 0) {
		dwc3_exynos_host_fill_xhci_irq_res(dwc, irq, "dwc_usb3");
		goto out;
	}

	if (irq == -EPROBE_DEFER)
		goto out;

	irq = platform_get_irq(dwc3_pdev, 0);
	if (irq > 0) {
		dwc3_exynos_host_fill_xhci_irq_res(dwc, irq, NULL);
		goto out;
	}

	if (!irq)
		irq = -EINVAL;

out:
	return irq;
}

static int dwc3_exynos_host_init(struct dwc3_exynos *exynos)
{
	struct dwc3		*dwc = exynos->dwc;
	struct property_entry	props[4];
	struct platform_device	*xhci;
	int			prop_idx = 0;
	int			ret = 0, irq = 0;

	irq = dwc3_exynos_host_get_irq(dwc);
	if (irq < 0)
		return irq;

	xhci = platform_device_alloc("xhci-hcd-exynos", PLATFORM_DEVID_AUTO);
	if (!xhci) {
		dev_err(dwc->dev, "couldn't allocate xHCI device\n");
		return -ENOMEM;
	}

	xhci->dev.parent	= dwc->dev;
	ret = dma_set_mask_and_coherent(&xhci->dev, DMA_BIT_MASK(36));
	if (ret) {
		pr_err("xhci dma set mask ret = %d\n", ret);
		return ret;
	}

	ret = platform_device_add_resources(xhci, dwc->xhci_resources,
						DWC3_XHCI_RESOURCES_NUM);
	if (ret) {
		dev_err(dwc->dev, "couldn't add resources to xHCI device\n");
		goto err;
	}

	memset(props, 0, sizeof(struct property_entry) * ARRAY_SIZE(props));

	if (dwc->usb3_lpm_capable)
		props[prop_idx++] = PROPERTY_ENTRY_BOOL("usb3-lpm-capable");

	if (dwc->usb2_lpm_disable)
		props[prop_idx++] = PROPERTY_ENTRY_BOOL("usb2-lpm-disable");

	/**
	 * WORKAROUND: dwc3 revisions <=3.00a have a limitation
	 * where Port Disable command doesn't work.
	 *
	 * The suggested workaround is that we avoid Port Disable
	 * completely.
	 *
	 * This following flag tells XHCI to do just that.
	 */
	if (DWC3_VER_IS_PRIOR(DWC3, 310A))
		props[prop_idx++] = PROPERTY_ENTRY_BOOL("quirk-broken-port-ped");

	if (prop_idx) {
		ret = device_create_managed_software_node(&xhci->dev, props, NULL);
		if (ret) {
			dev_err(dwc->dev, "failed to add properties to xHCI\n");
			goto err;
		}
	}

	dwc->xhci = xhci;

	return 0;
err:
	platform_device_put(xhci);
	return ret;
}


static u32 fixed_usb_idle_ip_index = 0;

static int dwc3_exynos_get_properties(struct dwc3_exynos *exynos)
{
	struct device *dev = exynos->dev;
	struct device_node *node = dev->of_node;
	u32 value;
	int ret = 0;

	if (!of_property_read_u32(node, "exynos,adj-sof-accuracy", &value)) {
		exynos->config.adj_sof_accuracy = value ? true : false;
		dev_info(dev, "adj-sof-accuracy set from %s node", node->name);
	} else {
		dev_err(dev, "can't get adj-sof-accuracy from %s node", node->name);
		return -EINVAL;
	}
	if (!of_property_read_u32(node, "exynos,enable_sprs_transfer", &value)) {
		exynos->config.sparse_transfer_control = value ? true : false;
	} else {
		dev_err(dev, "can't get sprs-xfer-ctrl from %s node", node->name);
		return -EINVAL;
	}
	if (!of_property_read_u32(node, "exynos,usb_host_device_timeout", &value)) {
		exynos->config.usb_host_device_timeout = value;
	} else {
		dev_info(dev, "usb_host_device_timeout is not defined...\n");
		exynos->config.usb_host_device_timeout = 0x0;
	}
	if (!of_property_read_u32(node, "exynos,suspend_clk_freq", &value)) {
		exynos->config.suspend_clk_freq = value;
	} else {
		dev_info(dev, "Set suspend clock freq to 26Mhz(Default)\n");
		exynos->config.suspend_clk_freq = 26000000;
	}
	if (of_property_read_bool(node, "lazy-vbus-up")) {
		exynos->lazy_vbus_up = 1;
		dev_info(dev, "lazy-vbus-up is enabled!!\n");
	} else
		exynos->lazy_vbus_up = 0;

	exynos->config.no_extra_delay = device_property_read_bool(dev,
					"exynos,no_extra_delay");
	exynos->config.ux_exit_in_px_quirk = device_property_read_bool(dev,
				"exynos,ux_exit_in_px_quirk");
	exynos->config.elastic_buf_mode_quirk = device_property_read_bool(dev,
				"exynos,elastic_buf_mode_quirk");
	exynos->config.force_gen1 = device_property_read_bool(dev,
				"exynos,force_gen1");
	exynos->config.u1u2_exitfail_to_recov_quirk = device_property_read_bool(
				dev, "exynos,u1u2_exitfail_quirk");
	exynos->config.usb20_pkt_retry_disable = device_property_read_bool(
				dev, "exynos,usb20_pkt_retry_disable");
	return ret;
}

#if IS_ENABLED(CONFIG_USB_TYPEC_MANAGER_NOTIFIER)
/**
 * dwc3_gadget_get_cmply_link_state - Gets current state of USB Link
 * @dwc: pointer to our context structure
 *
 * extern module can check dwc3 core link state  This function will
 * return 1 link is on compliance of loopback mode else 0.
 * add: when usb_data_enabled is set to false , return 1 to stay on usb cable.
 */
static int dwc3_gadget_get_cmply_link_state(void *dev)
{
	struct dwc3 *dwc = (struct dwc3 *)dev;
	struct dwc3_exynos *exynos = dwc3_exynos_match(dwc->dev->parent);
	u32 reg;
	u32 ret = -ENODEV;

	if (!dwc->softconnect || (exynos && !exynos->usb_data_enabled))
		return 1;

	if (dwc->pullups_connected) {
		reg = dwc3_otg_get_link_state(dwc);

		pr_info("%s: link state = %d\n", __func__, reg);
		if ((reg == DWC3_LINK_STATE_CMPLY) || (reg == DWC3_LINK_STATE_LPBK))
			ret = 1;
		else
			ret = 0;
	}

	return ret;
}

static struct typec_manager_gadget_ops typec_manager_dwc3_gadget_ops = {
	.get_cmply_link_state = dwc3_gadget_get_cmply_link_state,
};
#endif

struct kprobe_data {
	void *data0;
	void *data1;
	void *data2;
	int data3;
};

static int entry_dwc3_gadget_conndone_interrupt(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct kprobe_data *data = (struct kprobe_data *)ri->data;
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];

	data->data0 = dwc;
	return 0;
}

static int ret_dwc3_gadget_conndone_interrupt(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct kprobe_data *data = (struct kprobe_data *)ri->data;
	struct dwc3 *dwc = (struct dwc3 *)data->data0;

	pr_info("usb: dwc3_gadget_conndone_interrupt (%d)\n", dwc->speed);
	switch (dwc->speed) {
	case DWC3_DSTS_SUPERSPEED_PLUS:
#if defined(CONFIG_USB_NOTIFY_PROC_LOG)
		store_usblog_notify(NOTIFY_USBSTATE,
			(void *)"USB_STATE=ENUM:CONNDONE:PSS", NULL);
#endif
		break;
	case DWC3_DSTS_SUPERSPEED:
#if defined(CONFIG_USB_NOTIFY_PROC_LOG)
		store_usblog_notify(NOTIFY_USBSTATE,
			(void *)"USB_STATE=ENUM:CONNDONE:SS", NULL);
#endif
		break;
	case DWC3_DSTS_HIGHSPEED:
#if defined(CONFIG_USB_NOTIFY_PROC_LOG)
		store_usblog_notify(NOTIFY_USBSTATE,
			(void *)"USB_STATE=ENUM:CONNDONE:HS", NULL);
#endif
		break;
	case DWC3_DSTS_FULLSPEED:
#if defined(CONFIG_USB_NOTIFY_PROC_LOG)
		store_usblog_notify(NOTIFY_USBSTATE,
			(void *)"USB_STATE=ENUM:CONNDONE:FS", NULL);
#endif
		break;
	}
	dwc->link_state = DWC3_LINK_STATE_U0;
	return 0;
}

static int entry_dwc3_gadget_reset_interrupt(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];

#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	usb_reset_notify(dwc->gadget);
#endif
	pr_info("usb: dwc3_gadget_reset_interrupt (Speed:%d)\n", dwc->gadget->speed);
	return 0;
}

static int entry_dwc3_gadget_vbus_draw(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	unsigned int mA = (unsigned int)regs->regs[1];

	switch (mA) {
	case 2:
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
		pr_info("usb: dwc3_gadget_vbus_draw: suspend\n");
		make_suspend_current_event();
#endif
		break;
	case 100:
		break;
	case 500:
		break;
	case 900:
		break;
	default:
		break;
	}
	return 0;
}

static int entry_dwc3_gadget_run_stop(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];
	struct kprobe_data *data = (struct kprobe_data *)ri->data;
	int is_on = (int)regs->regs[1];

	data->data0 = dwc;
	data->data3 = is_on;
	pr_info("usb: dwc3_gadget_run_stop : is_on = %d\n", is_on);

	return 0;
}

static int ret_dwc3_gadget_run_stop(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	unsigned long long retval = regs_return_value(regs);
	struct kprobe_data *data = (struct kprobe_data *)ri->data;
	struct dwc3 *dwc = data->data0;
	int is_on;

	is_on = data->data3;
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	vbus_session_notify(dwc->gadget, is_on, retval);
#endif
	if (retval) {
		pr_info("usb: dwc3_gadget_run_stop : dwc3_gadget %s failed (%lld)\n",
			is_on ? "ON" : "OFF", retval);
	}

	return 0;
}

#define ENTRY_RET(name) {\
	.handler = ret_##name,\
	.entry_handler = entry_##name,\
	.data_size = sizeof(struct kprobe_data),\
	.maxactive = 8,\
	.kp.symbol_name = #name,\
}

#define ENTRY(name) {\
	.entry_handler = entry_##name,\
	.data_size = sizeof(struct kprobe_data),\
	.maxactive = 8,\
	.kp.symbol_name = #name,\
}

static struct kretprobe dwc3_exynos_probes[] = {
	ENTRY(dwc3_gadget_reset_interrupt),
	ENTRY_RET(dwc3_gadget_run_stop),
	ENTRY(dwc3_gadget_vbus_draw),
	ENTRY_RET(dwc3_gadget_conndone_interrupt),
};

static int dwc3_exyons_kretprobe_init(void)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(dwc3_exynos_probes) ; i++) {
		ret = register_kretprobe(&dwc3_exynos_probes[i]);
		if (ret < 0) {
			pr_err("register_kretprobe failed, returned %d\n", ret);
		}
	}

	return 0;
}

void dwc3_exynos_kretprobe_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dwc3_exynos_probes); i++)
		unregister_kretprobe(&dwc3_exynos_probes[i]);
}

static void dwc3_init_kprobe_work(struct work_struct *data)
{
	dwc3_exyons_kretprobe_init();
}

static int dwc3_exynos_probe(struct platform_device *pdev)
{
	struct dwc3_exynos	*exynos;
	struct device		*dev = &pdev->dev;
	struct platform_device *dwc3_pdev;
	struct device_node	*node = dev->of_node, *dwc3_np;
#ifdef USB_USE_IOCOHERENCY
	struct regmap *reg_sysreg;
#endif
	int			ret;
	struct phy		*temp_usb_phy;
	int 			wait_counter;

	dwc3_kretprobe_init();

	temp_usb_phy = devm_phy_get(dev, "usb2-phy");
	if (IS_ERR(temp_usb_phy)) {
		pr_info("USB phy is not probed - defered return!\n");
		return  -EPROBE_DEFER;
	}

	exynos = devm_kzalloc(dev, sizeof(*exynos), GFP_KERNEL);
	if (!exynos)
		return -ENOMEM;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(36));
	if (ret) {
		pr_err("dma set mask ret = %d\n", ret);
		return ret;
	}

	platform_set_drvdata(pdev, exynos);

	exynos->dev = dev;

	if (fixed_usb_idle_ip_index == 0) {
		usb_idle_ip_index = exynos_get_idle_ip_index(dev_name(dev), 1);
		pr_info("%s, usb idle ip = %d\n", __func__, usb_idle_ip_index);
		fixed_usb_idle_ip_index = usb_idle_ip_index;
		/* Dose it need?? */
		exynos_update_ip_idle_status(usb_idle_ip_index, 0);
	} else
		usb_idle_ip_index = fixed_usb_idle_ip_index;

	ret = dwc3_exynos_clk_get(exynos);
	if (ret)
		return ret;

	ret = dwc3_exynos_clk_prepare(exynos);
	if (ret)
		return ret;

	ret = dwc3_exynos_clk_enable(exynos);
	if (ret) {
		dwc3_exynos_clk_unprepare(exynos);
		return ret;
	}

	ret = dwc3_exynos_register_phys(exynos);
	if (ret) {
		dev_err(dev, "couldn't register PHYs\n");
		goto vdd33_err;
	}

	ret = dwc3_exynos_get_properties(exynos);
	if (ret) {
		dev_err(dev, "couldn't get properties.\n");
		goto vdd33_err;
	}

	pm_runtime_enable(dev);
	pr_info("%s %d\n", __func__, __LINE__);
	ret = pm_runtime_get_sync(dev);
	if (ret < 0)
		goto vdd33_err;
	pm_runtime_forbid(dev);

	dwc3_exynos_set_sclk_clock(dev);

	dwc3_np = of_get_child_by_name(node, "dwc3");
	if (!dwc3_np) {
		dev_err(dev, "failed to find dwc3 core child!\n");
		goto vdd33_err;
	}

	/* PHY enable for configurations */
	exynos_usbdrd_ldo_manual_control(1);
	exynos_usbdrd_phy_conn(temp_usb_phy, 1);

	if (node) {
		ret = of_platform_populate(node, NULL, NULL, dev);
		if (ret) {
			dev_err(dev, "failed to add dwc3 core\n");
			goto populate_err;
		}
	} else {
		dev_err(dev, "no device node, failed to add dwc3 core\n");
		ret = -ENODEV;
		goto populate_err;
	}

	dwc3_pdev = of_find_device_by_node(dwc3_np);
	exynos->dwc = platform_get_drvdata(dwc3_pdev);
	if (exynos->dwc == NULL) {
		ret = -EPROBE_DEFER;
		goto populate_err;
	}

	/*
	 * Set default ep0state to SETUP PHASE
	 * This will prevent WARN in dwc3_ep0_out_start
	 */
	exynos->dwc->ep0state = EP0_SETUP_PHASE;

	/* dwc3 core configurations */
	pm_runtime_allow(exynos->dwc->dev);
	ret = dma_set_mask_and_coherent(exynos->dwc->dev, DMA_BIT_MASK(36));
	if (ret) {
		pr_err("dwc3 core dma_set_mask returned FAIL!(%d)\n", ret);
		goto populate_err;
	}
	//exynos->dwc->imod_interval = 100;

	pm_runtime_dont_use_autosuspend(exynos->dwc->dev);
        pr_info("%s: remove system resume callback of dwc3 core\n", __func__);
        exynos->dwc3_pm_ops = *(exynos->dwc->dev->driver->pm);
        (exynos->dwc3_pm_ops).resume = NULL;
        (exynos->dwc3_pm_ops).suspend = NULL;
        exynos->dwc->dev->driver->pm = &(exynos->dwc3_pm_ops);

	/* set the initial value */
	exynos->usb_data_enabled = true;
#ifdef USB_USE_IOCOHERENCY
	dev_info(dev,"Configure USB sharability.\n");
	reg_sysreg = syscon_regmap_lookup_by_phandle(dev->of_node,
							"samsung,sysreg-usb");
	if (IS_ERR(reg_sysreg)) {
		dev_err(dev, "Failed to lookup Sysreg regmap\n");
	}
	regmap_update_bits(reg_sysreg, 0x704, 0x6, 0x6);
#endif

	ret = pm_runtime_put_sync(dev);
	pr_info("%s, pm_runtime_put_sync = %d\n",__func__, ret);
	pm_runtime_allow(dev);

	/* Wait for end of dwc3 idle */
	wait_counter = 0;
	while (exynos->dwc->current_dr_role !=
			DWC3_EXYNOS_IGNORE_CORE_OPS) {
		wait_counter++;
		msleep(20);

		if (wait_counter > 10) {
			pr_err("Can't wait dwc3 idle!!!!\n");
			break;
		}
	}

	/* PHY disable */
	exynos_usbdrd_phy_conn(temp_usb_phy, 0);
	exynos_usbdrd_ldo_manual_control(0);

	/* USB host initialization. */
	ret = dwc3_exynos_host_init(exynos);
	if (ret) {
		pr_err("USB host pre-initialization fail!\n");
		goto populate_err;
	}

	ret = xhci_exynos_audio_alloc(dev);
	if (ret < 0)
		dev_err(dev, "xhci_exynos_audio_alloc failed\n");

	dev_info(dev, "Configuration exynos OTG\n");
	dwc3_exynos_otg_init(exynos->dwc, exynos);

	dwc3_otg_start(exynos->dwc, exynos);

	otg_set_peripheral(&exynos->dotg->otg, exynos->dwc->gadget);

#if IS_ENABLED(CONFIG_USB_TYPEC_MANAGER_NOTIFIER)
	typec_manager_dwc3_gadget_ops.driver_data = exynos->dwc;
	probe_typec_manager_gadget_ops(&typec_manager_dwc3_gadget_ops);
#endif
	INIT_WORK(&exynos->int_kprobe_work, dwc3_init_kprobe_work);
	schedule_work(&exynos->int_kprobe_work);
	return 0;

populate_err:
	platform_device_unregister(exynos->usb2_phy);
	platform_device_unregister(exynos->usb3_phy);
vdd33_err:
	dwc3_exynos_clk_disable(exynos);
	dwc3_exynos_clk_unprepare(exynos);
	exynos_update_ip_idle_status(usb_idle_ip_index, 1);
	pm_runtime_disable(&pdev->dev);
	pr_info("%s err = %d\n", __func__, ret);

	return ret;
}

static int dwc3_exynos_remove(struct platform_device *pdev)
{
	struct dwc3_exynos	*exynos = platform_get_drvdata(pdev);

	pr_info("%s\n", __func__);

	dwc3_kretprobe_exit();
	pm_runtime_get_sync(&pdev->dev);

	pm_runtime_put_sync(&pdev->dev);
	pm_runtime_allow(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	device_for_each_child(&pdev->dev, NULL, dwc3_exynos_remove_child);
	platform_device_unregister(exynos->usb2_phy);
	platform_device_unregister(exynos->usb3_phy);
	dwc3_exynos_kretprobe_exit();

	pm_runtime_disable(&pdev->dev);
	if (!pm_runtime_status_suspended(&pdev->dev)) {
		dwc3_exynos_clk_disable(exynos);
		pm_runtime_set_suspended(&pdev->dev);
	}

	dwc3_exynos_clk_unprepare(exynos);

	return 0;
}

#ifdef CONFIG_PM
static int dwc3_exynos_runtime_suspend(struct device *dev)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);
	struct dwc3 *dwc;

	dev_info(dev, "%s\n", __func__);

	if (!exynos)
		return 0;

	dwc = exynos->dwc;
	if (pm_runtime_suspended(dev)) {
		dev_info(dev, "%s, already suspended\n", __func__);
		return 0;
	}

	dwc3_exynos_clk_disable(exynos);

	/* inform what USB state is idle to IDLE_IP */
	exynos_update_ip_idle_status(usb_idle_ip_index, 1);

	return 0;
}

static int dwc3_exynos_runtime_resume(struct device *dev)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);
	int ret = 0;

	dev_info(dev, "%s\n", __func__);

	if (!exynos)
		return 0;

	if (pm_runtime_active(dev)) {
		dev_info(dev, "%s, already active\n", __func__);
		return 0;
	}

	exynos_update_ip_idle_status(usb_idle_ip_index, 0);

	ret = dwc3_exynos_clk_enable(exynos);
	if (ret) {
		dev_err(dev, "%s: clk_enable failed\n", __func__);
		return ret;
	}

	dwc3_exynos_set_sclk_clock(exynos->dev);

	pm_runtime_mark_last_busy(dev);

	return 0;
}

static const struct dev_pm_ops dwc3_exynos_dev_pm_ops = {
	SET_RUNTIME_PM_OPS(dwc3_exynos_runtime_suspend,
			dwc3_exynos_runtime_resume, NULL)
};

#define DEV_PM_OPS	(&dwc3_exynos_dev_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif /* CONFIG_PM */

static struct platform_driver dwc3_exynos_driver = {
	.probe		= dwc3_exynos_probe,
	.remove		= dwc3_exynos_remove,
	.driver		= {
		.name	= "exynos-dwc3",
		.of_match_table = exynos_dwc3_match,
		.pm	= DEV_PM_OPS,
	},
};

module_platform_driver(dwc3_exynos_driver);

MODULE_SOFTDEP("pre:phy-exynos-usbdrd-super");
MODULE_AUTHOR("Anton Tikhomirov <av.tikhomirov@samsung.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DesignWare USB3 EXYNOS Glue Layer");
