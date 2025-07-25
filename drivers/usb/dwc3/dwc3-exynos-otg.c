// SPDX-License-Identifier: GPL-2.0
/**
 * dwc3-exynos-otg.c - DesignWare Exynos USB3 DRD Controller OTG
 *
 * Copyright (c) 2012, Code Aurora Forum. All rights reserved.
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Authors: Ido Shayevitz <idos@codeaurora.org>
 *	    Anton Tikhomirov <av.tikhomirov@samsung.com>
 *	    Minho Lee <minho55.lee@samsung.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2  of
 * the License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/pm_runtime.h>
#include <linux/workqueue.h>
#include <linux/suspend.h>
#if defined(CONFIG_OTG_DEFAULT)
#include <linux/usb/typec.h>
#endif

#include "core.h"
#include "core-exynos.h"
#include "exynos-otg.h"
#include "io.h"
#ifdef CONFIG_OF
#include <linux/of_device.h>
#endif
#include "../../base/base.h"
#if defined(CONFIG_OTG_CDP_SUPPORT)
#include "../notify_lsi/sec_battery_common.h"
#endif
#if IS_ENABLED(CONFIG_USB_EXYNOS_TPMON_MODULE)
#include "exynos_usb_tpmon.h"
#endif
#include <linux/usb/composite.h>
#include <linux/reboot.h>
#include "dwc3-exynos.h"

#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
#include <linux/usb/f_ss_mon_gadget.h>
#endif
#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
#include <linux/usb_notify.h>
#endif

#define LINK_DEBUG_L		(0x0C)
#define LINK_DEBUG_H		(0x10)
#define BUS_ACTIVITY_CHECK	(0x3F << 16)
#define READ_TRANS_OFFSET	10

extern int otg_connection;
extern int is_otg_only;

struct dwc3_exynos *g_dwc3_exynos;

extern bool g_vbus_active;

/* -------------------------------------------------------------------------- */
#if defined(CONFIG_OTG_DEFAULT)
struct intf_typec {
	/* struct mutex lock; */ /* device lock */
	struct device *dev;
	struct typec_port *port;
	struct typec_capability cap;
	struct typec_partner *partner;
};
#endif

static int usb_reboot_noti(struct notifier_block *nb, unsigned long event, void *buf);
static struct notifier_block usb_reboot_notifier = {
	.notifier_call = usb_reboot_noti,
};

static int dwc3_otg_statemachine(struct otg_fsm *fsm)
{
	struct usb_otg *otg = fsm->otg;
	struct dwc3_otg	*dotg = container_of(otg, struct dwc3_otg, otg);
	struct dwc3_exynos *exynos = dotg->exynos;
	enum usb_otg_state prev_state = otg->state;
	int ret = 0;

	pr_info("%s otg->state: %d fsm->b_sess_vld %d\n", __func__,
			otg->state, fsm->b_sess_vld);
	if (dotg->fsm_reset) {
		if (otg->state == OTG_STATE_A_HOST) {
			otg_drv_vbus(fsm, 0);
			otg_start_host(fsm, 0);
		} else if (otg->state == OTG_STATE_B_PERIPHERAL) {
			otg_start_gadget(fsm, 0);
		}

		otg->state = OTG_STATE_UNDEFINED;
		goto exit;
	}

	switch (otg->state) {
	case OTG_STATE_UNDEFINED:
		if (fsm->id)
			otg->state = OTG_STATE_B_IDLE;
		else
			otg->state = OTG_STATE_A_IDLE;
		break;
	case OTG_STATE_B_IDLE:
		if (!fsm->id) {
			otg->state = OTG_STATE_A_IDLE;
		} else if (fsm->b_sess_vld) {
			exynos->retry_cnt = 0;
			ret = otg_start_gadget(fsm, 1);
			if (!ret)
				otg->state = OTG_STATE_B_PERIPHERAL;
			else
				pr_err("OTG SM: cannot start gadget\n");
		}
		break;
	case OTG_STATE_B_PERIPHERAL:
		if (!fsm->id || !fsm->b_sess_vld) {
			exynos->retry_cnt = REMOVED_RETRY_CNT;
			ret = otg_start_gadget(fsm, 0);
			if (!ret)
				otg->state = OTG_STATE_B_IDLE;
			else
				pr_err("OTG SM: cannot stop gadget\n");
		}
		break;
	case OTG_STATE_A_IDLE:
		if (fsm->id) {
			otg->state = OTG_STATE_B_IDLE;
		} else {
			ret = otg_start_host(fsm, 1);
			if (!ret) {
				otg_drv_vbus(fsm, 1);
				otg->state = OTG_STATE_A_HOST;
			} else {
				pr_err("OTG SM: cannot start host\n");
			}
		}
		break;
	case OTG_STATE_A_HOST:
		if (fsm->id) {
			otg_drv_vbus(fsm, 0);
			ret = otg_start_host(fsm, 0);
			if (!ret)
				otg->state = OTG_STATE_A_IDLE;
			else
				pr_err("OTG SM: cannot stop host\n");
		}
		break;
	default:
		pr_err("OTG SM: invalid state\n");
	}

exit:
	if (!ret)
		ret = (otg->state != prev_state);

	pr_debug("OTG SM: %s => %s\n", usb_otg_state_string(prev_state),
		(ret > 0) ? usb_otg_state_string(otg->state) : "(no change)");

	return ret;
}

/* -------------------------------------------------------------------------- */

static struct dwc3_ext_otg_ops *dwc3_otg_exynos_rsw_probe(struct dwc3 *dwc)
{
	struct dwc3_ext_otg_ops *ops;
	bool ext_otg;

	ext_otg = dwc3_exynos_rsw_available(dwc->dev->parent);
	if (!ext_otg) {
		dev_err(dwc->dev, "failed to get ext_otg\n");
		return NULL;
	}

	/* Allocate and init otg instance */
	ops = devm_kzalloc(dwc->dev, sizeof(struct dwc3_ext_otg_ops),
			GFP_KERNEL);
	if (!ops) {
		 dev_err(dwc->dev, "unable to allocate dwc3_ext_otg_ops\n");
		 return NULL;
	}

	ops->setup = dwc3_exynos_rsw_setup;
	ops->start = dwc3_exynos_rsw_start;

	dev_err(dwc->dev, "%s done\n", __func__);

	return ops;
}

static void dwc3_otg_drv_vbus(struct otg_fsm *fsm, int on)
{
	struct dwc3_otg	*dotg = container_of(fsm, struct dwc3_otg, fsm);
	int ret;

	if (IS_ERR(dotg->vbus_reg)) {
		dev_err(dotg->dwc->dev, "vbus regulator is not available\n");
		return;
	}

	if (on)
		ret = regulator_enable(dotg->vbus_reg);
	else
		ret = regulator_disable(dotg->vbus_reg);

	if (ret)
		dev_err(dotg->dwc->dev, "failed to turn Vbus %s\n",
						on ? "on" : "off");
}

static void dwc3_bus_control(struct dwc3_exynos *dwc_exynos, int onoff)
{
	u32 reg;

	if (pm_runtime_suspended(dwc_exynos->dev)) {
		pr_info("%s: AP Suspend state, return!\n", __func__);
		return;
	}

	if (onoff == 1) {
		pr_info("Set MO1/BL1\n");
		/* MO1/BL1 */
		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG0);
		reg &= ~(DWC3_GSBUSCFG1_INCR_MASK);
		reg |= DWC3_GSBUSCFG0_INCRBRSTEN;
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_GSBUSCFG0, reg);

		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG1);
		reg &= ~(DWC3_GSBUSCFG1_BREQLIMIT_MASK);
		reg |= (DWC3_GSBUSCFG1_BREQLIMIT(0x0));
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_GSBUSCFG1, reg);
	} else {
		pr_info("Set MO4/BL16\n");
		/* MO4/BL16 */
		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG0);
		reg &= ~(DWC3_GSBUSCFG1_INCR_MASK);
		reg |= (DWC3_GSBUSCFG0_INCRBRSTEN | DWC3_GSBUSCFG0_INCR4BRSTEN |
			DWC3_GSBUSCFG0_INCR8BRSTEN | DWC3_GSBUSCFG0_INCR16BRSTEN);
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_GSBUSCFG0, reg);

		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG1);
		reg &= ~(DWC3_GSBUSCFG1_BREQLIMIT_MASK);
		reg |= (DWC3_GSBUSCFG1_BREQLIMIT(0xF));
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_GSBUSCFG1, reg);
	}

	pr_info("DWC3_GSBUSCFG0 0x %08x\n", dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG0));
	pr_info("DWC3_GSBUSCFG1 0x %08x\n", dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_GSBUSCFG1));
}

void dwc3_otg_pm_ctrl(struct dwc3_exynos *dwc_exynos, int onoff)
{
	u32 reg;

	if (pm_runtime_suspended(dwc_exynos->dev)) {
		pr_info("%s: AP Suspend state, return!\n", __func__);
		return;
	}

	if (onoff == 0) {
		pr_info("Disable USB U1/U2 for performance.\n");
		/* Disable U1U2 */
		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_DCTL);
		reg &= ~(DWC3_DCTL_INITU1ENA | DWC3_DCTL_ACCEPTU1ENA |
				DWC3_DCTL_INITU2ENA | DWC3_DCTL_ACCEPTU2ENA);
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_DCTL, reg);
	} else {
		/* Enable U1U2 */
		reg = dwc3_exynos_readl(dwc_exynos->dwc->regs, DWC3_DCTL);
		reg |= (DWC3_DCTL_INITU1ENA | DWC3_DCTL_ACCEPTU1ENA |
				DWC3_DCTL_INITU2ENA | DWC3_DCTL_ACCEPTU2ENA);
		dwc3_exynos_writel(dwc_exynos->dwc->regs, DWC3_DCTL, reg);
	}
}

static void usb3_phy_control(struct dwc3_otg *dotg, int on)
{
	struct dwc3	*dwc = dotg->dwc;
	struct device	*dev = dwc->dev;

	dev_info(dev, "%s, USB3.0 PHY %s\n", __func__, on ? "on" : "off");

	if (on) {
		dwc3_core_susphy_set(dwc, 0);
#ifdef CONFIG_EXYNOS_USBDRD_PHY30
		exynos_usbdrd_pipe3_enable(dwc->usb3_generic_phy);
#endif
		dwc3_core_susphy_set(dwc, 1);
	} else {
		dwc3_core_susphy_set(dwc, 0);
#ifdef CONFIG_EXYNOS_USBDRD_PHY30
		exynos_usbdrd_pipe3_disable(dwc->usb3_generic_phy);
#endif
		dwc3_core_susphy_set(dwc, 1);
	}
}

int port_usb3 = 0;

void usb_power_notify_control(int owner, int on)
{
	struct dwc3_otg	*dotg;
	struct dwc3	*dwc;
	struct device	*dev;
	u8 owner_bit = 0;

	if (g_dwc3_exynos == NULL) {
		pr_err("%s g_dwc3_exynos is NULL\n", __func__);
		return;
	}

	dwc = g_dwc3_exynos->dwc;

	if (dwc && g_dwc3_exynos->dotg && dwc->dev) {
		dotg = g_dwc3_exynos->dotg;
		dev = dwc->dev;
	} else {
		pr_err("%s dwc or dotg or dev NULL\n", __func__);
		return;
	}

	if (dwc->maximum_speed == USB_SPEED_HIGH) {
		dev_info(dev, "%s, Ignore USB3.0 phy control.\n", __func__);
		return;
	}

	dev_info(dev, "%s, combo phy = %d, owner= %d, on=%d\n",
		__func__, dotg->combo_phy_control, owner, on);

	mutex_lock(&dotg->lock);

	if (dotg->pm_qos_hsi0_val) {
		dev_info(dev, "pm_qos set hsi0 value = %d\n",
				dotg->pm_qos_hsi0_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
		exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req,
				dotg->pm_qos_hsi0_val);
#endif
	}

	if (dotg->pm_qos_int_val) {
		dev_info(dev, "pm_qos set int value = %d\n",
				dotg->pm_qos_int_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
		exynos_pm_qos_update_request(&dotg->pm_qos_int_req,
				dotg->pm_qos_int_val);
		dev_info(dev, "Cancel pm_qos hsi0 clear setting\n");
		cancel_delayed_work_sync(&g_dwc3_exynos->usb_qos_lock_delayed_work);
		dev_info(dev, "pm_qos hsi0 int min lock set 3000ms\n");
		schedule_delayed_work(&g_dwc3_exynos->usb_qos_lock_delayed_work,
				msecs_to_jiffies(3000));
#endif
	}

	owner_bit = (1 << owner);

	port_usb3 = on;

	if (on) {
		if (dotg->combo_phy_control == 0) {
#if 0
			if (dotg->pm_qos_hsi0_val) {
				dev_info(dev, "pm_qos set hsi0 value = %d\n",
						dotg->pm_qos_hsi0_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
				exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req,
						dotg->pm_qos_hsi0_val);
#endif
			}
#endif
			usb3_phy_control(dotg, 1);
		}
		dotg->combo_phy_control |= owner_bit;
	} else {
		dotg->combo_phy_control &= ~(owner_bit);
		if (dotg->combo_phy_control == 0) {
#if 0
			if (dotg->pm_qos_hsi0_val) {
				dev_info(dev, "Reset pm_qos hsi0 setting\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
				exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req, 0);
#endif
			}
#endif
			usb3_phy_control(dotg, 0);
		}
	}
	mutex_unlock(&dotg->lock);

	return;
}
EXPORT_SYMBOL(usb_power_notify_control);

void dwc3_otg_phy_tune(struct otg_fsm *fsm)
{
	struct usb_otg	*otg = fsm->otg;
	struct dwc3_otg	*dotg = container_of(otg, struct dwc3_otg, otg);
	struct dwc3	*dwc = dotg->dwc;

	exynos_usbdrd_phy_tune(dwc->usb2_generic_phy,
						dotg->otg.state);
#ifdef CONFIG_EXYNOS_USBDRD_PHY30
	exynos_usbdrd_phy_tune(dwc->usb3_generic_phy,
						dotg->otg.state);
#endif
}
EXPORT_SYMBOL_GPL(dwc3_otg_phy_tune);

static int dwc3_otg_start_host(struct otg_fsm *fsm, int on)
{
	struct usb_otg	*otg = fsm->otg;
	struct dwc3_otg	*dotg = container_of(otg, struct dwc3_otg, otg);
	struct dwc3	*dwc = dotg->dwc;
	struct device	*dev = dotg->dwc->dev;
	struct dwc3_exynos *exynos = dotg->exynos;
	struct device	*exynos_dev = exynos->dev;
	int ret = 0;
	int rpm_ret = 0;
	int ret1 = -1;
	int wait_counter = 0;
	int time = 0;

#if defined(CONFIG_OTG_CDP_SUPPORT)
	union power_supply_propval val;
#endif

	/* [W/A] Some device need VBUS up time */
	if (exynos->lazy_vbus_up)
		msleep(100);

	dev_info(dev, "Turn %s host\n", on ? "on" : "off");
	__pm_stay_awake(dotg->wakelock);

	if (on) {
		otg_connection = 1;
		if (dotg->pm_qos_hsi0_val) {
			dev_info(dev, "pm_qos set value = %d\n", dotg->pm_qos_hsi0_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req,
							dotg->pm_qos_hsi0_val);
#endif
		}

		if (dotg->pm_qos_int_val) {
			dev_info(dev, "pm_qos set value = %d\n", dotg->pm_qos_int_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_int_req,
							dotg->pm_qos_int_val);
#endif
		}
		/* update phy tune value before phy_enable */
		dwc3_otg_phy_tune(fsm);

#if defined(CONFIG_OTG_CDP_SUPPORT)
		/* vbus control test */
		pr_info("%s : psy_do_property vbus enable\n", __func__);
		val.intval = 1;
		psy_do_property("otg", set, POWER_SUPPLY_PROP_ONLINE, val);
		//-------------------//
		exynos_usbdrd_cdp_set(dwc->usb2_generic_phy, 1);
#endif
		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));
		wait_counter = 0;
		while (!pm_runtime_suspended(exynos->dev)) {
			msleep(20);
			pr_info("%s: sleep 20ms to wait for suspend, %d!\n", __func__, wait_counter++);
			if (wait_counter >= MAX_WAIT_SUSPEND_CNT) {
				pr_info("%s: Can't wait for suspend\n", __func__);
				break;
			}
		}
		dotg->dwc3_suspended = USB_NORMAL;
		pr_info("%s %d\n", __func__, __LINE__);
		rpm_ret = pm_runtime_get_sync(exynos_dev);
		if (rpm_ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize exynos: %d\n",
					__func__, rpm_ret);
			ret = -ENODEV;
			pm_runtime_set_suspended(exynos_dev);
			goto err1;
		}
		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
		pr_info("%s %d\n", __func__, __LINE__);
		rpm_ret = pm_runtime_get_sync(dev);
		if (rpm_ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize core: %d\n",
					__func__, rpm_ret);
			ret = -ENODEV;
			pm_runtime_set_suspended(dev);
			goto err2;
		}

		dwc3_exynos_core_init(dwc, exynos);
		dwc3_bus_control(exynos, 1);

		dwc3_core_susphy_set(dwc, 1);

		pr_info("%s: usb_role_switch_set_role = DWC3_GCTL_PRTCAP_HOST\n", __func__);
		usb_role_switch_set_role(dwc->role_sw, DWC3_GCTL_PRTCAP_HOST);

		schedule_delayed_work(&g_dwc3_exynos->usb_qos_lock_delayed_work,
				msecs_to_jiffies(3000));

#if IS_ENABLED(CONFIG_IF_CB_MANAGER)
		usbpd_set_host_on(dotg->man, on);
#endif
	} else {
#if IS_ENABLED(CONFIG_IF_CB_MANAGER)
		usbpd_set_host_on(dotg->man, on);
#endif
		otg_connection = 0;

		if (dotg->dwc3_suspended == USB_SUSPEND_PREPARE) {
			pr_info("%s: wait resume completion\n", __func__);
			ret1 = wait_for_completion_timeout(&dotg->resume_cmpl,
							msecs_to_jiffies(5000));
		}
		pr_info("%s: usb_role_switch_set_role = DWC3_GCTL_PRTCAP_DEVICE\n", __func__);
		usb_role_switch_set_role(dwc->role_sw, DWC3_GCTL_PRTCAP_DEVICE);

		while (dwc->current_dr_role != DWC3_GCTL_PRTCAP_DEVICE) {
			msleep(20);
			time += 20;
			if (time > 500) {
				pr_info("%s set_mode timeout\n", __func__);
				break;
			}
		}
		pr_info("%s set_mode time = %d\n", __func__, time);

		mutex_lock(&dwc->mutex);
		if (dwc->current_dr_role != DWC3_GCTL_PRTCAP_DEVICE)
			pr_info("%s set_mode error, role = %d\n",
				__func__, dwc->current_dr_role);
		mutex_unlock(&dwc->mutex);
err2:
		pm_runtime_put_sync_suspend(dev);
		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
err1:
		pm_runtime_put_sync_suspend(exynos_dev);
		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));

		otg_connection = 0;

#if defined(CONFIG_OTG_CDP_SUPPORT)
		pr_info("%s : psy_do_property vbus disable\n", __func__);
		val.intval = 0;
		psy_do_property("otg", set, POWER_SUPPLY_PROP_ONLINE, val);
		exynos_usbdrd_cdp_set(dwc->usb2_generic_phy, 0);
#endif

		if (dotg->pm_qos_hsi0_val) {
			dev_info(dev, "hsi0 pm_qos reset\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req, 0);
#endif
		}
		if (dotg->pm_qos_int_val) {
			dev_info(dev, "int pm_qos reset\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_int_req, 0);
#endif
		}
		cancel_delayed_work_sync(&g_dwc3_exynos->usb_qos_lock_delayed_work);
	}
	__pm_relax(dotg->wakelock);
	return ret;
}


u8 dwc3_otg_get_link_state(struct dwc3 *dwc)
{
	u32			reg;
	u8			link_state;

	reg = dwc3_exynos_readl(dwc->regs, DWC3_DSTS);
	link_state = DWC3_DSTS_USBLNKST(reg);

	return link_state;
}
EXPORT_SYMBOL_GPL(dwc3_otg_get_link_state);

int exynos_usb_recovery_reconn(void);

static void retry_configuration(struct timer_list *t)
{
	struct dwc3_exynos *exynos = from_timer(exynos, t, usb_connect_timer);
	struct usb_gadget *gadget = exynos->dwc->gadget;
	struct usb_composite_dev *cdev = get_gadget_data(gadget);
	u8 state;

	pr_info("%s: +++\n", __func__);

	if (exynos->retry_disable == 1) {
		pr_err("Stop retry configuration(retry disabled)\n");
		return;
	}

	if (cdev == NULL || exynos->retry_cnt == REMOVED_RETRY_CNT) {
		pr_err("Stop retry configuration(cdev is NULL) or Removed\n");
		if (cdev == NULL)
			mod_timer(&exynos->usb_connect_timer,
					jiffies + CHG_CONNECTED_DELAY_TIME);
		return;
	}

	state = dwc3_otg_get_link_state(exynos->dwc);
	if (state == DWC3_LINK_STATE_CMPLY || state == DWC3_LINK_STATE_LPBK ||
		state == DWC3_LINK_STATE_U3) {
		exynos->retry_cnt = 0;
		pr_info("%s: Don't retry in compliance mode\n", __func__);
		return;
	}

	if (!exynos->dwc->gadget_driver) {
		pr_info("%s: Postpone retry configuration(gadget_driver is NULL) !!\n", __func__);
		mod_timer(&exynos->usb_connect_timer,
				jiffies + CHG_CONNECTED_DELAY_TIME);
		return;
	}

	if (!cdev->config || exynos->retry_disable == 2) {
		if (exynos->retry_cnt >= MAX_RETRY_CNT) {
			pr_err("%s: Re-try 5 times, But usb enumeration fail\n",
					__func__);
			exynos->connection_fail = CONNECTION_FAIL_SET;
			return;
		}

		pr_info("%s: retry USB enumeration, retry count : %d\n",
				__func__, exynos->retry_cnt);

		exynos_usb_recovery_reconn();

		exynos->retry_cnt += 1;
		if (exynos->retry_disable == 2) {
			pr_info("%s: clear retry_disable\n", __func__);
			exynos->retry_disable = 0;
		}
	} else {
		exynos->retry_cnt = 0;
		exynos->connection_fail = CONNECTION_FAIL_CLEAR;
		pr_info("%s: already configuration done!!\n", __func__);
		return;
	}

	pr_info("%s: ---\n", __func__);
}

static int dwc3_check_extra_work(struct dwc3 *dwc)
{
	struct usb_gadget *gadget = dwc->gadget;
	struct usb_composite_dev *cdev;
	struct usb_function *f;
	struct device *dev = dwc->dev;
	int i, ret = 0;

	if (gadget == NULL) {
		pr_err("%s : Can't check extra work. gadget is NULL\n", __func__);
		return 0;
	}

	cdev = get_gadget_data(gadget);

	if (cdev == NULL) {
		pr_err("%s : Can't check extra work. cdev is NULL\n", __func__);
		return 0;
	}

	for (i = 0; i < MAX_CONFIG_INTERFACES; i++) {
		if (cdev->config == NULL)
			break;

		f = cdev->config->interface[i];
		if (f == NULL)
			break;

		/* Exynos specific function need extra delay */
		if (strncmp(f->name, "dm", sizeof("dm")) == 0) {
			dev_info(dev, "found dm function...\n");
			/* f->disable(f); */
			ret = 1;
		} else if (strncmp(f->name, "acm", sizeof("acm")) == 0) {
			dev_info(dev, "found acm function...\n");
			/* f->disable(f); */
			ret = 1;
		}
	}

	return ret;
}

static int dwc3_otg_start_gadget(struct otg_fsm *fsm, int on)
{
	struct usb_otg	*otg = fsm->otg;
	struct dwc3_otg	*dotg = container_of(otg, struct dwc3_otg, otg);
	struct dwc3	*dwc = dotg->dwc;
	struct dwc3_exynos *exynos = dotg->exynos;
	struct device	*dev = dotg->dwc->dev;
	struct device	*exynos_dev = exynos->dev;
	int ret = 0;
	int wait_counter = 0, extra_delay = 0;
	u32 evt_count, evt_buf_cnt;

	if (!otg->gadget) {
		dev_err(dev, "%s does not have any gadget\n", __func__);
		return -EINVAL;
	}

	dev_info(dev, "Turn %s gadget\n",
			on ? "on" : "off");

	dwc->softconnect = on;

#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	vbus_session_notify(dwc->gadget, on, EAGAIN);
#endif
	if (on) {
		__pm_stay_awake(dotg->wakelock);

		/* update phy tune value before phy_enable */
		dwc3_otg_phy_tune(fsm);

		if (dotg->pm_qos_hsi0_val) {
			dev_info(dev, "pm_qos set hsi0 value = %d\n", dotg->pm_qos_hsi0_val);
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req,
							dotg->pm_qos_hsi0_val);
#endif
		}

		exynos->vbus_state = true;
		dwc->ev_buf->flags |= BIT(20);
		pr_info("%s: set BIT(20) event buffer flags\n", __func__);
		while (dwc->gadget_driver == NULL) {
			wait_counter++;
			usleep_range(100, 200);

			if (wait_counter > 500) {
				pr_err("Can't wait gadget start!\n");
				break;
			}
		}

		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));
		wait_counter = 0;
		while (!pm_runtime_suspended(exynos->dev)) {
			msleep(20);
			pr_info("%s: sleep 20ms to wait for suspend, %d!\n", __func__, wait_counter++);
			if (wait_counter >= MAX_WAIT_SUSPEND_CNT) {
				pr_info("%s: Can't wait for suspend\n", __func__);
				break;
			}
		}
		dotg->dwc3_suspended = USB_NORMAL;

		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
		pr_info("%s %d\n", __func__, __LINE__);
		ret = pm_runtime_get_sync(exynos_dev);
		if (ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize exynos: %d\n",
					__func__, ret);
			pm_runtime_set_suspended(exynos_dev);
		}
		pr_info("%s %d\n", __func__, __LINE__);
		ret = pm_runtime_get_sync(dev);
		if (ret < 0) {
			dev_err(dwc->dev, "%s: failed to initialize core: %d\n",
					__func__, ret);
			pm_runtime_set_suspended(dev);
		}

		dwc3_exynos_core_init(dwc, exynos);

#if IS_ENABLED(CONFIG_USB_EXYNOS_TPMON_MODULE)
		usb_tpmon_open();
#endif
		dwc3_otg_pm_ctrl(exynos, 0);
		dwc3_bus_control(exynos, 0);
		pr_info("%s: start check usb configuration timer\n", __func__);
		timer_setup(&exynos->usb_connect_timer, retry_configuration, 0);
		mod_timer(&exynos->usb_connect_timer,
				jiffies + CHG_CONNECTED_DELAY_TIME);
	} else {
		exynos->vbus_state = false;
		dwc->ev_buf->flags &= ~BIT(20);
		pr_info("%s: clear BIT(20) event buffer flags\n", __func__);
#if IS_ENABLED(CONFIG_USB_EXYNOS_TPMON_MODULE)
		usb_tpmon_close();
#endif
		del_timer_sync(&exynos->usb_connect_timer);

		evt_buf_cnt = dwc->ev_buf->count;

		/* Wait until gadget stop */
		wait_counter = 0;
		evt_count = dwc3_exynos_readl(dwc->regs, DWC3_GEVNTCOUNT(0));
		evt_count &= DWC3_GEVNTCOUNT_MASK;
		while (evt_count || evt_buf_cnt) {
			wait_counter++;
			mdelay(20);

			if (wait_counter > 20) {
				pr_err("Can't wait dwc disconnect!\n");
				break;
			}
			evt_count = dwc3_exynos_readl(dwc->regs, DWC3_GEVNTCOUNT(0));
			evt_count &= DWC3_GEVNTCOUNT_MASK;
			evt_buf_cnt = dwc->ev_buf->count;
			dev_dbg(dev, "%s: evt = %d, evt_buf cnt = %d\n",
				__func__, evt_count, evt_buf_cnt);
		}
		dev_info(dev, "%s, evt compl wait cnt = %d\n",
			 __func__, wait_counter);

		/*
		 * we can extra work corresponding each functions by
		 * the following function.
		 */
		dwc3_exynos_gadget_disconnect_proc(dwc);

		if (dwc->ep0state != EP0_SETUP_PHASE ||
				atomic_read(&dev->power.usage_count) > 1) {
			pr_info("usb: %s: dwc->ep0state=%d, dep->flags=%d\n",
				__func__, dwc->ep0state, dwc->eps[0]->flags);
			usb_ep_set_halt(&(dwc->eps[0]->endpoint));
		}

		extra_delay = dwc3_check_extra_work(dwc);
		if (extra_delay)
			mdelay(100);

		pm_runtime_put_sync_suspend(dev);
		pr_info("core RPM Usage Count: %d\n", atomic_read(&dev->power.usage_count));
		pr_info("core RPM runtime_status: %d\n", dev->power.runtime_status);
		pm_runtime_put_sync_suspend(exynos_dev);
		pr_info("exynos RPM Usage Count: %d\n", atomic_read(&exynos->dev->power.usage_count));
		if (dotg->pm_qos_hsi0_val) {
			dev_info(dev, "pm_qos hsi0 reset\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req, 0);
#endif
		}

		__pm_relax(dotg->wakelock);
	}

	return 0;
}

static struct otg_fsm_ops dwc3_otg_fsm_ops = {
	.drv_vbus	= dwc3_otg_drv_vbus,
	.start_host	= dwc3_otg_start_host,
	.start_gadget	= dwc3_otg_start_gadget,
};

/* -------------------------------------------------------------------------- */

void dwc3_otg_run_sm(struct otg_fsm *fsm)
{
	struct dwc3_otg	*dotg = container_of(fsm, struct dwc3_otg, fsm);
	int state_changed;
	int i;

	/* Prevent running SM on early system resume */
	if (!dotg->ready)
		return;

	for (i = 0; i < 100; i++) {
		if (dotg->dwc3_suspended == USB_SUSPEND_PREPARE) {
			pr_info("%s Waiting system resume!!\n", __func__);
			usleep_range(5000, 5100);
		} else {
			pr_info("%s System resume Done!!\n", __func__);
			break;
		}
	}

	mutex_lock(&fsm->lock);

	do {
		state_changed = dwc3_otg_statemachine(fsm);
	} while (state_changed > 0);

	mutex_unlock(&fsm->lock);
}
EXPORT_SYMBOL_GPL(dwc3_otg_run_sm);

/* Bind/Unbind the peripheral controller driver */
static int dwc3_otg_set_peripheral(struct usb_otg *otg,
				struct usb_gadget *gadget)
{
	struct dwc3_otg	*dotg = container_of(otg, struct dwc3_otg, otg);
	struct otg_fsm	*fsm = &dotg->fsm;
	struct device	*dev = dotg->dwc->dev;

	if (gadget) {
		dev_info(dev, "Binding gadget %s\n", gadget->name);

		otg->gadget = gadget;
	} else {
		dev_info(dev, "Unbinding gadget\n");

		mutex_lock(&fsm->lock);

		if (otg->state == OTG_STATE_B_PERIPHERAL) {
			/* Reset OTG Statemachine */
			dotg->fsm_reset = 1;
			dwc3_otg_statemachine(fsm);
			dotg->fsm_reset = 0;
		}
		otg->gadget = NULL;

		mutex_unlock(&fsm->lock);

		dwc3_otg_run_sm(fsm);
	}

	return 0;
}
/* -------------------------------------------------------------------------- */

static ssize_t
dwc3_otg_show_state(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct usb_otg		*otg = &exynos->dotg->otg;

	return snprintf(buf, PAGE_SIZE, "%s\n",
			usb_otg_state_string(otg->state));
}

static DEVICE_ATTR(state, S_IRUSR | S_IRGRP,
	dwc3_otg_show_state, NULL);

static ssize_t
dwc3_otg_show_b_sess(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct otg_fsm	*fsm = &exynos->dotg->fsm;

	return snprintf(buf, PAGE_SIZE, "%d\n", fsm->b_sess_vld);
}

static ssize_t
dwc3_otg_store_b_sess(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct otg_fsm	*fsm = &exynos->dotg->fsm;
	int		b_sess_vld;

	mutex_lock(&fsm->lock);
	if (sscanf(buf, "%d", &b_sess_vld) != 1) {
		mutex_unlock(&fsm->lock);
		return -EINVAL;
	}

	if (is_blocked(get_otg_notify(), NOTIFY_BLOCK_TYPE_CLIENT)) {
		mutex_unlock(&fsm->lock);
		return NOTIFY_OK;
	}

	fsm->b_sess_vld = !!b_sess_vld;
	mutex_unlock(&fsm->lock);

	dwc3_otg_run_sm(fsm);

	return n;
}

static DEVICE_ATTR(b_sess, S_IWUSR | S_IRUSR | S_IRGRP,
	dwc3_otg_show_b_sess, dwc3_otg_store_b_sess);

static ssize_t
dwc3_otg_show_id(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct otg_fsm	*fsm = &exynos->dotg->fsm;

	return snprintf(buf, PAGE_SIZE, "%d\n", fsm->id);
}

static ssize_t
dwc3_otg_store_id(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	struct otg_fsm	*fsm = &exynos->dotg->fsm;
	int id;

	if (sscanf(buf, "%d", &id) != 1)
		return -EINVAL;

	if (!exynos->usb_data_enabled)
		return NOTIFY_OK;

	if (is_blocked(get_otg_notify(), NOTIFY_BLOCK_TYPE_HOST))
		return NOTIFY_OK;

	fsm->id = !!id;

	dwc3_otg_run_sm(fsm);

	return n;
}

static DEVICE_ATTR(id, S_IWUSR | S_IRUSR | S_IRGRP,
	dwc3_otg_show_id, dwc3_otg_store_id);

static ssize_t
dwc3_otg_show_retry_disable(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", exynos->retry_disable);
}

static ssize_t
dwc3_otg_store_retry_disable(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);
	int		retry_disable;

	if (sscanf(buf, "%d", &retry_disable) != 1)
		return -EINVAL;

	exynos->retry_disable = retry_disable;

	return n;
}

static DEVICE_ATTR(retry_disable, S_IWUSR | S_IRUSR | S_IRGRP,
	dwc3_otg_show_retry_disable, dwc3_otg_store_retry_disable);

static ssize_t
dwc3_otg_show_usb_state(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int len = 0;

	len += snprintf(buf + len, PAGE_SIZE, "\t==== Print USB State ====\n");
	// Call USB SFR dump function here!

	return len;
}

static DEVICE_ATTR(usb_state, S_IWUSR | S_IRUSR | S_IRGRP,
	dwc3_otg_show_usb_state, NULL);

static ssize_t
dwc3_otg_show_usb_connection_fail(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos	*exynos = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", exynos->connection_fail);
}

static ssize_t
dwc3_otg_store_usb_connection_fail(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);
	int 	connection_fail;

	if (sscanf(buf, "%d", &connection_fail) != 1)
		return -EINVAL;

	pr_info("%s: connection_fail variable %d -> %d\n", __func__,
		exynos->connection_fail, connection_fail);
	exynos->connection_fail = connection_fail;

	return n;
}

static DEVICE_ATTR(usb_connection_fail, S_IWUSR | S_IRUSR | S_IRGRP,
	dwc3_otg_show_usb_connection_fail, dwc3_otg_store_usb_connection_fail);

static ssize_t usb_data_enabled_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%s\n", exynos->usb_data_enabled ? "enabled" : "disabled");
}

static ssize_t usb_data_enabled_store(struct device *dev, struct device_attribute *attr,
				      const char *buf, size_t n)
{
	struct dwc3_exynos *exynos = dev_get_drvdata(dev);
	struct otg_fsm	*fsm = &exynos->dotg->fsm;
	bool enabled = true;
#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
	unsigned long usb_notify;
	int usb_notify_state;
	static int prev_enabled = -1;
#endif

	if (kstrtobool(buf, &enabled))
		return -EINVAL;

#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
	if (is_blocked(get_otg_notify(), NOTIFY_BLOCK_TYPE_CLIENT))
		return NOTIFY_OK;
#endif

	exynos->usb_data_enabled = enabled;

	if ((enabled == 1) && (g_vbus_active == 1))
	{
		if (fsm->b_sess_vld != g_vbus_active) {
			mutex_lock(&fsm->lock);
			fsm->b_sess_vld = g_vbus_active;
			mutex_unlock(&fsm->lock);
			dwc3_otg_run_sm(fsm);
		}
	}

#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
	usb_notify = NOTIFY_EVENT_ALL_DISABLE;
	if (prev_enabled != enabled) {
		if (enabled)
			usb_notify_state = NOTIFY_EVENT_DISABLING;
		else
			usb_notify_state = NOTIFY_EVENT_ENABLING;

		store_usblog_notify(NOTIFY_EVENT,
			(void *)&usb_notify, (void *)&usb_notify_state);
		prev_enabled = enabled;
	}
#endif

	pr_info("%s Turn %s\n", __func__, enabled ? "on" : "off");
	return n;
}
static DEVICE_ATTR_RW(usb_data_enabled);

static struct attribute *dwc3_otg_attributes[] = {
	&dev_attr_id.attr,
	&dev_attr_b_sess.attr,
	&dev_attr_state.attr,
	&dev_attr_retry_disable.attr,
	&dev_attr_usb_state.attr,
	&dev_attr_usb_connection_fail.attr,
	&dev_attr_usb_data_enabled.attr,
	NULL
};

static const struct attribute_group dwc3_otg_attr_group = {
	.attrs = dwc3_otg_attributes,
};

/**
 * dwc3_otg_start
 * @dwc: pointer to our controller context structure
 */
int dwc3_otg_start(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	struct dwc3_otg	*dotg = exynos->dotg;
	struct otg_fsm	*fsm = &dotg->fsm;
	int		ret;

	if (dotg->ext_otg_ops) {
		ret = dwc3_ext_otg_start(dotg);
		if (ret) {
			dev_err(dwc->dev, "failed to start external OTG\n");
			return ret;
		}
	}

	dotg->ready = 1;

	dwc3_otg_run_sm(fsm);

	return 0;
}
/* -------------------------------------------------------------------------- */

extern u32 otg_is_connect(void);
struct work_struct recovery_reconn_work;

static void dwc3_recovery_reconnection(struct work_struct *w)
{
	struct dwc3_otg *dotg = g_dwc3_exynos->dotg;
	struct dwc3 *dwc = dotg->dwc;
	struct otg_fsm	*fsm = &dotg->fsm;
	int ret = 0;

	__pm_stay_awake(dotg->reconn_wakelock);
	/* Lock to avoid real cable insert/remove operation. */
	mutex_lock(&fsm->lock);

	if (otg_connection == 1) {
		pr_err("Recovery Host Reconnection\n");
		ret = dwc3_otg_start_host(fsm, 0);
		if (ret < 0) {
			pr_err("Cable was already disconnected!!\n");
			goto emeg_out;
		}
	} else {
		pr_err("Recovery Gadget Reconnection\n");
		if (g_dwc3_exynos->vbus_state == false) {
			pr_err("Cable was already disconnected!!\n");
			goto emeg_out;
		}
		usb_gadget_set_state(dwc->gadget, USB_STATE_NOTATTACHED);
		dwc3_otg_start_gadget(fsm, 0);
	}

	msleep(50);
	if (otg_connection == 1)
		dwc3_otg_start_host(fsm, 1);
	else
		dwc3_otg_start_gadget(fsm, 1);

emeg_out:
	mutex_unlock(&fsm->lock);
	__pm_relax(dotg->reconn_wakelock);
}

int exynos_usb_recovery_reconn(void)
{
	if (g_dwc3_exynos == NULL) {
		pr_err("WARNING : g_dwc3_exynos is NULL\n");
		return -ENODEV;
	}

	schedule_work(&recovery_reconn_work);

	return 0;
}
EXPORT_SYMBOL_GPL(exynos_usb_recovery_reconn);

static int dwc3_otg_pm_notifier(struct notifier_block *nb,
		unsigned long action, void *nb_data)
{
	struct dwc3_otg *dotg
		= container_of(nb, struct dwc3_otg, pm_nb);

	switch (action) {
	case PM_SUSPEND_PREPARE:
		pr_info("%s suspend prepare\n", __func__);
		dotg->dwc3_suspended = USB_SUSPEND_PREPARE;
		reinit_completion(&dotg->resume_cmpl);
		break;
	case PM_POST_SUSPEND:
		pr_info("%s post suspend\n", __func__);
		dotg->dwc3_suspended = USB_POST_SUSPEND;
		complete(&dotg->resume_cmpl);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

#if defined(CONFIG_OTG_DEFAULT)
static void typec_work_func(struct work_struct *work)
{
	struct dwc3_otg		*dotg = container_of(work, struct dwc3_otg,
							typec_work.work);
	struct dwc3		*dwc = dotg->dwc;
	struct intf_typec	*typec = dotg->typec;
	struct typec_partner_desc partner;

	pr_info("%s\n", __func__);

	typec->cap.type = TYPEC_PORT_DRP;
	typec->cap.revision = USB_TYPEC_REV_1_2;
	typec->cap.pd_revision = 0x312;
	typec->cap.prefer_role = TYPEC_NO_PREFERRED_ROLE;

	typec->port = typec_register_port(dwc->dev, &typec->cap);
	if (!typec->port) {
		dev_err(dwc->dev, "failed register port\n");
		return;
	}

	typec_set_data_role(typec->port, TYPEC_DEVICE);
	typec_set_pwr_role(typec->port, TYPEC_SINK);
	typec_set_pwr_opmode(typec->port, TYPEC_PWR_MODE_USB);

	memset(&partner, 0, sizeof(struct typec_partner_desc));

	typec->partner = typec_register_partner(typec->port, &partner);
	if (!dotg->typec->partner)
		dev_err(dwc->dev, "failed register partner\n");
}
#endif

static int usb_reboot_noti(struct notifier_block *nb, unsigned long event, void *buf)
{
	struct dwc3_otg *dotg = g_dwc3_exynos->dotg;
	struct dwc3	*dwc = dotg->dwc;
	struct otg_fsm  *fsm = &dotg->fsm;
	int ret = 0;

	dev_info(dwc->dev, "%s, event = %ld\n", __func__, event);

	switch (event) {
	case SYS_RESTART:
	case SYS_POWER_OFF:
		exynos_usbdrd_shutdown_notice(1);
		if (otg_connection == 1) {
			dev_info(dwc->dev, "host enabled. Turn off host\n");
			fsm->id = 1;
			dwc3_otg_run_sm(fsm);
		}
		break;
	}

	return ret;
}

static void dwc3_otg_qos_lock_delayed_work(struct work_struct *wk)
{
	struct delayed_work *delay_work =
		container_of(wk, struct delayed_work, work);
	struct dwc3_exynos *exynos = container_of(delay_work, struct dwc3_exynos,
			usb_qos_lock_delayed_work);
	struct dwc3_otg *dotg = exynos->dotg;
	struct device *dev = dotg->dwc->dev;

	dev_info(dev, "%s\n", __func__);
	if (dotg->pm_qos_int_val) {
		dev_info(dev, "Reset pm_qos int setting\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
		exynos_pm_qos_update_request(&dotg->pm_qos_int_req, 0);
#endif
	}
	if (port_usb3 == 0) {
		if (dotg->pm_qos_hsi0_val) {
			dev_info(dev, "Reset pm_qos hsi0 setting\n");
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
			exynos_pm_qos_update_request(&dotg->pm_qos_hsi0_req, 0);
#endif
		}
	}
}

int dwc3_exynos_otg_init(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	struct dwc3_otg *dotg;
	struct dwc3_ext_otg_ops *ops = NULL;
	int ret = 0;
#if defined(CONFIG_OTG_DEFAULT)
	struct intf_typec	*typec;
#endif

	dev_info(dwc->dev, "%s\n", __func__);

	/* EXYNOS SoCs don't have HW OTG, but it supports SW OTG. */
	ops = dwc3_otg_exynos_rsw_probe(dwc);
	if (!ops)
		return 0;

	g_dwc3_exynos = exynos;
	INIT_WORK(&recovery_reconn_work, dwc3_recovery_reconnection);

	/* Allocate and init otg instance */
	dotg = devm_kzalloc(dwc->dev, sizeof(struct dwc3_otg), GFP_KERNEL);
	if (!dotg) {
		dev_err(dwc->dev, "unable to allocate dwc3_otg\n");
		return -ENOMEM;
	}

	/* This reference is used by dwc3 modules for checking otg existance */
	exynos->dotg = dotg;
	dotg->dwc = dwc;
	dotg->exynos = exynos;
	dev_info(dwc->dev, "%s, dotg = %pK\n", __func__, exynos->dotg);

	ret = of_property_read_u32(dwc->dev->of_node,
				"usb-pm-qos-hsi0", &dotg->pm_qos_hsi0_val);
	if (ret < 0) {
		dev_err(dwc->dev, "couldn't read usb-pm-qos-hsi0 %s node, error = %d\n",
					dwc->dev->of_node->name, ret);
		dotg->pm_qos_hsi0_val = 0;
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
	} else {
		exynos_pm_qos_add_request(&dotg->pm_qos_hsi0_req,
					PM_QOS_HSI0_THROUGHPUT, 0);
#endif
	}

	ret = of_property_read_u32(dwc->dev->of_node,
				"usb-pm-qos-int", &dotg->pm_qos_int_val);
	if (ret < 0) {
		dev_err(dwc->dev, "couldn't read usb-pm-qos-int %s node, error = %d\n",
					dwc->dev->of_node->name, ret);
		dotg->pm_qos_int_val = 0;
#if IS_ENABLED(CONFIG_EXYNOS_PM_QOS)
	} else {
		exynos_pm_qos_add_request(&dotg->pm_qos_int_req,
				PM_QOS_DEVICE_THROUGHPUT, 0);
#endif
	}
	dotg->ext_otg_ops = ops;

	dotg->otg.set_peripheral = dwc3_otg_set_peripheral;
	dotg->otg.set_host = NULL;

	dotg->otg.state = OTG_STATE_UNDEFINED;

	mutex_init(&dotg->fsm.lock);
	dotg->fsm.ops = &dwc3_otg_fsm_ops;
	dotg->fsm.otg = &dotg->otg;

	dotg->vbus_reg = devm_regulator_get(dwc->dev, "dwc3-vbus");
	if (IS_ERR(dotg->vbus_reg))
		dev_err(dwc->dev, "failed to obtain vbus regulator\n");

	if (dotg->ext_otg_ops) {
		dev_info(dwc->dev, "%s, dwc3_ext_otg_setup call\n", __func__);
		ret = dwc3_ext_otg_setup(dotg);
		if (ret) {
			dev_err(dwc->dev, "failed to setup OTG\n");
			return ret;
		}
	}

	dotg->wakelock = wakeup_source_register(dwc->dev, "dwc3-otg");
	dotg->reconn_wakelock = wakeup_source_register(dwc->dev,
				"dwc3-reconnection");
	mutex_init(&dotg->lock);

	ret = sysfs_create_group(&exynos->dev->kobj, &dwc3_otg_attr_group);
	if (ret)
		dev_err(dwc->dev, "failed to create dwc3 otg attributes\n");

	init_completion(&dotg->resume_cmpl);
	dotg->dwc3_suspended = USB_NORMAL;
	dotg->pm_nb.notifier_call = dwc3_otg_pm_notifier;
	register_pm_notifier(&dotg->pm_nb);
	/* register_usb_is_connect(otg_is_connect); */

	dwc->gadget->sg_supported = false;

#if IS_ENABLED(CONFIG_IF_CB_MANAGER)
	dotg->usb_d.data = (void *)dotg;
	dotg->man = register_usb(&dotg->usb_d);
#endif

	INIT_DELAYED_WORK(&exynos->usb_qos_lock_delayed_work,
			dwc3_otg_qos_lock_delayed_work);

#if defined(CONFIG_OTG_DEFAULT)
	INIT_DELAYED_WORK(&dotg->typec_work, typec_work_func);

	typec = devm_kzalloc(dwc->dev, sizeof(*typec), GFP_KERNEL);
	if (!typec)
		return -ENOMEM;

	/* mutex_init(&md05->lock); */
	typec->dev = dwc->dev;
	dotg->typec = typec;

	schedule_delayed_work(&dotg->typec_work,
			      msecs_to_jiffies(2000));
#endif

	dev_info(dwc->dev, "%s done\n", __func__);
#if IS_ENABLED(CONFIG_USB_EXYNOS_TPMON_MODULE)
	usb_tpmon_init(exynos->dev);
#endif
	ret = register_reboot_notifier(&usb_reboot_notifier);
	if (ret)
		dev_err(dwc->dev, "failed register reboot notifier\n");

	return 0;
}

void dwc3_exynos_otg_exit(struct dwc3 *dwc, struct dwc3_exynos *exynos)
{
	struct dwc3_otg *dotg = exynos->dotg;

	if (!dotg->ext_otg_ops)
		return;

#if defined(CONFIG_OTG_DEFAULT)
	typec_unregister_partner(dotg->typec->partner);
	typec_unregister_port(dotg->typec->port);
#endif
	unregister_pm_notifier(&dotg->pm_nb);

	dwc3_ext_otg_exit(dotg);

	sysfs_remove_group(&dwc->dev->kobj, &dwc3_otg_attr_group);
	wakeup_source_unregister(dotg->wakelock);
	wakeup_source_unregister(dotg->reconn_wakelock);
	free_irq(dotg->irq, dotg);
	dotg->otg.state = OTG_STATE_UNDEFINED;
	kfree(dotg);
	exynos->dotg = NULL;
#if IS_ENABLED(CONFIG_USB_EXYNOS_TPMON_MODULE)
	usb_tpmon_exit();
#endif
}
