/*
 *  max77775_charger.c
 *  Samsung max77775 Charger Driver
 *
 *  Copyright (C) 2012 Samsung Electronics
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define DEBUG

#include <linux/mfd/max77775-private.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/power_supply.h>
#include <linux/mfd/max77775.h>
#include <linux/of_gpio.h>
#include "max77775_charger.h"
#include <linux/muic/common/muic.h>
#ifdef CONFIG_USB_HOST_NOTIFY
#include <linux/usb_notify.h>
#endif
#include <linux/sec_debug.h>

#define ENABLE 1
#define DISABLE 0

#if defined(CONFIG_SEC_FACTORY)
#define WC_CURRENT_WORK_STEP	250
#else
#define WC_CURRENT_WORK_STEP	200
#endif
#define WC_CURRENT_WORK_STEP_OTG	200
#define AICL_WORK_DELAY		100

#if IS_ENABLED(CONFIG_WRL_MODE4_FG_SETTING)
static bool is_wireless_mode_4_set;
#endif
static unsigned int __read_mostly lpcharge;
module_param(lpcharge, uint, 0444);
static int factory_mode;
module_param(factory_mode, int, 0444);

extern void max77775_usbc_icurr(u8 curr);
extern void max77775_set_fw_noautoibus(int enable);
extern void max77775_usb_id_set(u8 mode);
extern void max77775_usbc_icurr_autoibus_on(u8 curr);
extern void max77775_set_shipmode_op(int enable, u8 data);
extern void max77775_chgrcv_ramp(bool enable);
#if !defined(CONFIG_SEC_FACTORY)
extern void max77775_bypass_maintain(void);
#endif

static enum power_supply_property max77775_charger_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static enum power_supply_property max77775_otg_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static struct device_attribute max77775_charger_attrs[] = {
	MAX77775_CHARGER_ATTR(chip_id),
	MAX77775_CHARGER_ATTR(data),
};

static void max77775_charger_initialize(struct max77775_charger_data *charger);
static int max77775_get_vbus_state(struct max77775_charger_data *charger);
static int max77775_get_charger_state(struct max77775_charger_data *charger);
static void max77775_init_aicl_irq(struct max77775_charger_data *charger);
static void max77775_chg_set_mode_state(struct max77775_charger_data *charger,
					unsigned int state);
static void max77775_set_switching_frequency(struct max77775_charger_data *charger,
					int frequency);

static unsigned int max77775_get_lpmode(void) { return lpcharge; }
static unsigned int max77775_get_facmode(void) { return factory_mode; }

static bool max77775_charger_unlock(struct max77775_charger_data *charger)
{
	u8 reg_data, chgprot;
	int retry_cnt = 0;
	bool need_init = false;

	do {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06, &reg_data);
		chgprot = ((reg_data & 0x0C) >> 2);
		if (chgprot != 0x03) {
			pr_err("%s: unlock err, chgprot(0x%x), retry(%d)\n",
			       __func__, chgprot, retry_cnt);
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06,
					    (0x03 << 2), (0x03 << 2));
			need_init = true;
			msleep(20);
		} else {
			break;
		}
	} while ((chgprot != 0x03) && (++retry_cnt < 10));

	return need_init;
}

static void check_charger_unlock_state(struct max77775_charger_data *charger)
{
	pr_debug("%s\n", __func__);

	if (max77775_charger_unlock(charger)) {
		pr_err("%s: charger locked state, reg init\n", __func__);
		max77775_charger_initialize(charger);
	}
}

static void max77775_test_read(struct max77775_charger_data *charger)
{
	u8 data = 0;
	u32 addr = 0;
	char str[1024] = { 0, };

	for (addr = 0xB1; addr <= 0xC8; addr++) {
		max77775_read_reg(charger->i2c, addr, &data);
		sprintf(str + strlen(str), "[0x%02x]0x%02x, ", addr, data);
	}
	pr_info("max77775_charger %s[B1~C8] : %s\n", __func__, str);
}

static int max77775_get_autoibus(struct max77775_charger_data *charger)
{
	u8 reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);
	if (reg_data & 0x80)
		return 1; /* set by charger */

	return 0; /* set by USBC */
}

static int max77775_get_vbus_state(struct max77775_charger_data *charger)
{
	u8 reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);

	if (is_wcin_type(charger->cable_type))
		reg_data = ((reg_data & MAX77775_WCIN_DTLS) >>
			    MAX77775_WCIN_DTLS_SHIFT);
	else
		reg_data = ((reg_data & MAX77775_CHGIN_DTLS) >>
			    MAX77775_CHGIN_DTLS_SHIFT);

	switch (reg_data) {
	case 0x00:
		pr_info("%s: VBUS is invalid. CHGIN < CHGIN_UVLO\n", __func__);
		break;
	case 0x01:
		pr_info("%s: VBUS is invalid. CHGIN < MBAT+CHGIN2SYS and CHGIN > CHGIN_UVLO\n", __func__);
		break;
	case 0x02:
		pr_info("%s: VBUS is invalid. CHGIN > CHGIN_OVLO\n", __func__);
		break;
	case 0x03:
		pr_info("%s: VBUS is valid. CHGIN < CHGIN_OVLO\n", __func__);
		break;
	default:
		break;
	}

	return reg_data;
}

static int max77775_get_charger_state(struct max77775_charger_data *charger)
{
	int status = POWER_SUPPLY_STATUS_UNKNOWN;
	u8 reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &reg_data);
	pr_info("%s : charger status (0x%02x)\n", __func__, reg_data);

	reg_data &= 0x0f;
	switch (reg_data) {
	case 0x00:
	case 0x01:
	case 0x02:
		status = POWER_SUPPLY_STATUS_CHARGING;
		break;
	case 0x03:
	case 0x04:
		status = POWER_SUPPLY_STATUS_FULL;
		break;
	case 0x05:
	case 0x06:
		status = POWER_SUPPLY_STATUS_NOT_CHARGING;
		break;
	case 0x07:
	case 0x08:
	case 0x0A:
	case 0x0B:
		status = POWER_SUPPLY_STATUS_DISCHARGING;
		break;
	default:
		break;
	}

	return (int)status;
}

static bool max77775_chg_get_wdtmr_status(struct max77775_charger_data *charger)
{
	u8 reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &reg_data);
	reg_data = ((reg_data & MAX77775_CHG_DTLS) >> MAX77775_CHG_DTLS_SHIFT);

	if (reg_data == 0x0B) {
		dev_info(charger->dev, "WDT expired 0x%x !!\n", reg_data);
		return true;
	}

	return false;
}

static int max77775_chg_set_wdtmr_en(struct max77775_charger_data *charger,
					bool enable)
{
	pr_info("%s: WDT en = %d\n", __func__, enable);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			(enable ? CHG_CNFG_00_WDTEN_MASK : 0), CHG_CNFG_00_WDTEN_MASK);

	return 0;
}

static int max77775_chg_set_wdtmr_kick(struct max77775_charger_data *charger)
{
	pr_info("%s: WDT Kick\n", __func__);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06,
			    (MAX77775_WDTCLR << CHG_CNFG_06_WDTCLR_SHIFT),
			    CHG_CNFG_06_WDTCLR_MASK);

	return 0;
}

static void max77775_set_termination_voltage(struct max77775_charger_data *charger,
					int float_voltage)
{
	u8 reg_data = 0;

	if (float_voltage > charger->pdata->chg_float_voltage) {
		pr_info("%s: set float voltage(%d <-%d)\n", __func__,
				charger->pdata->chg_float_voltage, float_voltage);
		float_voltage = charger->pdata->chg_float_voltage;
	}

	if (float_voltage <= 4000)
		reg_data = ((float_voltage - 3400) / 100) + 0x00;
	else if (float_voltage <= 4200)
		reg_data = ((float_voltage - 4000) / 50) + 0x06;
	else if (float_voltage <= 4400)
		reg_data = ((float_voltage - 4200) / 10) + 0x0A;
	else
		reg_data = ((float_voltage - 4400) / 5) + 0x1E;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_04,
			    (reg_data << CHG_CNFG_04_CHG_CV_PRM_SHIFT),
			    CHG_CNFG_04_CHG_CV_PRM_MASK);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_04, &reg_data);
	pr_info("%s: battery cv voltage 0x%x\n", __func__, reg_data);
}

static void max77775_set_float_voltage(struct max77775_charger_data *charger,
					int float_voltage)
{
	if (max77775_get_facmode()) {
		float_voltage = charger->pdata->fac_vsys;
		pr_info("%s: Factory mode Skip set float voltage(%d)\n", __func__, float_voltage);
		// do not return here
	}

	max77775_set_termination_voltage(charger, float_voltage);
}

static int max77775_get_float_voltage(struct max77775_charger_data *charger)
{
	u8 reg_data = 0;
	int float_voltage;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_04, &reg_data);
	reg_data &= 0x3F;

	if (reg_data <= 0x06)
		float_voltage = 3400 + (reg_data * 100);
	else if (reg_data <= 0x0A)
		float_voltage = 4000 + ((reg_data - 0x06) * 50);
	else if (reg_data <= 0x1E)
		float_voltage = 4200 + ((reg_data - 0x0A) * 10);
	else
		float_voltage = 4400 + ((reg_data - 0x1E) * 5);

	pr_debug("%s: battery cv reg : 0x%x, float voltage val : %d\n",
		__func__, reg_data, float_voltage);

	return float_voltage;
}

static int max77775_get_charging_health(struct max77775_charger_data *charger)
{
	union power_supply_propval value = {0,}, val_iin = {0,}, val_vbyp = {0,};
	int state = POWER_SUPPLY_HEALTH_GOOD;
	int vbus_state, retry_cnt;
	u8 chg_dtls, reg_data, chg_cnfg_00;
	bool wdt_status, abnormal_status = false;

	/* watchdog kick */
	max77775_chg_set_wdtmr_kick(charger);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &reg_data);
	reg_data = ((reg_data & MAX77775_BAT_DTLS) >> MAX77775_BAT_DTLS_SHIFT);

	if (charger->pdata->enable_noise_wa) {
		psy_do_property("battery", get, POWER_SUPPLY_PROP_CAPACITY, value);
		if ((value.intval >= 80) &&
			(charger->fsw_now != MAX77775_CHG_FSW_3MHz))
			max77775_set_switching_frequency(charger, MAX77775_CHG_FSW_3MHz);
		else if ((value.intval < 80) &&
			(charger->fsw_now != MAX77775_CHG_FSW_1_5MHz))
			max77775_set_switching_frequency(charger, MAX77775_CHG_FSW_1_5MHz);
	}

	pr_info("%s: reg_data(0x%x)\n", __func__, reg_data);
	switch (reg_data) {
	case 0x00:
		pr_info("%s: No battery and the charger is suspended\n", __func__);
		break;
	case 0x01:
		pr_info("%s: battery is okay but its voltage is low(~VPQLB)\n", __func__);
		break;
	case 0x02:
		pr_info("%s: battery dead\n", __func__);
		break;
	case 0x03:
		break;
	case 0x04:
		pr_info("%s: battery is okay but its voltage is low\n", __func__);
		break;
	case 0x05:
		pr_info("%s: battery ovp\n", __func__);
		break;
	case 0x06:
		pr_info("%s: battery ocp\n", __func__);
		break;
	default:
		pr_info("%s: battery unknown\n", __func__);
		break;
	}
	if (charger->is_charging) {
		max77775_read_reg(charger->i2c,	MAX77775_CHG_REG_DETAILS_00, &reg_data);
		pr_info("%s: details00(0x%x)\n", __func__, reg_data);
	}

	/* get wdt status */
	wdt_status = max77775_chg_get_wdtmr_status(charger);

	psy_do_property("battery", get, POWER_SUPPLY_EXT_PROP_HEALTH, value);
	/* VBUS OVP state return battery OVP state */
	vbus_state = max77775_get_vbus_state(charger);
	/* read CHG_DTLS and detecting battery terminal error */
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &chg_dtls);
	chg_dtls = ((chg_dtls & MAX77775_CHG_DTLS) >> MAX77775_CHG_DTLS_SHIFT);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &chg_cnfg_00);

	/* print the log at the abnormal case */
	if ((charger->is_charging == 1) && !charger->uno_on
		&& ((chg_dtls == 0x08) || (chg_dtls == 0x0B))) {
		max77775_test_read(charger);
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_CHARGING_OFF);
		max77775_set_float_voltage(charger, charger->float_voltage);
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_CHARGING);
		abnormal_status = true;
	}

	val_iin.intval = SEC_BATTERY_IIN_MA;
	psy_do_property("max77775-fuelgauge", get,
		POWER_SUPPLY_EXT_PROP_MEASURE_INPUT, val_iin);

	val_vbyp.intval = SEC_BATTERY_VBYP;
	psy_do_property("max77775-fuelgauge", get,
		POWER_SUPPLY_EXT_PROP_MEASURE_INPUT, val_vbyp);

	pr_info("%s: vbus_state: 0x%x, chg_dtls: 0x%x, iin: %dmA, vbyp: %dmV, health: %d, abnormal: %s\n",
		__func__, vbus_state, chg_dtls, val_iin.intval,
		val_vbyp.intval, value.intval, (abnormal_status ? "true" : "false"));

	/*  OVP is higher priority */
	if (vbus_state == 0x02) {	/*  CHGIN_OVLO */
		pr_info("%s: vbus ovp\n", __func__);
		if (is_wcin_type(charger->cable_type)) {
			retry_cnt = 0;
			do {
				msleep(50);
				vbus_state = max77775_get_vbus_state(charger);
			} while ((retry_cnt++ < 2) && (vbus_state == 0x02));
			if (vbus_state == 0x02) {
				state = POWER_SUPPLY_HEALTH_OVERVOLTAGE;
				pr_info("%s: wpc and over-voltage\n", __func__);
			} else {
				state = POWER_SUPPLY_HEALTH_GOOD;
			}
		} else {
			state = POWER_SUPPLY_HEALTH_OVERVOLTAGE;
		}
	} else if (((vbus_state == 0x0) || (vbus_state == 0x01)) && (chg_dtls & 0x08)
		   && (chg_cnfg_00 & MAX77775_MODE_5_BUCK_CHG_ON)
		   && !is_wcin_type(charger->cable_type)) {
		pr_info("%s: vbus is under\n", __func__);
		state = POWER_SUPPLY_EXT_HEALTH_UNDERVOLTAGE;
	} else if ((value.intval == POWER_SUPPLY_EXT_HEALTH_UNDERVOLTAGE) &&
		   ((vbus_state == 0x0) || (vbus_state == 0x01)) &&
		   !is_wcin_type(charger->cable_type)) {
		pr_info("%s: keep under-voltage\n", __func__);
		state = POWER_SUPPLY_EXT_HEALTH_UNDERVOLTAGE;
	} else if (wdt_status) {
		pr_info("%s: wdt expired\n", __func__);
		state = POWER_SUPPLY_HEALTH_WATCHDOG_TIMER_EXPIRE;
	} else if (is_wireless_type(charger->cable_type)) {
		if (abnormal_status || (vbus_state == 0x00) || (vbus_state == 0x01))
			charger->misalign_cnt++;
		else
			charger->misalign_cnt = 0;

		if (charger->misalign_cnt >= 3) {
			pr_info("%s: invalid WCIN, Misalign occurs!\n", __func__);
			value.intval = POWER_SUPPLY_STATUS_NOT_CHARGING;
			psy_do_property(charger->pdata->wireless_charger_name,
				set, POWER_SUPPLY_PROP_STATUS, value);
		}
	}

	return (int)state;
}

static int max77775_get_charge_current(struct max77775_charger_data *charger)
{
	struct max77775_dev *max77775 = dev_get_drvdata(charger->dev->parent);
	u8 reg_data;
	int get_current = 0;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02, &reg_data);
	reg_data &= MAX77775_CHG_CC;

	if (max77775->pmic_rev == MAX77775_PASS1)
		get_current = reg_data <= 0x04 ? 267 : (int)((reg_data * 6665) / 100);
	else
		get_current = (int)((reg_data * 6665) / 100);

	pr_info("%s: reg:(0x%x), charging_current:(%d)\n",
			__func__, reg_data, get_current);

	return get_current;
}

static int max77775_get_input_current_type(struct max77775_charger_data
					*charger, int cable_type)
{
	u8 reg_data;
	int get_current = 0;

	if (cable_type == SEC_BATTERY_CABLE_WIRELESS) {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_10, &reg_data);
		/* AND operation for removing the formal 2bit  */
		reg_data &= MAX77775_CHG_WCIN_LIM;

		if (reg_data <= 0x3)
			get_current = 100;
		else if (reg_data >= 0x3F)
			get_current = 1600;
		else
			get_current = (reg_data + 0x01) * 25;
	} else {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09, &reg_data);
		/* AND operation for removing the formal 1bit  */
		reg_data &= MAX77775_CHG_CHGIN_LIM;

		if (reg_data <= 0x3)
			get_current = 100;
		else if (reg_data >= 0x7F)
			get_current = 3200;
		else
			get_current = (reg_data + 0x01) * 25;
	}
	pr_info("%s: reg:(0x%x), charging_current:(%d)\n",
			__func__, reg_data, get_current);

	return get_current;
}

static int max77775_get_input_current(struct max77775_charger_data *charger)
{
	if (is_wcin_type(charger->cable_type) || is_wireless_fake_type(charger->cable_type))
		return max77775_get_input_current_type(charger, SEC_BATTERY_CABLE_WIRELESS);
	else
		return max77775_get_input_current_type(charger,	SEC_BATTERY_CABLE_TA);
}

static int reduce_input_current(struct max77775_charger_data *charger)
{
	int input_current = 0, max_value = 0;

	input_current = max77775_get_input_current(charger);
	if (input_current <= MINIMUM_INPUT_CURRENT) {
		charger->input_current = input_current;
		return input_current;
	}

	if (is_wcin_type(charger->cable_type) || is_wireless_fake_type(charger->cable_type))
		max_value = 1600;
	else
		max_value = 3200;

	input_current -= REDUCE_CURRENT_STEP;
	input_current = (input_current > max_value) ? max_value :
			((input_current < MINIMUM_INPUT_CURRENT) ? MINIMUM_INPUT_CURRENT : input_current);

	sec_votef("ICL", VOTER_AICL, true, input_current);
	charger->input_current = max77775_get_input_current(charger);

	return input_current;
}

static bool max77775_check_battery(struct max77775_charger_data *charger)
{
	u8 reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);
	pr_info("%s: CHG_INT_OK(0x%x)\n",
		__func__, reg_data);

	if (reg_data & MAX77775_BATP_OK)
		return true;
	else
		return false;
}

static void max77775_check_cnfg12_reg(struct max77775_charger_data *charger)
{
	static bool is_valid = true;
	u8 valid_cnfg12, reg_data;

	if (is_valid) {
		reg_data = MAX77775_CHG_WCINSEL;
		valid_cnfg12 = is_wcin_type(charger->cable_type) ?
			reg_data : (reg_data | (1 << CHG_CNFG_12_CHGINSEL_SHIFT));

		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12, &reg_data);
		pr_info("%s: valid_data = 0x%2x, reg_data = 0x%2x\n",
			__func__, valid_cnfg12, reg_data);
		if (valid_cnfg12 != (reg_data & 0x7F)) {
			max77775_test_read(charger);
			is_valid = false;
		}
	}
}

static void max77775_set_charge_path(struct max77775_charger_data *charger, int path, int ctrl_mask)
{
	u8 cnfg12 = (1 << CHG_CNFG_12_CHGINSEL_SHIFT);
	u8 path_mask = (CHG_CNFG_12_CHGINSEL_MASK | CHG_CNFG_12_WCINSEL_MASK);

	switch (path) {
	case CHGIN_SEL:
		cnfg12 = (1 << CHG_CNFG_12_CHGINSEL_SHIFT);
		if (ctrl_mask == CHGIN_SEL)
			path_mask = CHG_CNFG_12_CHGINSEL_MASK;
		break;
	case WCIN_SEL:
		cnfg12 = (1 << CHG_CNFG_12_WCINSEL_SHIFT);
		if (ctrl_mask == WCIN_SEL)
			path_mask = CHG_CNFG_12_WCINSEL_MASK;
		break;
	case WC_CHG_ALL_ON:
		cnfg12 = ((1 << CHG_CNFG_12_CHGINSEL_SHIFT) | (1 << CHG_CNFG_12_WCINSEL_SHIFT));

		break;
	case WC_CHG_ALL_OFF:
		cnfg12 = 0;
		break;
	default:
		pr_info("%s could not apply charge_path (%d)\n",
				__func__, path);
	}

	if (max77775_get_facmode()) {
		cnfg12 |= (1 << CHG_CNFG_12_CHGINSEL_SHIFT);
		path_mask |= CHG_CNFG_12_CHGINSEL_MASK;
	}

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
			    cnfg12, path_mask);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12, &cnfg12);
	pr_info("%s : CHG_CNFG_12(0x%02x)\n", __func__, cnfg12);

	max77775_check_cnfg12_reg(charger);
}

static void max77775_check_charge_path(struct max77775_charger_data *charger)
{
	int chgin_sel = (charger->uno_on || is_nocharge_type(charger->cable_type) ? WC_CHG_ALL_ON : CHGIN_SEL);
	int wcin_sel = (charger->otg_on ? WC_CHG_ALL_ON : WCIN_SEL);

	if (is_wcin_type(charger->cable_type) || is_wireless_fake_type(charger->cable_type))
		max77775_set_charge_path(charger, wcin_sel, WC_CHG_ALL_ON);
	else
		max77775_set_charge_path(charger, chgin_sel, WC_CHG_ALL_ON);
}

static void max77775_set_ship_mode(struct max77775_charger_data *charger,
					int enable)
{
	u8 cnfg07 = ((enable ? 1 : 0) << CHG_CNFG_07_REG_SHIPMODE_SHIFT);

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07,
			    cnfg07, CHG_CNFG_07_REG_SHIPMODE_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07, &cnfg07);
	pr_info("%s : CHG_CNFG_07(0x%02x)\n", __func__, cnfg07);
}

static void max77775_set_ship_exit_db(struct max77775_charger_data *charger,
					int exit_time_ms)
{
	u8 reg_data = 0;

	pr_info("%s : exit_time_ms(%d)\n", __func__, exit_time_ms);

	if (exit_time_ms < 500)
		pr_info("%s could not apply ship mode exit_time_ms(%d) under 500ms\n",
				__func__, exit_time_ms);
	else if (exit_time_ms >= 500 && exit_time_ms < 1000)
		reg_data = 0x00;
	else if (exit_time_ms >= 1000 && exit_time_ms < 2000)
		reg_data = 0x01;
	else if (exit_time_ms >= 2000 && exit_time_ms < 4000)
		reg_data = 0x02;
	else
		reg_data = 0x03;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13,
		reg_data << CHG_CNFG_13_SHIP_EXT_DB_SHIFT, CHG_CNFG_13_SHIP_EXT_DB_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13, &reg_data);
	pr_info("%s : CHG_CNFG_13(0x%02x)\n", __func__, reg_data);
}

static void max77775_set_ship_entry_db(struct max77775_charger_data *charger,
					int ent_time_s)
{
	u8 reg_data = 0;

	pr_info("%s : ent_time_s(%d)\n", __func__, ent_time_s);

	if (ent_time_s < 0)
		pr_info("%s could not apply ship mode ent_time_s(%d) under 0\n",
				__func__, ent_time_s);
	else if (ent_time_s >= 0 && ent_time_s < 16)
		reg_data = 0x00;
	else if (ent_time_s >= 16 && ent_time_s < 32)
		reg_data = 0x01;
	else if (ent_time_s >= 32 && ent_time_s < 192)
		reg_data = 0x02;
	else
		reg_data = 0x03;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13,
		reg_data, CHG_CNFG_13_SHIP_ENTRY_DB_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13, &reg_data);
	pr_info("%s : CHG_CNFG_13(0x%02x)\n", __func__, reg_data);
}

static int max77775_get_ship_mode(struct max77775_charger_data *charger)
{
	int ret = 0;
	u8 cnfg07 = 0;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07, &cnfg07);
	ret = (cnfg07 & CHG_CNFG_07_REG_SHIPMODE_MASK);
	pr_info("%s : CHG_CNFG_07(0x%02x, %d)\n", __func__, cnfg07, ret);

	return ret;
}

static void max77775_set_auto_ship_mode(struct max77775_charger_data *charger,
					int enable)
{
	u8 cnfg13 = ((enable ? 1 : 0) << CHG_CNFG_13_REG_AUTO_SHIPMODE_SHIFT);

	/* auto ship mode should work under 2.6V */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13,
			    cnfg13, CHG_CNFG_13_REG_AUTO_SHIPMODE_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13, &cnfg13);
	pr_info("%s : CHG_CNFG_13(0x%02x)\n", __func__, cnfg13);
}

static void max77775_set_bypass_auto_ship_en(struct max77775_charger_data *charger,
					int enable)
{
	u8 cnfg13 = ((enable ? 1 : 0) << CHG_CNFG_13_BYPASS_AUTOSHIP_EN_SHIFT);

	/* auto ship mode should work under 2.6V */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13,
			    cnfg13, CHG_CNFG_13_BYPASS_AUTOSHIP_EN_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13, &cnfg13);
	pr_info("%s : CHG_CNFG_13(0x%02x)\n", __func__, cnfg13);
}

#if defined(CONFIG_SHIPMODE_BY_VBAT) && !defined(CONFIG_SEC_FACTORY)
static bool max77775_check_current_level(void)
{
	union power_supply_propval val_avg_curr = {0, }, val_now_curr = {0, };

	val_avg_curr.intval = SEC_BATTERY_CURRENT_MA;
	val_now_curr.intval = SEC_BATTERY_CURRENT_MA;
	psy_do_property("max77775-fuelgauge", get, POWER_SUPPLY_PROP_CURRENT_AVG, val_avg_curr);
	psy_do_property("max77775-fuelgauge", get, POWER_SUPPLY_PROP_CURRENT_NOW, val_now_curr);
	pr_info("[DEBUG]%s: current: %d, %d\n",
		__func__, val_avg_curr.intval, val_now_curr.intval);

	return ((val_avg_curr.intval > 6000) && (val_now_curr.intval > 6000)) ? true : false;
}

static u8 max77775_get_auto_shipmode_data(int voltage, int offset)
{
	u8 ret = 0x00;

	if (voltage >= 4000)
		ret = 0x03;
	else if (voltage >= 3700)
		ret = 0x02;
	else if (voltage >= 3400)
		ret = 0x01;

	if (ret > offset)
		ret = (ret) ?
			(offset ? (ret - offset) : ret) : 0;
	else
		ret = 0x00;

	return ret;
}

static void max77775_check_auto_shipmode_level(struct max77775_charger_data *charger, int offset)
{
	union power_supply_propval value = { 0, };
	int voltage = 2600;
	u8 reg_data, read_data = 0;
	int ari_cond = charger->spcom ? 91 : 0;

	psy_do_property("max77775-fuelgauge", get, POWER_SUPPLY_PROP_VOLTAGE_NOW, value);
	if (value.intval >= 4200)
		voltage = 4000;
	else if (value.intval >= 3900)
		voltage = 3700;
	else if (value.intval >= 3700)
		voltage = 3400;

	/* Not delivered ari cnt or under 90, set 2.6v auto ship mode */
	/* no dts, but if ari cnt write,
		it is judged to be abnormal and set 2.6v auto ship mode */
	if (charger->ari_cnt < ari_cond)
		voltage = 2600;

	reg_data = max77775_get_auto_shipmode_data(voltage, offset);
	max77775_set_shipmode_op(true, reg_data);

	pr_info("[DEBUG]%s: check shipmode %d, %d, 0x%x, 0x%x\n",
		__func__, value.intval, voltage, reg_data, read_data);
}
#endif

static void max77775_set_input_current(struct max77775_charger_data *charger,
					int input_current)
{
	int curr_step = 25;
	u8 set_reg, set_mask, reg_data = 0;

	if (max77775_get_facmode() || charger->bypass_mode) {
		pr_info("%s: %s Skip set input current\n", __func__,
			(charger->bypass_mode ? "bypass mode" : "Factory mode"));
		return;
	}

	charger->dpm_last_icl = input_current;
	if (!charger->bat_det && input_current < charger->pdata->dpm_icl) {
		input_current = charger->pdata->dpm_icl;
		pr_info("%s : DPM, icl setting value change (%dmA)\n", __func__, input_current);
	}

	mutex_lock(&charger->charger_mutex);

	if (is_wcin_type(charger->cable_type) || is_wireless_fake_type(charger->cable_type)) {
		set_reg = MAX77775_CHG_REG_CNFG_10;
		set_mask = MAX77775_CHG_WCIN_LIM;
		input_current = (input_current > 1600) ? 1600 : input_current;
	} else {
		set_reg = MAX77775_CHG_REG_CNFG_09;
		set_mask = MAX77775_CHG_CHGIN_LIM;
		input_current = (input_current > 3200) ? 3200 : input_current;
	}

	if (input_current >= 100)
		reg_data = (input_current / curr_step) - 0x01;

	max77775_update_reg(charger->i2c, set_reg, reg_data, set_mask);
	pr_info("[%s] REG(0x%02x) DATA(0x%02x), CURRENT(%d)\n",
		__func__, set_reg, reg_data, input_current);

	if (is_nocharge_type(charger->cable_type)) {
		set_reg = MAX77775_CHG_REG_CNFG_10;
		set_mask = MAX77775_CHG_WCIN_LIM;
		input_current = (input_current > 1600) ? 1600 : input_current;
		if (input_current >= 100)
			reg_data = (input_current / curr_step) - 0x01;
		max77775_update_reg(charger->i2c, set_reg, reg_data, set_mask);
		pr_info("[%s] REG(0x%02x) DATA(0x%02x), CURRENT(%d)\n",
			__func__, set_reg, reg_data, input_current);
	}

	if (!max77775_get_autoibus(charger))
		max77775_set_fw_noautoibus(MAX77775_AUTOIBUS_AT_OFF);

	mutex_unlock(&charger->charger_mutex);
}

static void max77775_set_charge_current(struct max77775_charger_data *charger,
					int fast_charging_current)
{
	struct max77775_dev *max77775 = dev_get_drvdata(charger->dev->parent);
	u8 reg_data = 0;

	if (max77775_get_facmode()) {
		pr_info("%s: Factory Mode Skip set charge current\n", __func__);
		return;
	}

	fast_charging_current =
		(fast_charging_current > 4199) ? 4199 : fast_charging_current;

	if (max77775->pmic_rev == MAX77775_PASS1) {
		if (fast_charging_current > 267)
			reg_data = (u8)((fast_charging_current * 100) / 6665);
		else
			reg_data = 1;
	} else {
		reg_data = (u8)((fast_charging_current * 100) / 6665);
	}

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
		reg_data, MAX77775_CHG_CC);

	pr_info("[%s] REG(0x%02x) DATA(0x%02x), CURRENT(%d)\n", __func__,
		MAX77775_CHG_REG_CNFG_02, reg_data, fast_charging_current);
}

static void max77775_set_wireless_input_current(
				struct max77775_charger_data *charger, int input_current)
{
	union power_supply_propval value = {0, };
	unsigned int work_state;

	cancel_delayed_work(&charger->wc_chg_current_work);
	__pm_relax(charger->wc_chg_current_ws);

	if (is_wireless_type(charger->cable_type)) {
		work_state = work_busy(&charger->wc_current_work.work);
		pr_info("%s: check wc_current_work state(0x%x)\n", __func__, work_state);
		if (!(work_state & (WORK_BUSY_PENDING | WORK_BUSY_RUNNING))) {
			/* Wcurr-A) In cases of wireless input current change,
			 * configure the Vrect adj room to 270mV for safe wireless charging.
			 */
			if (is_hv_wireless_type(charger->cable_type))
				value.intval = WIRELESS_VRECT_ADJ_ROOM_1; /* Vrect Room 277mV */
			else
				value.intval = charger->pdata->nv_wc_headroom;
			psy_do_property(charger->pdata->wireless_charger_name, set,
					POWER_SUPPLY_EXT_PROP_WIRELESS_RX_CONTROL, value);
			msleep(500); /* delay 0.5sec */
		}
		charger->wc_pre_current = max77775_get_input_current(charger);
		charger->wc_current = input_current;
		pr_info("%s: wc_current(%d), wc_pre_current(%d)\n",
				__func__, charger->wc_current, charger->wc_pre_current);
		if (charger->wc_current > charger->wc_pre_current)
			max77775_set_charge_current(charger, charger->charging_current);
	}
	mutex_lock(&charger->icl_mutex);
	__pm_stay_awake(charger->wc_current_ws);
	queue_delayed_work(charger->wqueue, &charger->wc_current_work, 0);
	mutex_unlock(&charger->icl_mutex);
}

static void max77775_set_topoff_current(struct max77775_charger_data *charger,
					int termination_current)
{
	struct max77775_dev *max77775 = dev_get_drvdata(charger->dev->parent);
	int curr_base = 200, curr_step = 67, curr_max = 1200;
	u8 reg_data;

	if (max77775->pmic_rev == MAX77775_PASS1) {
		curr_base = 200;
		curr_step = 67;
		curr_max = 1200;
	} else {
		curr_base = 133;
		curr_step = 67;
		curr_max = 1133;
	}

	if (termination_current < curr_base)
		termination_current = curr_base;
	else if (termination_current > curr_max)
		termination_current = curr_max;

	reg_data = (u8)((termination_current - curr_base) / curr_step);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_03,
			    reg_data, CHG_CNFG_03_TO_ITH_MASK);

	pr_info("%s: reg_data(0x%02x), topoff(%dmA)\n",
		__func__, reg_data, termination_current);
}

static void max77775_set_topoff_time(struct max77775_charger_data *charger,
					int topoff_time)
{
	u8 reg_data = 0;
	switch (topoff_time) {
	case 30:
		reg_data = MAX77775_TO_TIME_30M << CHG_CNFG_03_TO_TIME_SHIFT;
		break;
	case 40:
		reg_data = MAX77775_TO_TIME_40M << CHG_CNFG_03_TO_TIME_SHIFT;
		break;
	case 50:
		reg_data = MAX77775_TO_TIME_50M << CHG_CNFG_03_TO_TIME_SHIFT;
		break;
	case 70:
		reg_data = MAX77775_TO_TIME_70M << CHG_CNFG_03_TO_TIME_SHIFT;
		break;
	default:
		pr_info("%s could not apply topoff_time (%d)\n",
				__func__, topoff_time);
		return;
	}

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_03,
		reg_data, CHG_CNFG_03_TO_TIME_MASK);

	pr_info("%s: reg_data(0x%02x), topoff_time(%dmin)\n",
		__func__, reg_data, topoff_time);
}

static void max77775_set_bypass_mode(struct max77775_charger_data *charger,
				int enable)
{
	u8 cnfg_08;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);
	max77775_set_input_current(charger, 3200);

	/* enable bypass mode write en */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_17,
			(0x01 << CHG_CNFG_17_BYPASS_MODE_WR_EN_SHIFT),
			CHG_CNFG_17_BYPASS_MODE_WR_EN_MASK);

	/* Set bypass mode */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08,
			(enable << CHG_CNFG_08_BYPASS_MODE_SHIFT),
			CHG_CNFG_08_BYPASS_MODE_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08, &cnfg_08);

	pr_info("%s : set bypass mode - CHG_CNFG_08(0x%02x)\n", __func__, cnfg_08);

	/* disable bypass mode write en */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_17,
			(0x00 << CHG_CNFG_17_BYPASS_MODE_WR_EN_SHIFT),
			CHG_CNFG_17_BYPASS_MODE_WR_EN_MASK);

	charger->bypass_mode = enable ? true : false;
}

static void max77775_set_switching_frequency(struct max77775_charger_data *charger,
				int frequency)
{
	u8 cnfg_08;

	/* Set Switching Frequency */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08,
			(frequency << CHG_CNFG_08_REG_FSW_SHIFT),
			CHG_CNFG_08_REG_FSW_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08, &cnfg_08);

	charger->fsw_now = frequency;
	pr_info("%s : CHG_CNFG_08(0x%02x)\n", __func__, cnfg_08);
}

static void max77775_set_skipmode(struct max77775_charger_data *charger,
				int enable)
{
	u8 reg_data = enable ? MAX77775_AUTO_SKIP : MAX77775_DISABLE_SKIP;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
			reg_data << CHG_CNFG_12_REG_DISKIP_SHIFT,
			CHG_CNFG_12_REG_DISKIP_MASK);
}

static void max77775_set_b2sovrc(struct max77775_charger_data *charger,
					u32 ocp_current, u32 ocp_dtc)
{
	u8 reg_data = 1; // 4400 mA

	if (ocp_current == 0)
		reg_data = MAX77775_B2SOVRC_DISABLE;
	else
		reg_data += (ocp_current - 4400) / 400;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05,
		(reg_data << CHG_CNFG_05_REG_B2SOVRC_SHIFT),
		CHG_CNFG_05_REG_B2SOVRC_MASK);

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06,
		((ocp_dtc == 100 ? MAX77775_B2SOVRC_DTC_100MS : 0)
		<< CHG_CNFG_06_B2SOVRC_DTC_SHIFT), CHG_CNFG_06_B2SOVRC_DTC_MASK);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05, &reg_data);
	pr_info("%s : CHG_CNFG_05(0x%02x)\n", __func__, reg_data);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06, &reg_data);
	pr_info("%s : CHG_CNFG_06(0x%02x)\n", __func__, reg_data);

	return;
}

static int max77775_set_spsn_det_res(struct max77775_charger_data *charger, int resistor)
{
	u8 reg_data = MAX77775_CHG_SPSN_OPEN;
	int ret = 0;

	switch (resistor) {
	case 1:
		reg_data = MAX77775_CHG_SPSN_1K;
		break;
	case 10:
		reg_data = MAX77775_CHG_SPSN_10K;
		break;
	case 100:
		reg_data = MAX77775_CHG_SPSN_100K;
		break;
	}

	ret = max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08,
			(reg_data << CHG_CNFG_08_REG_SPSN_DET_SHIFT),
			CHG_CNFG_08_REG_SPSN_DET_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_08, &reg_data);
	pr_info("%s: ret = %d, reg_data = 0x%x\n", __func__, ret, reg_data);
	return ret;
}

static int max77775_check_wcin_before_otg_on(struct max77775_charger_data *charger)
{
	union power_supply_propval value = {0,};
	struct power_supply *psy;
	u8 reg_data;

	psy = get_power_supply_by_name("wireless");
	if (!psy)
		return -ENODEV;
	if ((psy->desc->get_property != NULL) &&
		(psy->desc->get_property(psy, POWER_SUPPLY_PROP_ONLINE, &value) >= 0)) {
		if (value.intval)
			return 0;
	} else {
		return -ENODEV;
	}
	power_supply_put(psy);

#if defined(CONFIG_WIRELESS_TX_MODE)
	psy_do_property("battery", get,
		POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ENABLE, value);
	/* check TX status */
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg_data);
	reg_data &= CHG_CNFG_00_MODE_MASK;
	if (value.intval &&
		(reg_data == MAX77775_MODE_8_BOOST_UNO_ON ||
		reg_data == MAX77775_MODE_C_BUCK_BOOST_UNO_ON ||
		reg_data == MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON)) {
		value.intval = BATT_TX_EVENT_WIRELESS_TX_OTG_ON;
		psy_do_property("wireless", set,
			POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ERR, value);
		return 0;
	}
#endif

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);
	reg_data = ((reg_data & MAX77775_WCIN_DTLS) >> MAX77775_WCIN_DTLS_SHIFT);
	if ((reg_data != 0x03) || (charger->pdata->wireless_charger_name == NULL))
		return 0;

	psy_do_property(charger->pdata->wireless_charger_name, get,
		POWER_SUPPLY_PROP_ENERGY_NOW, value);
	if (value.intval < 0)
		return -ENODEV;

    return 0;
}

static void max77775_set_otg(struct max77775_charger_data *charger, int enable)
{
	union power_supply_propval value = {0, };
	u8 chg_int_state, otg_lim;
	int ret = 0;

	pr_info("%s: CHGIN-OTG %s\n", __func__,	enable > 0 ? "on" : "off");
	if (charger->otg_on == enable || max77775_get_lpmode())
		return;

	if (charger->pdata->wireless_charger_name) {
		ret = max77775_check_wcin_before_otg_on(charger);
		pr_info("%s: wc_state = %d\n", __func__, ret);
		if (ret < 0)
			return;
	}

	__pm_stay_awake(charger->otg_ws);
	/* CHGIN-OTG */
	value.intval = enable;
	mutex_lock(&charger->charger_mutex);
	charger->otg_on = enable;
	mutex_unlock(&charger->charger_mutex);

	if (!enable)
		charger->hp_otg = false;

	/* otg current limit 900mA or 1500mA */
	if (charger->hp_otg)
		otg_lim = MAX77775_OTG_ILIM_1500;
	else
		otg_lim = MAX77775_OTG_ILIM_900;

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
			otg_lim << CHG_CNFG_02_OTG_ILIM_SHIFT,
			CHG_CNFG_02_OTG_ILIM_MASK);

	if (enable) {
		psy_do_property("wireless", set,
			POWER_SUPPLY_EXT_PROP_CHARGE_OTG_CONTROL, value);

		mutex_lock(&charger->charger_mutex);
		/* OTG on, boost on */
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_OTG_ON);
		mutex_unlock(&charger->charger_mutex);
	} else {
		mutex_lock(&charger->charger_mutex);
		/* OTG off(UNO on), boost off */
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_OTG_OFF);
		mutex_unlock(&charger->charger_mutex);
		msleep(50);

		psy_do_property("wireless", set,
			POWER_SUPPLY_EXT_PROP_CHARGE_OTG_CONTROL, value);
	}
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_MASK, &chg_int_state);
	pr_info("%s: INT_MASK(0x%x)\n", __func__, chg_int_state);

	power_supply_changed(charger->psy_otg);
	__pm_relax(charger->otg_ws);
}

static void max77775_check_slow_charging(struct max77775_charger_data *charger,
					int input_current)
{
	union power_supply_propval value = {0, };

	/* under 400mA considered as slow charging concept for VZW */
	if (input_current <= SLOW_CHARGING_CURRENT_STANDARD &&
	    !is_nocharge_type(charger->cable_type)) {
		charger->slow_charging = true;
		pr_info("%s: slow charging on : input current(%dmA), cable type(%d)\n",
		     __func__, input_current, charger->cable_type);

		psy_do_property("battery", set,	POWER_SUPPLY_PROP_CHARGE_TYPE, value);
	} else {
		charger->slow_charging = false;
	}
}

static void max77775_set_factory_mode(struct max77775_charger_data *charger)
{
	/* fmbst 0 */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07,
		0, CHG_CNFG_07_REG_FMBST_MASK);

	max77775_set_fw_noautoibus(MAX77775_AUTOIBUS_FW_AT_OFF);

	/* FG src change to vsys */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07,
		(0x01 << CHG_CNFG_07_REG_FGSRC_SHIFT),
		CHG_CNFG_07_REG_FGSRC_MASK);

	/* buck on, charge off */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
		MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);

	/* float voltage 4.4v */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_04,
		(0x1E << CHG_CNFG_04_CHG_CV_PRM_SHIFT),
		CHG_CNFG_04_CHG_CV_PRM_MASK);

	/* chginlim 3200mA */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09,
		0x7F, MAX77775_CHG_CHGIN_LIM);

	/* chgcc 267mA */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
		0x01, MAX77775_CHG_CC);

	/* disable AICL */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06,
		MAX77775_DIS_AICL << CHG_CNFG_06_DIS_AICL_SHIFT,
		CHG_CNFG_06_DIS_AICL_MASK);

	/* vchgin uvlo 4.7 */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
				0x00, CHG_CNFG_12_VCHGIN_REG_MASK);

	/* SPSN_DET set to 1 */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			MAX77775_SPSN_DET_ENABLE << CHG_CNFG_00_SPSN_DET_EN_SHIFT,
			CHG_CNFG_00_SPSN_DET_EN_MASK);

	factory_mode = 1;
	pr_info("%s : enter power on factory mode(523k)\n", __func__);
}

static void max77775_charger_initialize(struct max77775_charger_data *charger)
{
	u8 reg_data;
	int jig_gpio;

	pr_info("%s\n", __func__);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg_data);
	charger->cnfg00_mode = (reg_data & CHG_CNFG_00_MODE_MASK);

	/* unlock charger setting protect slowest LX slope
	 */
	reg_data = (0x03 << 2); // unlock
	reg_data |= 0x60; // slowest LX slop
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06, reg_data, reg_data);

	if (!max77775_get_facmode()) {
		/* If DIS_AICL is enabled(CNFG06[4]: 1) from factory_mode,
		 * clear to 0 to disable DIS_AICL
		 */
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_06,
				MAX77775_DIS_AICL << CHG_CNFG_06_DIS_AICL_SHIFT,
				CHG_CNFG_06_DIS_AICL_MASK);
	}

	/* fast charge timer disable
	 * restart threshold disable
	 * pre-qual charge disable
	 */
	reg_data = (MAX77775_FCHGTIME_DISABLE << CHG_CNFG_01_FCHGTIME_SHIFT) |
			(MAX77775_CHG_RSTRT_DISABLE << CHG_CNFG_01_CHG_RSTRT_SHIFT) |
			(MAX77775_CHG_VTRICKLE_EN_DISABLE << CHG_CNFG_01_VTRICKLE_EN_SHIFT);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_01, reg_data,
	(CHG_CNFG_01_FCHGTIME_MASK | CHG_CNFG_01_CHG_RSTRT_MASK | CHG_CNFG_01_VTRICKLE_EN_MASK));

	/* enalbe RECYCLE_EN for ocp */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_01,
			MAX77775_RECYCLE_EN_ENABLE << CHG_CNFG_01_RECYCLE_EN_SHIFT,
			CHG_CNFG_01_RECYCLE_EN_MASK);

	/* otg current limit 900mA */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
			MAX77775_OTG_ILIM_900 << CHG_CNFG_02_OTG_ILIM_SHIFT,
			CHG_CNFG_02_OTG_ILIM_MASK);

	/* UNO ILIM 1.0A */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05,
			MAX77775_UNOILIM_1000 << CHG_CNFG_05_REG_UNOILIM_SHIFT,
			CHG_CNFG_05_REG_UNOILIM_MASK);

	/* BAT to SYS OCP */
	max77775_set_b2sovrc(charger,
		charger->pdata->chg_ocp_current, charger->pdata->chg_ocp_dtc);

	/* top off current 150mA */
	reg_data = (MAX77775_TO_ITH_150MA << CHG_CNFG_03_TO_ITH_SHIFT) |
			(MAX77775_SYS_TRACK_DISABLE << CHG_CNFG_03_SYS_TRACK_DIS_SHIFT);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_03, reg_data,
	(CHG_CNFG_03_TO_ITH_MASK | CHG_CNFG_03_SYS_TRACK_DIS_MASK));

	/* topoff_time */
	max77775_set_topoff_time(charger, charger->pdata->topoff_time);

	/* cv voltage 4.2V or 4.35V */
	max77775_set_float_voltage(charger, charger->pdata->chg_float_voltage);

	if (!max77775_get_facmode()) {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);
		/* VCHGIN : REG=4.6V, UVLO=4.8V
		 * to fix CHGIN-UVLO issues including cheapy battery packs
		 */
		if (reg_data & MAX77775_CHGIN_OK) {
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
				0x08, CHG_CNFG_12_VCHGIN_REG_MASK);
		} else if (reg_data & MAX77775_WCIN_OK) {
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
				0x00, CHG_CNFG_12_VCHGIN_REG_MASK);
		} else {
			/* VCHGIN : REG=4.5V, UVLO=4.7V */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
				0x00, CHG_CNFG_12_VCHGIN_REG_MASK);
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
				0x00, CHG_CNFG_00_CHG_MASK);
			charger->cnfg00_mode &= ~CHG_CNFG_00_CHG_MASK;
		}
	}

	if (charger->jig_low_active)
		jig_gpio = !gpio_get_value(charger->jig_gpio);
	else
		jig_gpio = gpio_get_value(charger->jig_gpio);

	pr_info("%s: jig_gpio = %d\n", __func__, jig_gpio);

	if (charger->pdata->enable_dpm && charger->pdata->disqbat) {
		if (max77775_check_battery(charger)) {
			/* disqbat set to LOW (Qbat ON) */
			charger->bat_det = true;
			gpio_direction_output(charger->pdata->disqbat, 0);
		} else {
			/* disqbat set to HIGH (Qbat OFF) */
			charger->bat_det = false;
			gpio_direction_output(charger->pdata->disqbat, 1);
		}
		pr_info("%s: battery detection = %d\n", __func__, charger->bat_det);
	}

	if (max77775_get_facmode()) {
		/* fgsrc should depend on factory_mode since 301k and 619k do not triger jig_gpio */
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07,
				    (1 << CHG_CNFG_07_REG_FGSRC_SHIFT),
				    CHG_CNFG_07_REG_FGSRC_MASK);
		/* Watchdog Disable */
		max77775_chg_set_wdtmr_en(charger, 0);
	} else {
		/* fgsrc should depend on jig_gpio */
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_07,
			    (jig_gpio << CHG_CNFG_07_REG_FGSRC_SHIFT),
			    CHG_CNFG_07_REG_FGSRC_MASK);
		/* Watchdog Enable */
		max77775_chg_set_wdtmr_en(charger, 1);
	}

	/* THRM_DIS = 0 */
	max77775_update_reg(charger->pmic_i2c, MAX77775_PMIC_REG_MAINCTRL1, 0x00, 0x01);

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09,
			    MAX77775_CHG_EN, MAX77775_CHG_EN);

	/* VBYPSET=5.0V */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_11,
			0x00, CHG_CNFG_11_VBYPSET_MASK);

	/* Switching Frequency */
	max77775_set_switching_frequency(charger, charger->pdata->fsw);

	/* Auto skip mode */
	max77775_set_skipmode(charger, 1);

	/* disable shipmode */
	max77775_set_ship_mode(charger, 0);
	max77775_set_ship_exit_db(charger, 4000);

	/* disable auto shipmode, this should work under 2.6V */
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_13,
			    0x00 << CHG_CNFG_13_AUTOSHIP_TH_SHIFT,
			    CHG_CNFG_13_AUTOSHIP_TH_MASK);
	max77775_set_auto_ship_mode(charger, 0);
	max77775_set_ship_entry_db(charger, 192);

	max77775_test_read(charger);
}

static void max77775_set_sysovlo(struct max77775_charger_data *charger, int enable)
{
	u8 reg_data;

	max77775_read_reg(charger->pmic_i2c,
		MAX77775_PMIC_REG_SYSTEM_INT_MASK, &reg_data);

	reg_data = enable ? reg_data & 0xDF : reg_data | 0x20;
	max77775_write_reg(charger->pmic_i2c,
		MAX77775_PMIC_REG_SYSTEM_INT_MASK, reg_data);

	max77775_read_reg(charger->pmic_i2c,
		MAX77775_PMIC_REG_SYSTEM_INT_MASK, &reg_data);
	pr_info("%s: check topsys irq mask(0x%x), enable(%d)\n",
		__func__, reg_data, enable);
}

static void max77775_check_mode_status(struct max77775_charger_data *charger)
{
	union power_supply_propval val_status;

	psy_do_property("battery", get, POWER_SUPPLY_PROP_STATUS, val_status);

	if ((val_status.intval == POWER_SUPPLY_STATUS_FULL) &&
		!is_wireless_all_type(charger->cable_type)) {
		if (!charger->cv_mode_check) {
			charger->cv_mode_check = true;
			max77775_chg_set_mode_state(charger, charger->charge_mode);
		}
	} else if (charger->cv_mode_check) {
		charger->cv_mode_check = false;
		max77775_chg_set_mode_state(charger, charger->charge_mode);
	}
	pr_info("%s: cv_mode_check(%d)\n", __func__,
			charger->cv_mode_check ? 1 : 0);
}

static void max77775_chg_monitor_work(struct max77775_charger_data *charger)
{
	u8 reg_b2sovrc = 0, reg_mode = 0;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg_mode);
	reg_mode = (reg_mode & CHG_CNFG_00_MODE_MASK) >> CHG_CNFG_00_MODE_SHIFT;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05, &reg_b2sovrc);
	reg_b2sovrc =
		(reg_b2sovrc & CHG_CNFG_05_REG_B2SOVRC_MASK) >> CHG_CNFG_05_REG_B2SOVRC_SHIFT;

	pr_info("%s: [CHG] MODE(0x%x), B2SOVRC(0x%x), otg_on(%d)\n",
		__func__, reg_mode, reg_b2sovrc, charger->otg_on);

	/* protection code for sync with battery and charger driver */
	if (charger->pdata->enable_dpm && !charger->bat_det) {
		union power_supply_propval value = {0, };

		psy_do_property("battery", get, POWER_SUPPLY_EXT_PROP_MISC_EVENT, value);
		if (!(value.intval & DPM_MISC)) {
			/* disable thermal control */
			value.intval = 1;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_THERMAL_ZONE, value);

			/* set DPM misc event for PMS UI control */
			value.intval = DPM_MISC;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_MISC_EVENT, value);
		}
	}
	max77775_check_mode_status(charger);
}

static int max77775_chg_create_attrs(struct device *dev)
{
	int i, rc;

	for (i = 0; i < (int)ARRAY_SIZE(max77775_charger_attrs); i++) {
		rc = device_create_file(dev, &max77775_charger_attrs[i]);
		if (rc)
			goto create_attrs_failed;
	}
	return rc;

create_attrs_failed:
	dev_err(dev, "%s: failed (%d)\n", __func__, rc);
	while (i--)
		device_remove_file(dev, &max77775_charger_attrs[i]);
	return rc;
}

ssize_t max77775_chg_show_attrs(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct power_supply *psy = dev_get_drvdata(dev);
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	const ptrdiff_t offset = attr - max77775_charger_attrs;
	int i = 0;
	u8 addr, data;

	switch (offset) {
	case CHIP_ID:
		max77775_read_reg(charger->pmic_i2c, MAX77775_PMIC_REG_PMICID, &data);
		i += scnprintf(buf + i, PAGE_SIZE - i, "%x\n", data);
		break;
	case DATA:
		for (addr = 0xB1; addr <= 0xC8; addr++) {
			max77775_read_reg(charger->i2c, addr, &data);
			i += scnprintf(buf + i, PAGE_SIZE - i,
				       "0x%02x : 0x%02x\n", addr, data);
		}
		break;
	default:
		return -EINVAL;
	}
	return i;
}

ssize_t max77775_chg_store_attrs(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct power_supply *psy = dev_get_drvdata(dev);
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	const ptrdiff_t offset = attr - max77775_charger_attrs;
	int ret = 0;
	int x, y;

	switch (offset) {
	case CHIP_ID:
		ret = count;
		break;
	case DATA:
		if (sscanf(buf, "0x%8x 0x%8x", &x, &y) == 2) {
			if (x >= 0xB1 && x <= 0xC8) {
				u8 addr = x, data = y;

				if (max77775_write_reg(charger->i2c, addr, data) < 0)
					dev_info(charger->dev, "%s: addr: 0x%x write fail\n",
						__func__, addr);
			} else {
				dev_info(charger->dev, "%s: addr: 0x%x is wrong\n",
					__func__, x);
			}
		}
		ret = count;
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

static void max77775_set_uno(struct max77775_charger_data *charger, int en)
{
	u8 chg_int_state;
	u8 reg;

	if (charger->otg_on) {
		if (en) {
#if defined(CONFIG_WIRELESS_TX_MODE)
			union power_supply_propval value = {0, };
			psy_do_property("battery", get,
				POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ENABLE, value);
			if (value.intval) {
				pr_info("%s: OTG ON, then skip UNO Control\n", __func__);
				value.intval = BATT_TX_EVENT_WIRELESS_TX_ETC;
				psy_do_property("wireless", set, POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ERR, value);
				return;
			}
#endif
		}
	}

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg);
	if (en && (reg & MAX77775_WCIN_OK)) {
		pr_info("%s: WCIN is already valid by wireless charging, then skip UNO Control\n",
			__func__);
		return;
	}

	if (en == SEC_BAT_CHG_MODE_UNO_ONLY) {
		charger->uno_on = true;
		max77775_set_charge_path(charger, WCIN_SEL, WCIN_SEL);
		charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
				charger->cnfg00_mode, CHG_CNFG_00_MODE_MASK);
	} else if (en) {
		charger->uno_on = true;
		/* UNO on, boost on */
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_UNO_ON);
	} else {
		charger->uno_on = false;
		/* boost off */
		max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_UNO_OFF);
		msleep(50);
	}
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_MASK, &chg_int_state);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg);
	pr_info("%s: UNO(%d), INT_MASK(0x%x), CHG_CNFG_00(0x%x)\n",
		__func__, charger->uno_on, chg_int_state, reg);
}

static void max77775_set_uno_iout(struct max77775_charger_data *charger, int iout)
{
	u8 reg = 0;

	if (iout < 800)
		reg = MAX77775_UNOILIM_600;
	else if (iout >= 800 && iout < 1000)
		reg = MAX77775_UNOILIM_800;
	else if (iout >= 1000 && iout < 1200)
		reg = MAX77775_UNOILIM_1000;
	else if (iout >= 1200 && iout < 1400)
		reg = MAX77775_UNOILIM_1200;
	else if (iout >= 1400 && iout < 1600)
		reg = MAX77775_UNOILIM_1400;
	else if (iout >= 1600 && iout < 2000)
		reg = MAX77775_UNOILIM_1600;
	else if (iout >= 2000)
		reg = MAX77775_UNOILIM_2000;

	if (reg)
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05,
				reg << CHG_CNFG_05_REG_UNOILIM_SHIFT,
				CHG_CNFG_05_REG_UNOILIM_MASK);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_05, &reg);
	pr_info("@Tx_mode %s: CNFG_05 (0x%x)\n", __func__, reg);
}

static void max77775_set_uno_vout(struct max77775_charger_data *charger, int vout)
{
	u8 reg = 0;

	if (vout == WC_TX_VOUT_OFF) {
		pr_info("%s: set UNO default\n", __func__);
	} else {
		if (vout < WC_TX_VOUT_MIN) {
			pr_err("%s: vout(%d) is lower than min\n", __func__, vout);
			vout = WC_TX_VOUT_MIN;
		} else if (vout > WC_TX_VOUT_MAX) {
			pr_err("%s: vout(%d) is higher than max\n", __func__, vout);
			vout = WC_TX_VOUT_MAX;
		}
		/* Set TX Vout(VBYPSET) */
		if (vout <= 5000)
			reg = 0;
		else
			reg = (vout - 5000) / 50;
		pr_info("%s: UNO VOUT (0x%x)\n", __func__, reg);
	}
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_11,
				reg, CHG_CNFG_11_VBYPSET_MASK);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_11, &reg);
	pr_info("@Tx_mode %s: CNFG_11(0x%x)\n", __func__, reg);
}

static int max77775_chg_get_property(struct power_supply *psy,
					enum power_supply_property psp,
					union power_supply_propval *val)
{
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp = (enum power_supply_ext_property) psp;
	u8 reg_data;

	if (atomic_read(&charger->shutdown_cnt) > 0) {
		dev_info(charger->dev, "%s: charger already shutdown\n", __func__);
		return -EINVAL;
	}

	switch ((int)psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = SEC_BATTERY_CABLE_NONE;
		if (!max77775_read_reg(charger->i2c,
				      MAX77775_CHG_REG_INT_OK, &reg_data)) {
			if (reg_data & MAX77775_WCIN_OK) {
#if defined(CONFIG_USE_POGO)
				val->intval = SEC_BATTERY_CABLE_POGO;
#else
				val->intval = SEC_BATTERY_CABLE_WIRELESS;
#endif
			} else if (reg_data & MAX77775_CHGIN_OK) {
				val->intval = SEC_BATTERY_CABLE_TA;
			}
		}
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = max77775_check_battery(charger);
		break;
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = max77775_get_charger_state(charger);
		break;
	case POWER_SUPPLY_PROP_CHARGE_TYPE:
		if (!charger->is_charging) {
			val->intval = POWER_SUPPLY_CHARGE_TYPE_NONE;
		} else if (charger->slow_charging) {
			val->intval = POWER_SUPPLY_CHARGE_TYPE_TRICKLE;
			pr_info("%s: slow-charging mode\n", __func__);
		} else {
			val->intval = POWER_SUPPLY_CHARGE_TYPE_FAST;
		}
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = max77775_get_charging_health(charger);
		max77775_check_cnfg12_reg(charger);
		break;
	case POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT:
		val->intval = charger->input_current;
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT:
		val->intval = charger->charging_current;
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE:
		val->intval = max77775_get_float_voltage(charger);
		break;
	case POWER_SUPPLY_PROP_CHARGE_NOW:
		max77775_read_reg(charger->i2c,
				  MAX77775_CHG_REG_DETAILS_01, &reg_data);
		reg_data &= 0x0F;
		switch (reg_data) {
		case 0x01:
			val->strval = "CC Mode";
			break;
		case 0x02:
			val->strval = "CV Mode";
			break;
		case 0x03:
			val->strval = "EOC";
			break;
		case 0x04:
			val->strval = "DONE";
			break;
		default:
			val->strval = "NONE";
			break;
		}
		break;
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_WDT_STATUS:
			if (max77775_chg_get_wdtmr_status(charger)) {
				dev_info(charger->dev, "charger WDT is expired!!\n");
				max77775_test_read(charger);
			}
			break;
		case POWER_SUPPLY_EXT_PROP_CHIP_ID:
			if (!max77775_read_reg(charger->i2c,
					MAX77775_PMIC_REG_PMICREV, &reg_data)) {
				/* pmic_ver should below 0x7 */
				val->intval =
					(charger->pmic_ver >= 0x1 && charger->pmic_ver <= 0x7);
				pr_info("%s : IF PMIC ver.0x%x\n", __func__,
					charger->pmic_ver);
			} else {
				val->intval = 0;
				pr_info("%s : IF PMIC I2C fail.\n", __func__);
			}
			break;
		case POWER_SUPPLY_EXT_PROP_MONITOR_WORK:
			max77775_test_read(charger);
			max77775_chg_monitor_work(charger);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGE_BOOST:
			max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg_data);
			reg_data &= CHG_CNFG_00_MODE_MASK;
			val->intval = (reg_data & MAX77775_MODE_BOOST) ? 1 : 0;
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGE_OTG_CONTROL:
			mutex_lock(&charger->charger_mutex);
			val->intval = charger->otg_on;
			mutex_unlock(&charger->charger_mutex);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGE_COUNTER_SHADOW:
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGING_ENABLED:
			val->intval = charger->charge_mode;
			break;
		case POWER_SUPPLY_EXT_PROP_SHIPMODE_TEST:
#if defined(CONFIG_SUPPORT_SHIP_MODE)
			val->intval = max77775_get_ship_mode(charger);
			pr_info("%s: ship mode is %d\n", __func__, val->intval);
#else
			val->intval = 0;
			pr_info("%s: ship mode is not supported\n", __func__);
#endif
			break;
		case POWER_SUPPLY_EXT_PROP_INPUT_CURRENT_LIMIT_WRL:
			val->intval = max77775_get_input_current_type(charger, SEC_BATTERY_CABLE_WIRELESS);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGER_IC_NAME:
			val->strval = "MAX77775";
			break;
		case POWER_SUPPLY_EXT_PROP_SPSN_TEST:
			/* MODE set to 0 */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
					0, CHG_CNFG_00_MODE_MASK);

			/* SPSN_DET set to 1 */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
					MAX77775_SPSN_DET_ENABLE << CHG_CNFG_00_SPSN_DET_EN_SHIFT,
					CHG_CNFG_00_SPSN_DET_EN_MASK);

			/* delay for DTLS_00 update */
			msleep(50);

			/* read SPSN_DTLS */
			max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);
			reg_data = (reg_data & MAX77775_SPSN_DTLS) >> MAX77775_SPSN_DTLS_SHIFT;

			/* return test result */
			val->intval = reg_data;

			/* read CNFG_00 for check test condition */
			max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg_data);
			pr_info("%s: SPSN_DTLS (0x%x), CNFG_00 (0x%x)\n", __func__, val->intval, reg_data);

			/* restore SPSN_DET */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
				    MAX77775_SPSN_DET_DISABLE << CHG_CNFG_00_SPSN_DET_EN_SHIFT,
				    CHG_CNFG_00_SPSN_DET_EN_MASK);

			/* restore MODE */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
				charger->cnfg00_mode, CHG_CNFG_00_MODE_MASK);
			break;
		case POWER_SUPPLY_EXT_PROP_FACTORY_MODE:
			break;
		case POWER_SUPPLY_EXT_PROP_ARI_CNT:
			val->intval = charger->ari_cnt;
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static bool is_timeout(int total_time)
{
	if (total_time <= 0) {
		pr_info("%s: timeout for load step down\n", __func__);
		return true;
	}

	return false;
}

static bool escape_load_step_down(bool is_otg_on, int wc_status)
{
	if (!is_otg_on || is_nocharge_type(wc_status)) {
		pr_info("%s: Disconnect OTG or Wirless charging\n", __func__);
		return true;
	}

	return false;
}

static void set_otg_boost_before_load_step_down(struct i2c_client *i2c)
{
	u8 reg = 0;

	max77775_update_reg(i2c, MAX77775_CHG_REG_CNFG_00,
		MAX77775_MODE_A_BOOST_OTG_ON, CHG_CNFG_00_MODE_MASK);
	pr_info("%s: Set 0xA temporarily before 0xF\n", __func__);
	max77775_read_reg(i2c, MAX77775_CHG_REG_CNFG_00, &reg);
	pr_info("%s: CNFG_00 (0x%x)\n", __func__, reg);
}

/* check vout for 0xA mode
 */
static bool do_step1(int vout)
{
	if (vout > 0)
		return false;

	return true;
}

/* wait WC type for BPP / EPP type for EPP
 */
static bool do_step2(char *wireless_charger_name, int wc_status)
{
	union power_supply_propval op_mode = {0, };

	if (!is_wireless_fake_type(wc_status))
		return false;

	psy_do_property(wireless_charger_name, get,
		POWER_SUPPLY_EXT_PROP_WIRELESS_OP_MODE, op_mode);
	if (op_mode.intval == 0x2) /* EPP : 0x2. Should be checked operation mode register of rx ic */
		return false;

	return true;
}

/* wait to reduce input current
 */
#define MIN_ICL MINIMUM_INPUT_CURRENT
static bool do_step3(int icl)
{
	if (icl <= MIN_ICL)
		return false;

	return true;
}

/* wait to reduce input voltage
 */
static bool do_step4(int vout, int vout_condition)
{
	if (vout <= vout_condition)
		return false;

	return true;
}

static bool load_step_down_before_wcin_otg(struct max77775_charger_data *charger)
{
	union power_supply_propval read_vout = {0, }, set_vout = {0, }, wc_status = {0, };
	int total_time = 20000;
	int vout_condition = 0;
	char *wireless_charger_name = charger->pdata->wireless_charger_name;
	u8 reg = 0;

	pr_info("%s\n", __func__);

	psy_do_property(wireless_charger_name, get,
		POWER_SUPPLY_PROP_ENERGY_NOW, read_vout);
	if (do_step1(read_vout.intval)) {
		if (charger->cnfg00_mode != MAX77775_MODE_A_BOOST_OTG_ON)
			set_otg_boost_before_load_step_down(charger->i2c);
		total_time += 5000;
	}

	psy_do_property("wireless", get,
		POWER_SUPPLY_EXT_PROP_WIRELESS_WC_STATUS, wc_status);
	while (do_step2(wireless_charger_name, wc_status.intval)) {
		if (escape_load_step_down(charger->otg_on, wc_status.intval))
			goto skip_load_step_down;
		if (is_timeout(total_time))
			goto skip_load_step_down;

		pr_info("%s: Set 0xF mode after 200ms\n", __func__);
		msleep(200);
		total_time -= 200;
		psy_do_property("wireless", get,
			POWER_SUPPLY_EXT_PROP_WIRELESS_WC_STATUS, wc_status);
	}

	do {
		psy_do_property("wireless", get,
			POWER_SUPPLY_EXT_PROP_WIRELESS_WC_STATUS, wc_status);

		if (escape_load_step_down(charger->otg_on, wc_status.intval))
			goto skip_load_step_down;

		if (max77775_get_input_current_type(charger, SEC_BATTERY_CABLE_WIRELESS) > 700) {
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_10,
				0x1B, MAX77775_CHG_WCIN_LIM);
			msleep(300);
			total_time -= 300;
		} else if (max77775_get_input_current_type(charger, SEC_BATTERY_CABLE_WIRELESS) > MIN_ICL) {
			max77775_update_reg(charger->i2c,
				MAX77775_CHG_REG_CNFG_10, 0x07, MAX77775_CHG_WCIN_LIM);
			msleep(300);
			total_time -= 300;
		}
	} while (do_step3(max77775_get_input_current_type(charger, SEC_BATTERY_CABLE_WIRELESS)));
	pr_info("%s: Finish to reduce input current\n", __func__);

	vout_condition = (4700 + 50);
	do {
		psy_do_property("wireless", get,
			POWER_SUPPLY_EXT_PROP_WIRELESS_WC_STATUS, wc_status);

		if (escape_load_step_down(charger->otg_on, wc_status.intval))
			goto skip_load_step_down;
		if (is_timeout(total_time))
			goto skip_load_step_down;

		psy_do_property(wireless_charger_name, get,
				POWER_SUPPLY_PROP_ENERGY_NOW, read_vout);
		pr_info("%s: Wireless charger Vout: %dmV\n", __func__, read_vout.intval);

		if (read_vout.intval > (9000 + 500)) {
			set_vout.intval = WIRELESS_VOUT_FORCE_9V;
			psy_do_property(wireless_charger_name, set,
				POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION, set_vout);
			msleep(300);
			total_time -= 300;
		} else {
			set_vout.intval = WIRELESS_VOUT_FORCE_4_7V;
			psy_do_property(wireless_charger_name, set,
				POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION, set_vout);
			msleep(300);
			total_time -= 300;
		}
	} while (do_step4(read_vout.intval, vout_condition));
	pr_info("%s: Finish to reduce input voltage\n", __func__);

	msleep(300);
	pr_info("%s: Finish to decrease load\n", __func__);

	return true;

skip_load_step_down:
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			charger->cnfg00_mode, CHG_CNFG_00_MODE_MASK);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg);
	pr_info("%s: CNFG_00 (0x%x)\n", __func__, reg);

	return false;
}

static void set_icl_wcin_otg_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =
	    container_of(work, struct max77775_charger_data, set_icl_wcin_otg_work.work);
	union power_supply_propval value = {0, };

	psy_do_property("wireless", set,
		POWER_SUPPLY_EXT_PROP_CHARGE_OTG_ICL_CONTROL, value);

	msleep(200);
	value.intval = WIRELESS_VOUT_FORCE_4_8V;
	psy_do_property(charger->pdata->wireless_charger_name, set,
		POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION, value);

	msleep(100);
	value.intval = WIRELESS_VOUT_FORCE_4_9V;
	psy_do_property(charger->pdata->wireless_charger_name, set,
		POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION, value);

	msleep(100);
	value.intval = WIRELESS_VOUT_FORCE_5V;
	psy_do_property(charger->pdata->wireless_charger_name, set,
		POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION, value);

	__pm_relax(charger->set_icl_wcin_otg_ws);
}

#if IS_ENABLED(CONFIG_WRL_MODE4_FG_SETTING)
static void max77775_chg_check_wireless_mode4(struct max77775_charger_data *charger)
{
	union power_supply_propval value = {0, };

	if (charger->cnfg00_mode == MAX77775_MODE_4_BUCK_ON && is_wireless_all_type(charger->cable_type)) {
		if (!is_wireless_mode_4_set) {
			is_wireless_mode_4_set = true;
			value.intval = 1;
			psy_do_property("max77775-fuelgauge", set, POWER_SUPPLY_EXT_PROP_WIRELESS_MODE_4, value);
		}
	} else if (is_wireless_mode_4_set) {
		is_wireless_mode_4_set = false;
		value.intval = 0;
		psy_do_property("max77775-fuelgauge", set, POWER_SUPPLY_EXT_PROP_WIRELESS_MODE_4, value);
	}
}
#endif

static void max77775_chg_set_mode_state(struct max77775_charger_data *charger,
					unsigned int state)
{
	u8 reg, prev_mode;

	if (state == SEC_BAT_CHG_MODE_CHARGING)
		charger->is_charging = true;
	else if (state == SEC_BAT_CHG_MODE_CHARGING_OFF ||
			state == SEC_BAT_CHG_MODE_BUCK_OFF)
		charger->is_charging = false;

	if (max77775_get_facmode() || charger->bypass_mode) {
		if (state == SEC_BAT_CHG_MODE_CHARGING ||
			state == SEC_BAT_CHG_MODE_CHARGING_OFF ||
			state == SEC_BAT_CHG_MODE_BUCK_OFF) {
			pr_info("%s: %s Skip set charger state\n", __func__,
				(charger->bypass_mode ? "bypass mode" : "Factory mode"));
			return;
		}
	}

	if (!charger->bat_det) {
		pr_info("%s : DPM, chg state force set to buck on, chg off\n", __func__);
		state = SEC_BAT_CHG_MODE_CHARGING_OFF;
		charger->is_charging = false;
	}


	mutex_lock(&charger->mode_mutex);
	pr_info("%s: current_mode(0x%x), state(%d)\n", __func__, charger->cnfg00_mode, state);
	prev_mode = charger->cnfg00_mode;
	switch (charger->cnfg00_mode) {
		/* all off */
	case MAX77775_MODE_0_ALL_OFF:
		if (state == SEC_BAT_CHG_MODE_CHARGING_OFF)
			charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		else if (state == SEC_BAT_CHG_MODE_CHARGING)
			charger->cnfg00_mode
				= charger->cv_mode_check ? MAX77775_MODE_7_BUCK_ON : MAX77775_MODE_5_BUCK_CHG_ON;
		else if (state == SEC_BAT_CHG_MODE_OTG_ON)
			charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		else if (state == SEC_BAT_CHG_MODE_UNO_ON)
			charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		break;
		/* buck only */
	case MAX77775_MODE_4_BUCK_ON:
		if (state == SEC_BAT_CHG_MODE_CHARGING)
			charger->cnfg00_mode
				= charger->cv_mode_check ? MAX77775_MODE_7_BUCK_ON : MAX77775_MODE_5_BUCK_CHG_ON;
		else if (state == SEC_BAT_CHG_MODE_BUCK_OFF)
			charger->cnfg00_mode = MAX77775_MODE_0_ALL_OFF;
		else if (state == SEC_BAT_CHG_MODE_OTG_ON) {
			if (is_wcin_type(charger->cable_type)) {
				if (load_step_down_before_wcin_otg(charger)) {
					max77775_set_charge_path(charger, WC_CHG_ALL_ON, WC_CHG_ALL_ON);
					max77775_chgrcv_ramp(false);
					msleep(50);
					charger->cnfg00_mode = MAX77775_MODE_E_BUCK_BOOST_OTG_ON;
				} else {
					charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
					pr_info("%s : Can not change mode to 0xE\n", __func__);
				}
			} else {
				charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
			}
		} else if (state == SEC_BAT_CHG_MODE_UNO_ON) {
			if (is_wired_type(charger->cable_type))
				charger->cnfg00_mode = MAX77775_MODE_C_BUCK_BOOST_UNO_ON;
			else
				charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		}
		break;
		/* buck, charger on */
	case MAX77775_MODE_5_BUCK_CHG_ON:
		if (state == SEC_BAT_CHG_MODE_BUCK_OFF)
			charger->cnfg00_mode = MAX77775_MODE_0_ALL_OFF;
		else if (state == SEC_BAT_CHG_MODE_CHARGING_OFF)
			charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		else if (state == SEC_BAT_CHG_MODE_OTG_ON) {
			if (load_step_down_before_wcin_otg(charger)) {
				charger->cnfg00_mode = MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON;
			} else {
				charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
				pr_info("%s : Can not change mode to 0xF\n", __func__);
			}
		}
		else if (state == SEC_BAT_CHG_MODE_UNO_ON)
			charger->cnfg00_mode = MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON;
		else if (charger->cv_mode_check && (state == SEC_BAT_CHG_MODE_CHARGING))
			charger->cnfg00_mode = MAX77775_MODE_7_BUCK_ON;
		break;
	case MAX77775_MODE_7_BUCK_ON:
		pr_info("%s : set 0x04 mode after 0x07 mode\n", __func__);
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			    MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);
		usleep_range(100, 200);
		if (state == SEC_BAT_CHG_MODE_BUCK_OFF)
			charger->cnfg00_mode = MAX77775_MODE_0_ALL_OFF;
		else if (state == SEC_BAT_CHG_MODE_CHARGING_OFF)
			charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		else if (state == SEC_BAT_CHG_MODE_OTG_ON)
			charger->cnfg00_mode = MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON;
		else if (state == SEC_BAT_CHG_MODE_UNO_ON)
			charger->cnfg00_mode = MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON;
		else if (!charger->cv_mode_check && (state == SEC_BAT_CHG_MODE_CHARGING))
			charger->cnfg00_mode = MAX77775_MODE_5_BUCK_CHG_ON;
		break;
	case MAX77775_MODE_8_BOOST_UNO_ON:
		if (state == SEC_BAT_CHG_MODE_CHARGING_OFF) {
			if (is_wired_type(charger->cable_type))
				charger->cnfg00_mode = MAX77775_MODE_C_BUCK_BOOST_UNO_ON;
		} else if (state == SEC_BAT_CHG_MODE_CHARGING) {
			max77775_set_charge_path(charger, WC_CHG_ALL_ON, WC_CHG_ALL_ON);
			max77775_chgrcv_ramp(false);
			msleep(50);
			charger->cnfg00_mode = MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON;
		} else if (state == SEC_BAT_CHG_MODE_UNO_OFF) {
			if (charger->charge_mode == SEC_BAT_CHG_MODE_BUCK_OFF)
				charger->cnfg00_mode = MAX77775_MODE_0_ALL_OFF;
			else
				charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		/* UNO -> UNO + OTG */
		} else if (state == SEC_BAT_CHG_MODE_OTG_ON)
			charger->cnfg00_mode = MAX77775_MODE_B_BOOST_OTG_UNO_ON;
		break;
	case MAX77775_MODE_A_BOOST_OTG_ON:
		if (state == SEC_BAT_CHG_MODE_CHARGING_OFF) {
			if (is_wcin_type(charger->cable_type)) {
				if (load_step_down_before_wcin_otg(charger)) {
					max77775_set_charge_path(charger, WC_CHG_ALL_ON, WC_CHG_ALL_ON);
					max77775_chgrcv_ramp(false);
					msleep(50);
					charger->cnfg00_mode = MAX77775_MODE_E_BUCK_BOOST_OTG_ON;
				} else {
					pr_info("%s : Can not change mode to 0xE\n", __func__);
				}
			}
		} else if (state == SEC_BAT_CHG_MODE_CHARGING) {
			if (load_step_down_before_wcin_otg(charger)) {
				max77775_set_charge_path(charger, WC_CHG_ALL_ON, WC_CHG_ALL_ON);
				max77775_chgrcv_ramp(false);
				msleep(50);
				charger->cnfg00_mode = MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON;
			} else {
				pr_info("%s : Can not change mode to 0xF\n", __func__);
			}
		} else if (state == SEC_BAT_CHG_MODE_OTG_OFF) {
			if (charger->charge_mode == SEC_BAT_CHG_MODE_BUCK_OFF)
				charger->cnfg00_mode = MAX77775_MODE_0_ALL_OFF;
			else
				charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		/* OTG -> OTG + UNO */
		} else if (state == SEC_BAT_CHG_MODE_UNO_ON)
			charger->cnfg00_mode = MAX77775_MODE_B_BOOST_OTG_UNO_ON;
		break;
	case MAX77775_MODE_B_BOOST_OTG_UNO_ON:
		/* OTG + UNO -> OTG */
		if (state == SEC_BAT_CHG_MODE_UNO_OFF)
			charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		/* OTG + UNO -> UNO */
		else if (state == SEC_BAT_CHG_MODE_OTG_OFF)
			charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		break;
	case MAX77775_MODE_C_BUCK_BOOST_UNO_ON:
		if (state == SEC_BAT_CHG_MODE_BUCK_OFF)
			charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		else if (state == SEC_BAT_CHG_MODE_CHARGING)
			charger->cnfg00_mode = MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON;
		else if (state == SEC_BAT_CHG_MODE_UNO_OFF)
			charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		/* UNO -> OTG + UNO */
		else if ((state == SEC_BAT_CHG_MODE_OTG_ON) && (!is_wired_type(charger->cable_type)))
			charger->cnfg00_mode = MAX77775_MODE_B_BOOST_OTG_UNO_ON;
		break;
	case MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON:
		if (state == SEC_BAT_CHG_MODE_BUCK_OFF) {
			charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		} else if (state == SEC_BAT_CHG_MODE_CHARGING_OFF) {
			if (is_wired_type(charger->cable_type))
				charger->cnfg00_mode = MAX77775_MODE_C_BUCK_BOOST_UNO_ON;
			else
				charger->cnfg00_mode = MAX77775_MODE_8_BOOST_UNO_ON;
		} else if (state == SEC_BAT_CHG_MODE_UNO_OFF) {
			charger->cnfg00_mode
				= charger->cv_mode_check ? MAX77775_MODE_7_BUCK_ON : MAX77775_MODE_5_BUCK_CHG_ON;
		} else if (state == SEC_BAT_CHG_MODE_OTG_ON) { /* UNO -> OTG */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			    MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);
			usleep_range(1000, 2000);
			/* mode 0x4, and 1msec delay, and then otg on */
			charger->cnfg00_mode = MAX77775_MODE_E_BUCK_BOOST_OTG_ON;
		}

		if (charger->cnfg00_mode != MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON) {
			max77775_chgrcv_ramp(true);
			msleep(50);
		}
		break;
	case MAX77775_MODE_E_BUCK_BOOST_OTG_ON:
		if (state == SEC_BAT_CHG_MODE_BUCK_OFF)
			charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		else if (state == SEC_BAT_CHG_MODE_CHARGING_OFF) {
			if (!is_wcin_type(charger->cable_type))
				charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		}
		else if (state == SEC_BAT_CHG_MODE_CHARGING)
			charger->cnfg00_mode = MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON;
		else if (state == SEC_BAT_CHG_MODE_OTG_OFF)
			charger->cnfg00_mode = MAX77775_MODE_4_BUCK_ON;
		/* OTG -> OTG + UNO */
		else if ((state == SEC_BAT_CHG_MODE_UNO_ON) && (!is_wcin_type(charger->cable_type)))
			charger->cnfg00_mode = MAX77775_MODE_B_BOOST_OTG_UNO_ON;
		break;
	case MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON:
		if (state == SEC_BAT_CHG_MODE_CHARGING_OFF) {
			if (is_wcin_type(charger->cable_type))
				charger->cnfg00_mode = MAX77775_MODE_E_BUCK_BOOST_OTG_ON;
			else
				charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		} else if (state == SEC_BAT_CHG_MODE_BUCK_OFF) {
			charger->cnfg00_mode = MAX77775_MODE_A_BOOST_OTG_ON;
		} else if (state == SEC_BAT_CHG_MODE_OTG_OFF) {
			charger->cnfg00_mode
				= charger->cv_mode_check ? MAX77775_MODE_7_BUCK_ON : MAX77775_MODE_5_BUCK_CHG_ON;
		}

		if (charger->cnfg00_mode != MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON) {
			max77775_chgrcv_ramp(true);
			msleep(50);
		}
		break;
	}

	/* disable wcinsel, chginsel */
	if (charger->cnfg00_mode == MAX77775_MODE_0_ALL_OFF)
		max77775_set_charge_path(charger, WC_CHG_ALL_OFF, WC_CHG_ALL_OFF);
	else
		max77775_check_charge_path(charger);

	if (charger->cv_mode_check && (charger->cnfg00_mode == MAX77775_MODE_7_BUCK_ON)) {
		pr_info("%s : set 0x04 mode before 0x07 mode\n", __func__);
		max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			    MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);
		usleep_range(100, 200);
	}

	if (max77775_get_facmode())
		charger->cnfg00_mode |= MAX77775_MODE_4_BUCK_ON;

	pr_info("%s: prev(0x%x) -> current_mode(0x%x)\n", __func__, prev_mode, charger->cnfg00_mode);
	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
			charger->cnfg00_mode, CHG_CNFG_00_MODE_MASK);

#if IS_ENABLED(CONFIG_WRL_MODE4_FG_SETTING)
	if (charger->cnfg00_mode != prev_mode)
		max77775_chg_check_wireless_mode4(charger);
#endif

	if (((charger->cnfg00_mode == MAX77775_MODE_F_BUCK_CHG_BOOST_OTG_ON) &&
		((prev_mode == MAX77775_MODE_A_BOOST_OTG_ON) || (prev_mode == MAX77775_MODE_5_BUCK_CHG_ON))) ||
		((charger->cnfg00_mode == MAX77775_MODE_E_BUCK_BOOST_OTG_ON) &&
		((prev_mode == MAX77775_MODE_A_BOOST_OTG_ON) || (prev_mode == MAX77775_MODE_4_BUCK_ON)))) {
		if (delayed_work_pending(&charger->set_icl_wcin_otg_work)) {
			cancel_delayed_work(&charger->set_icl_wcin_otg_work);
			__pm_relax(charger->set_icl_wcin_otg_ws);
		}
		__pm_stay_awake(charger->set_icl_wcin_otg_ws);
		queue_delayed_work(charger->wqueue, &charger->set_icl_wcin_otg_work, 0);
	}

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, &reg);
	pr_info("%s: CNFG_00 (0x%x)\n", __func__, reg);
	mutex_unlock(&charger->mode_mutex);
}

static bool max77775_irq_enable(int irq, bool en)
{
	bool ret = false;

	if (irq <= 0)
		return ret;

	if (en && irqd_irq_disabled(&irq_to_desc(irq)->irq_data)) {
		enable_irq(irq);
		ret = true;
	} else if (!en && !irqd_irq_disabled(&irq_to_desc(irq)->irq_data)) {
		disable_irq_nosync(irq);
		ret = true;
	}
	pr_info("%s : irq: %d, en: %d, st: %d\n", __func__, irq, en,
		irqd_irq_disabled(&irq_to_desc(irq)->irq_data));

	return ret;
}

static void max77775_aicl_irq_enable(struct max77775_charger_data *charger,
				bool en)
{
	mutex_lock(&charger->irq_aicl_mutex);

	if (max77775_irq_enable(charger->irq_aicl, en)) {
		u8 reg_data = 0;

		max77775_read_reg(charger->i2c,
			MAX77775_CHG_REG_INT_MASK, &reg_data);
		pr_info("%s: %s aicl : 0x%x\n",
			__func__, en ? "enable" : "disable", reg_data);
	}

	mutex_unlock(&charger->irq_aicl_mutex);
}


#if defined(CONFIG_UPDATE_BATTERY_DATA)
static int max77775_charger_parse_dt(struct max77775_charger_data *charger);
#endif
static int max77775_chg_set_property(struct power_supply *psy,
					enum power_supply_property psp,
					const union power_supply_propval *val)
{
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp = (enum power_supply_ext_property) psp;
	u8 reg_data = 0;

	if (atomic_read(&charger->shutdown_cnt) > 0) {
		dev_info(charger->dev, "%s: charger already shutdown\n", __func__);
		return -EINVAL;
	}

	/* check unlock status before does set the register */
	max77775_charger_unlock(charger);
	switch ((int)psp) {
	/* val->intval : type */
	case POWER_SUPPLY_PROP_STATUS:
		charger->status = val->intval;
		break;
	case POWER_SUPPLY_PROP_CHARGE_TYPE:
#if defined(CONFIG_USE_POGO)
		{
			union power_supply_propval value = {0, };
			int pogo_state = 0;

			max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);
			pogo_state = (reg_data & MAX77775_WCIN_DTLS) >> MAX77775_WCIN_DTLS_SHIFT;

			value.intval = SEC_BATTERY_VBYP;
			psy_do_property("max77775-fuelgauge", get,
					POWER_SUPPLY_EXT_PROP_MEASURE_INPUT, value);

			pr_info("%s: pogo_state(%d), Vwcin(%d)\n", __func__, pogo_state, value.intval);

			if (pogo_state) {
				if (value.intval > 8000)
					value.intval = 2;
				else
					value.intval = 1;
			} else
				value.intval = 0;

			psy_do_property("pogo", set, POWER_SUPPLY_PROP_ONLINE, value);
		}
#endif
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		charger->cable_type = val->intval;
		charger->aicl_curr = 0;
		charger->slow_charging = false;
		charger->input_current = max77775_get_input_current(charger);
		max77775_check_charge_path(charger);
		if (!max77775_get_autoibus(charger))
			max77775_set_fw_noautoibus(MAX77775_AUTOIBUS_AT_OFF);

		if (charger->pdata->boosting_voltage_aicl)
			max77775_aicl_irq_enable(charger, true);

		if (is_nocharge_type(charger->cable_type)) {
			charger->wc_pre_current = WC_CURRENT_START;
			/* VCHGIN : REG=4.5V, UVLO=4.7V */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
			    0x00, CHG_CNFG_12_VCHGIN_REG_MASK);
			if (charger->pdata->enable_sysovlo_irq)
				max77775_set_sysovlo(charger, 1);

			if (!charger->pdata->boosting_voltage_aicl)
				max77775_aicl_irq_enable(charger, true);
		} else if (is_wired_type(charger->cable_type)) {
			/* VCHGIN : REG=4.6V, UVLO=4.8V
			 * to fix CHGIN-UVLO issues including cheapy battery packs
			 */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12,
				0x08, CHG_CNFG_12_VCHGIN_REG_MASK);
			if (is_hv_wire_type(charger->cable_type) ||
			(charger->cable_type == SEC_BATTERY_CABLE_HV_TA_CHG_LIMIT)) {
				if (!charger->pdata->boosting_voltage_aicl) {
					max77775_aicl_irq_enable(charger, false);
					cancel_delayed_work(&charger->aicl_work);
					__pm_relax(charger->aicl_ws);
				}
			}
		}
#if IS_ENABLED(CONFIG_WRL_MODE4_FG_SETTING)
		max77775_chg_check_wireless_mode4(charger);
#endif
		break;
		/* val->intval : input charging current */
	case POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT:
		{
			int input_current = val->intval;

			if (delayed_work_pending(&charger->aicl_work)) {
				cancel_delayed_work(&charger->aicl_work);
				charger->aicl_curr = 0;
				queue_delayed_work(charger->wqueue, &charger->aicl_work,
					msecs_to_jiffies(AICL_WORK_DELAY));
			}

			if (is_wireless_type(charger->cable_type))
				max77775_set_wireless_input_current(charger, input_current);
			else
				max77775_set_input_current(charger, input_current);

			charger->input_current = input_current;
		}
		break;
		/* val->intval : charging current */
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT:
		charger->charging_current = val->intval;
		max77775_set_charge_current(charger, val->intval);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE:
		charger->float_voltage = val->intval;
		pr_info("%s: float voltage(%d)\n", __func__, val->intval);
		max77775_set_float_voltage(charger, val->intval);
		break;
	case POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX:
		max77775_init_aicl_irq(charger);
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);
		if (!(reg_data & MAX77775_AICL_OK))
			queue_delayed_work(charger->wqueue, &charger->aicl_work,
					   msecs_to_jiffies(AICL_WORK_DELAY));
		break;
	case POWER_SUPPLY_PROP_CHARGE_TERM_CURRENT:
		max77775_set_topoff_current(charger, val->intval);
		break;
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_FACTORY_VOLTAGE_REGULATION:
			charger->float_voltage = val->intval;
			pr_info("%s: factory voltage regulation(%d)\n", __func__, val->intval);
			max77775_set_termination_voltage(charger, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_SURGE:
			if (val->intval) {
				pr_info("%s : Charger IC reset by surge. charger re-initialize\n",
					__func__);
				check_charger_unlock_state(charger);
			}
			break;
		case POWER_SUPPLY_EXT_PROP_CHGINSEL:
			if (val->intval == WL_TO_W)
				max77775_set_charge_path(charger, CHGIN_SEL, CHGIN_SEL);
			else
				max77775_check_charge_path(charger);
			break;
		case POWER_SUPPLY_EXT_PROP_PAD_VOLT_CTRL:
			break;
		case POWER_SUPPLY_EXT_PROP_SHIPMODE_TEST:
#if defined(CONFIG_SUPPORT_SHIP_MODE)
			if ((val->intval == SHIP_MODE_EN) || (val->intval == SHIP_MODE_EN_OP)) {
				pr_info("%s: set ship mode enable\n", __func__);
				max77775_set_ship_mode(charger, 1);
				max77775_set_bypass_auto_ship_en(charger, 1);
				max77775_set_auto_ship_mode(charger, 1);
				max77775_set_ship_entry_db(charger, 1);
			} else {
				pr_info("%s: ship mode disable is not supported\n", __func__);
			}
#else
			pr_info("%s: ship mode(%d) is not supported\n", __func__, val->intval);
#endif
			break;
		case POWER_SUPPLY_EXT_PROP_AUTO_SHIPMODE_CONTROL:
			if (val->intval) {
				pr_info("%s: auto ship mode is enabled\n", __func__);
				max77775_set_auto_ship_mode(charger, 1);
			} else {
				pr_info("%s: auto ship mode is disabled\n", __func__);
				max77775_set_auto_ship_mode(charger, 0);
			}
			break;
		case POWER_SUPPLY_EXT_PROP_FGSRC_SWITCHING:
			{
				u8 reg_data = 0, reg_fgsrc = 0;

				/* if jig attached, change the power source */
				/* from the VBATFG to the internal VSYS */
				if ((val->intval == SEC_BAT_INBAT_FGSRC_SWITCHING_VSYS) ||
					(val->intval == SEC_BAT_FGSRC_SWITCHING_VSYS))
					reg_fgsrc = 1;
				else
					reg_fgsrc = 0;

				max77775_update_reg(charger->i2c,
					MAX77775_CHG_REG_CNFG_07,
					(reg_fgsrc << CHG_CNFG_07_REG_FGSRC_SHIFT),
					CHG_CNFG_07_REG_FGSRC_MASK);
				max77775_read_reg(charger->i2c,
					MAX77775_CHG_REG_CNFG_07, &reg_data);

				pr_info("%s: POWER_SUPPLY_EXT_PROP_FGSRC_SWITCHING(%d): reg(0x%x) val(0x%x)\n",
					__func__, reg_fgsrc, MAX77775_CHG_REG_CNFG_07, reg_data);
			}
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGING_ENABLED:
			charger->charge_mode = val->intval;
			charger->misalign_cnt = 0;
			max77775_chg_set_mode_state(charger, charger->charge_mode);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGE_OTG_CONTROL:
			max77775_set_otg(charger, val->intval);
			break;
#if defined(CONFIG_UPDATE_BATTERY_DATA)
		case POWER_SUPPLY_EXT_PROP_POWER_DESIGN:
			max77775_charger_parse_dt(charger);
			break;
#endif
		case POWER_SUPPLY_EXT_PROP_CONSTANT_CHARGE_CURRENT_WRL:
			charger->charging_current = val->intval;
			__pm_stay_awake(charger->wc_chg_current_ws);
			queue_delayed_work(charger->wqueue, &charger->wc_chg_current_work,
				msecs_to_jiffies(0));
			break;
		case POWER_SUPPLY_EXT_PROP_CURRENT_MEASURE:
			pr_info("%s: keystring bypass mode is %s\n",
				__func__, val->intval ? "enable" : "disable");
			if (val->intval) {
				max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
					MAX77775_MODE_4_BUCK_ON, CHG_CNFG_00_MODE_MASK);
				max77775_set_input_current(charger, 3200);
				/* write 255k for bypass mode */
				max77775_usb_id_set(0x04);
#if !defined(CONFIG_SEC_FACTORY)
			} else
				max77775_bypass_maintain();
#else
			}
#endif
			break;
		case POWER_SUPPLY_EXT_PROP_INPUT_VOLTAGE_REGULATION:
			if (val->intval)
				max77775_set_bypass_mode(charger, 1);
			break;
		case POWER_SUPPLY_EXT_PROP_SPSN_TEST:
			max77775_set_spsn_det_res(charger, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_FACTORY_MODE:
			max77775_set_factory_mode(charger);
			break;
		case POWER_SUPPLY_EXT_PROP_ARI_CNT:
			if (charger->spcom) {
				charger->ari_cnt = val->intval;
				dev_info(charger->dev, "%s: ari cnt:%d\n",
						__func__, charger->ari_cnt);
			} else {
				charger->ari_cnt = -1;
				dev_info(charger->dev, "%s: not support ari cnt: %d\n",
					__func__, val->intval);
			}
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int max77775_otg_get_property(struct power_supply *psy,
				     enum power_supply_property psp,
				     union power_supply_propval *val)
{
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp = (enum power_supply_ext_property) psp;
	u8 reg_data;

	if (atomic_read(&charger->shutdown_cnt) > 0) {
		dev_info(charger->dev, "%s: charger already shutdown\n", __func__);
		return -EINVAL;
	}

	switch ((int)psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		mutex_lock(&charger->charger_mutex);
		val->intval = charger->otg_on;
		mutex_unlock(&charger->charger_mutex);
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		break;
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_CHARGE_UNO_CONTROL:
			max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00,
					  &reg_data);
			reg_data &= CHG_CNFG_00_MODE_MASK;
			if (reg_data == MAX77775_MODE_8_BOOST_UNO_ON ||
				reg_data == MAX77775_MODE_C_BUCK_BOOST_UNO_ON ||
				reg_data == MAX77775_MODE_D_BUCK_CHG_BOOST_UNO_ON)
				val->intval = 1;
			else
				val->intval = 0;
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int max77775_otg_set_property(struct power_supply *psy,
				     enum power_supply_property psp,
				     const union power_supply_propval *val)
{
	struct max77775_charger_data *charger = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp = (enum power_supply_ext_property) psp;
	bool mfc_fw_update = false;
	union power_supply_propval value = {0, };

	if (atomic_read(&charger->shutdown_cnt) > 0) {
		dev_info(charger->dev, "%s: charger already shutdown\n", __func__);
		return -EINVAL;
	}

	switch ((int)psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		psy_do_property("battery", get,
			POWER_SUPPLY_EXT_PROP_MFC_FW_UPDATE, value);
		mfc_fw_update = value.intval;
		if (!mfc_fw_update) {
			max77775_set_otg(charger, val->intval);
			if (val->intval) {
				max77775_aicl_irq_enable(charger, false);
				cancel_delayed_work(&charger->aicl_work);
				__pm_relax(charger->aicl_ws);
				charger->aicl_curr = 0;
				charger->slow_charging = false;
			} else if (!val->intval) {
				max77775_aicl_irq_enable(charger, true);
			}
		} else {
			pr_info("%s : max77775_set_otg skip, mfc_fw_update(%d)\n",
				__func__, mfc_fw_update);
		}
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		pr_info("POWER_SUPPLY_PROP_VOLTAGE_MAX, set otg current limit %dmA\n", (val->intval) ? 1500 : 900);

		if (val->intval) {
			charger->hp_otg = true;
			/* otg current limit 1500mA */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
					MAX77775_OTG_ILIM_1500 << CHG_CNFG_02_OTG_ILIM_SHIFT,
					CHG_CNFG_02_OTG_ILIM_MASK);
		} else {
			charger->hp_otg = false;
			/* otg current limit 900mA */
			max77775_update_reg(charger->i2c, MAX77775_CHG_REG_CNFG_02,
					MAX77775_OTG_ILIM_900 << CHG_CNFG_02_OTG_ILIM_SHIFT,
					CHG_CNFG_02_OTG_ILIM_MASK);
		}
		break;
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_WIRELESS_TX_VOUT:
			max77775_set_uno_vout(charger, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_WIRELESS_TX_IOUT:
			max77775_set_uno_iout(charger, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGE_UNO_CONTROL:
			pr_info("%s: WCIN-UNO %d\n", __func__, val->intval);
			max77775_set_uno(charger, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_OTG_VBUS_CTRL:
			pr_info("%s: OTG_VBUS_CTRL %d\n", __func__, val->intval);
			mutex_lock(&charger->charger_mutex);
			if (val->intval == TURN_OTG_ON) {
				max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_OTG_ON);
			} else if (val->intval == TURN_OTG_OFF) {
				max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_OTG_OFF);
			} else if (val->intval == TURN_RB_OFF) {
				value.intval = 0;
				psy_do_property("sec-direct-charger", set,
					POWER_SUPPLY_EXT_PROP_OTG_VBUS_CTRL, value);
			} else if (val->intval == TURN_RB_ON) {
				value.intval = 1;
				psy_do_property("sec-direct-charger", set,
					POWER_SUPPLY_EXT_PROP_OTG_VBUS_CTRL, value);
			} else if (val->intval == TURN_OTG_OFF_RB_ON) {
				max77775_chg_set_mode_state(charger, SEC_BAT_CHG_MODE_OTG_OFF);
				value.intval = 1;
				psy_do_property("sec-direct-charger", set,
					POWER_SUPPLY_EXT_PROP_OTG_VBUS_CTRL, value);
			} else {
				pr_info("%s: Unknown OTG_VBUS_CTRL %d\n", __func__, val->intval);
			}
			mutex_unlock(&charger->charger_mutex);
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int max77775_debugfs_show(struct seq_file *s, void *data)
{
	struct max77775_charger_data *charger = s->private;
	u8 reg, reg_data;

	seq_puts(s, "MAX77775 CHARGER IC :\n");
	seq_puts(s, "===================\n");
	for (reg = 0xB0; reg <= 0xC8; reg++) {
		max77775_read_reg(charger->i2c, reg, &reg_data);
		seq_printf(s, "0x%02x:\t0x%02x\n", reg, reg_data);
	}

	seq_puts(s, "\n");
	return 0;
}

static int max77775_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, max77775_debugfs_show, inode->i_private);
}

static const struct file_operations max77775_debugfs_fops = {
	.open = max77775_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void max77775_chg_isr_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =
	    container_of(work, struct max77775_charger_data, isr_work.work);

	max77775_get_charger_state(charger);
	max77775_get_charging_health(charger);
}

static irqreturn_t max77775_chg_irq_thread(int irq, void *irq_data)
{
	struct max77775_charger_data *charger = irq_data;

	pr_info("%s: Charger interrupt occurred\n", __func__);

	if ((charger->pdata->full_check_type == SEC_BATTERY_FULLCHARGED_CHGINT)
		|| (charger->pdata->ovp_uvlo_check_type == SEC_BATTERY_OVP_UVLO_CHGINT))
		schedule_delayed_work(&charger->isr_work, 0);

	return IRQ_HANDLED;
}

static irqreturn_t max77775_batp_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;
	union power_supply_propval value = {0, };
	u8 reg_data;

	pr_info("%s : irq(%d)\n", __func__, irq);

	check_charger_unlock_state(charger);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);

	if (charger->pdata->enable_dpm && charger->pdata->disqbat) {
		if (!(reg_data & MAX77775_BATP_OK)) {
			if (!charger->bat_det) {
				pr_info("%s : ignore duplicated irq(%d)\n", __func__, charger->bat_det);
				return IRQ_HANDLED;
			}

			/* disqbat set to HIGH (Qbat OFF) */
			charger->bat_det = false;
			gpio_direction_output(charger->pdata->disqbat, 1);

			/* disable thermal control */
			value.intval = 1;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_THERMAL_ZONE, value);

			/* set DPM misc event for PMS UI control */
			value.intval = DPM_MISC;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_MISC_EVENT, value);
		} else {
			if (charger->bat_det) {
				pr_info("%s : ignore duplicated irq(%d)\n", __func__, charger->bat_det);
				return IRQ_HANDLED;
			}

			/* fuelgauge reset before battery insertion control */
			value.intval = SEC_FUELGAUGE_CAPACITY_TYPE_RESET;
			psy_do_property("max77775-fuelgauge", set, POWER_SUPPLY_PROP_CAPACITY, value);
			pr_info("%s : do reset SOC for battery insertion control\n", __func__);

			/* disqbat set to LOW (Qbat ON) */
			charger->bat_det = true;
			gpio_direction_output(charger->pdata->disqbat, 0);

			/* enable thermal control */
			value.intval = 0;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_THERMAL_ZONE, value);

			/* set DPM misc event for PMS UI control */
			value.intval = DPM_MISC;
			psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_MISC_EVENT_CLEAR, value);
		}
		max77775_set_input_current(charger, charger->dpm_last_icl);
		max77775_chg_set_mode_state(charger, charger->charge_mode);
		pr_info("%s: battery_detect(%d)\n", __func__, charger->bat_det);
	} else {	/* original code that does not use DPM */
		if (!(reg_data & MAX77775_BATP_OK))
			psy_do_property("battery", set, POWER_SUPPLY_PROP_PRESENT, value);
	}
	return IRQ_HANDLED;
}

#if defined(CONFIG_MAX77775_CHECK_B2SOVRC)
#if defined(CONFIG_REGULATOR_S2MPS18)
extern void s2mps18_print_adc_val_power(void);
#endif
static irqreturn_t max77775_bat_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;
	union power_supply_propval value = {0, };
	u8 reg_int_ok, reg_data;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_int_ok);
	if (!(reg_int_ok & MAX77775_BAT_OK)) {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &reg_data);
		reg_data = ((reg_data & MAX77775_BAT_DTLS) >> MAX77775_BAT_DTLS_SHIFT);
		if (reg_data == 0x06) {
			pr_info("OCP(B2SOVRC)\n");

			if (charger->uno_on) {
#if defined(CONFIG_WIRELESS_TX_MODE)
				union power_supply_propval val;
				val.intval = BATT_TX_EVENT_WIRELESS_TX_OCP;
				psy_do_property("wireless", set,
					POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ERR, val);
#endif
			}
#if defined(CONFIG_REGULATOR_S2MPS18)
			s2mps18_print_adc_val_power();
#endif
			/* print vnow, inow */
			psy_do_property("max77775-fuelgauge", get,
				POWER_SUPPLY_EXT_PROP_FUELGAUGE_LOG, value);
		}
	} else {
		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_01, &reg_data);
		reg_data = ((reg_data & MAX77775_BAT_DTLS) >> MAX77775_BAT_DTLS_SHIFT);
		pr_info("%s: reg_data(0x%x)\n", __func__, reg_data);
	}
	check_charger_unlock_state(charger);

	return IRQ_HANDLED;
}
#endif

static irqreturn_t max77775_bypass_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;
#ifdef CONFIG_USB_HOST_NOTIFY
	struct otg_notify *o_notify;
#endif
	union power_supply_propval val;
	u8 dtls_02, byp_dtls;

	pr_info("%s: irq(%d)\n", __func__, irq);

	/* check and unlock */
	check_charger_unlock_state(charger);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_02, &dtls_02);

	byp_dtls = ((dtls_02 & MAX77775_BYP_DTLS) >> MAX77775_BYP_DTLS_SHIFT);
	pr_info("%s: BYP_DTLS(0x%02x)\n", __func__, byp_dtls);

	if (byp_dtls & 0x1) {
		pr_info("%s: bypass overcurrent limit\n", __func__);
		/* disable the register values just related to OTG and
		 * keep the values about the charging
		 */
		if (charger->otg_on) {
#ifdef CONFIG_USB_HOST_NOTIFY
			o_notify = get_otg_notify();
			if (o_notify)
				send_otg_notify(o_notify, NOTIFY_EVENT_OVERCURRENT, 0);
#endif
			val.intval = 0;
			psy_do_property("otg", set, POWER_SUPPLY_PROP_ONLINE, val);
		} else if (charger->uno_on) {
#if defined(CONFIG_WIRELESS_TX_MODE)
			val.intval = BATT_TX_EVENT_WIRELESS_TX_OCP;
			psy_do_property("wireless", set, POWER_SUPPLY_EXT_PROP_WIRELESS_TX_ERR, val);
#endif
		}
	}
	return IRQ_HANDLED;
}

static bool aicl_work_skip_condition(struct max77775_charger_data *charger)
{
	union power_supply_propval value = {0, };
	int hv_pdo = 0;
	int aicl_voter_value = 0;

	if (is_nocharge_type(charger->cable_type))
		return true;
	if (irqd_irq_disabled(&irq_to_desc(charger->irq_aicl)->irq_data))
		return true;

	psy_do_property("battery", get,
		POWER_SUPPLY_EXT_PROP_HV_PDO, value);
	hv_pdo = value.intval;
	if (hv_pdo) {
		pr_info("%s : skip because of hv_pdo\n", __func__);
		return true;
	}

	if (is_wireless_type(charger->cable_type) &&
		(charger->wc_pre_current > charger->wc_current)) {
		if (get_sec_voter_statusf("ICL", VOTER_AICL, &aicl_voter_value) < 0)
			return true;

		if (charger->wc_current < aicl_voter_value) {
			pr_info("%s : aicl voter(%dmA) is higher than other voter(%dmA), skip first."
					" aicl voter will be set when irq occurs again later\n",
					__func__, aicl_voter_value, charger->wc_current);
			return true;
		}
	}

	return false;
}

static void max77775_aicl_isr_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =
		container_of(work, struct max77775_charger_data, aicl_work.work);
	bool aicl_mode = false;
	u8 aicl_state = 0;
	int aicl_current = 0;

	if (aicl_work_skip_condition(charger)) {
		pr_info("%s: skip\n", __func__);
		charger->aicl_curr = 0;
		sec_votef("ICL", VOTER_AICL, false, 0);
		cancel_delayed_work(&charger->aicl_work);
		__pm_relax(charger->aicl_ws);
		return;
	}

	/* check and unlock */
	check_charger_unlock_state(charger);
	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &aicl_state);

	if (!(aicl_state & MAX77775_AICL_OK)) {
		/* AICL mode */
		pr_info("%s : AICL Mode : CHG_INT_OK(0x%02x)\n",
			__func__, aicl_state);

		mutex_lock(&charger->icl_mutex);
		cancel_delayed_work(&charger->wc_current_work);
		__pm_relax(charger->wc_current_ws);
		mutex_unlock(&charger->icl_mutex);

		charger->aicl_curr = reduce_input_current(charger);

		if (is_not_wireless_type(charger->cable_type))
			max77775_check_slow_charging(charger, charger->input_current);

		if (charger->input_current <= MINIMUM_INPUT_CURRENT) {
			max77775_aicl_irq_enable(charger, false);

			/* notify aicl current, no more aicl check */
			aicl_current = MINIMUM_INPUT_CURRENT;
		} else {
			aicl_mode = true;
			queue_delayed_work(charger->wqueue, &charger->aicl_work,
				msecs_to_jiffies(AICL_WORK_DELAY));
		}
	} else {
		/* Not in AICL mode */
		pr_info("%s : Not in AICL Mode : CHG_INT_OK(0x%02x), aicl_curr(%d)\n",
			__func__, aicl_state, charger->aicl_curr);
		if (charger->aicl_curr) {
			/* notify aicl current, if aicl is on and aicl state is cleard */
			aicl_current = charger->aicl_curr;
		}
	}

	if (aicl_current) {
		union power_supply_propval value = {0, };

		value.intval = aicl_current;
		psy_do_property("battery", set,
			POWER_SUPPLY_EXT_PROP_AICL_CURRENT, value);
	}

	/* keep wakeup_source if this is not last work to prevent to enter suspend */
	if (!aicl_mode && !delayed_work_pending(&charger->aicl_work))
		__pm_relax(charger->aicl_ws);
}

static irqreturn_t max77775_aicl_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;

	__pm_stay_awake(charger->aicl_ws);
	queue_delayed_work(charger->wqueue, &charger->aicl_work,
		msecs_to_jiffies(AICL_WORK_DELAY));

	pr_info("%s: irq(%d)\n", __func__, irq);

	return IRQ_HANDLED;
}

static void max77775_init_aicl_irq(struct max77775_charger_data *charger)
{
	int ret;

	charger->irq_aicl = charger->max77775_pdata->irq_base + MAX77775_CHG_IRQ_AICL_I;
	ret = request_threaded_irq(charger->irq_aicl, NULL,
					max77775_aicl_irq, 0,
					"aicl-irq", charger);
	if (ret < 0) {
		pr_err("%s: fail to request aicl IRQ: %d: %d\n",
		       __func__, charger->irq_aicl, ret);
	}
	pr_info("%s: %d\n", __func__, irqd_irq_disabled(&irq_to_desc(charger->irq_aicl)->irq_data));
}

static void max77775_wc_current_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =
		container_of(work, struct max77775_charger_data, wc_current_work.work);
	union power_supply_propval value = {0, };
	int diff_current = 0;

	if (is_not_wireless_type(charger->cable_type)) {
		charger->wc_pre_current = WC_CURRENT_START;
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_10, WC_DEFAULT_CURRENT);
		__pm_relax(charger->wc_current_ws);
		return;
	}

	if (charger->wc_pre_current == charger->wc_current) {
		max77775_set_input_current(charger, charger->wc_pre_current);
		max77775_set_charge_current(charger, charger->charging_current);
#if IS_ENABLED(CONFIG_DUAL_BATTERY)
		psy_do_property("battery", set,
			POWER_SUPPLY_EXT_PROP_FASTCHG_LIMIT_CURRENT, value);
#endif
		/* Wcurr-B) Restore Vrect adj room to previous value
		 *  after finishing wireless input current setting.
		 * Refer to Wcurr-A) step
		 */
		msleep(500);
		value.intval = WIRELESS_VRECT_ADJ_OFF; /* Vrect Room 0mV */
		psy_do_property(charger->pdata->wireless_charger_name, set,
				POWER_SUPPLY_EXT_PROP_WIRELESS_RX_CONTROL, value);
		/* keep wakeup_source if this is not last work to prevent to enter suspend */
		if (!delayed_work_pending(&charger->wc_current_work))
			__pm_relax(charger->wc_current_ws);
	} else {
		diff_current = charger->wc_pre_current - charger->wc_current;
		diff_current = (diff_current > charger->pdata->wc_current_step) ? charger->pdata->wc_current_step :
			((diff_current < -charger->pdata->wc_current_step) ? -charger->pdata->wc_current_step : diff_current);

		charger->wc_pre_current -= diff_current;
		max77775_set_input_current(charger, charger->wc_pre_current);
		__pm_stay_awake(charger->wc_current_ws);
		queue_delayed_work(charger->wqueue, &charger->wc_current_work,
				   msecs_to_jiffies(charger->otg_on ?
				   WC_CURRENT_WORK_STEP_OTG : WC_CURRENT_WORK_STEP));
	}
	pr_info("%s: wc_current(%d), wc_pre_current(%d), diff(%d)\n", __func__,
		charger->wc_current, charger->wc_pre_current, diff_current);
}

static void max77775_wc_chg_current_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =
		container_of(work, struct max77775_charger_data, wc_chg_current_work.work);
#if IS_ENABLED(CONFIG_DUAL_BATTERY)
	union power_supply_propval value = {0, };
#endif

	max77775_set_charge_current(charger, charger->charging_current);
#if IS_ENABLED(CONFIG_DUAL_BATTERY)
	psy_do_property("battery", set,
		POWER_SUPPLY_EXT_PROP_FASTCHG_LIMIT_CURRENT, value);
#endif
	__pm_relax(charger->wc_chg_current_ws);
}

#if defined(CONFIG_USE_POGO)
static void max77775_wcin_det_work(struct work_struct *work)
{
	struct max77775_charger_data *charger =	container_of(work,
				struct max77775_charger_data, wcin_det_work.work);
	u8 reg_data, wcin_state, wcin_dtls = 0;
	union power_supply_propval value = {0, }, val_vbyp = {0, };

	max77775_update_reg(charger->i2c,
				MAX77775_CHG_REG_INT_MASK, 0, MAX77775_WCIN_IM);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);
	wcin_state = (reg_data & MAX77775_WCIN_OK) >> MAX77775_WCIN_OK_SHIFT;

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_DETAILS_00, &reg_data);
	wcin_dtls = (reg_data & MAX77775_WCIN_DTLS) >> MAX77775_WCIN_DTLS_SHIFT;

	pr_info("%s wcin_state(%d) wcin_dtls(%d)\n", __func__, wcin_state, wcin_dtls);

	val_vbyp.intval = SEC_BATTERY_VBYP;
	psy_do_property("max77775-fuelgauge", get,
		POWER_SUPPLY_EXT_PROP_MEASURE_INPUT, val_vbyp);

	if (wcin_state && wcin_dtls) {
		if (val_vbyp.intval > 8000)
			value.intval = 2;
		else
			value.intval = 1;
	} else
		value.intval = 0;

	psy_do_property("pogo", set, POWER_SUPPLY_PROP_ONLINE, value);

	/* Do unmask again. (for frequent wcin irq problem) */
	max77775_update_reg(charger->i2c,
				MAX77775_CHG_REG_INT_MASK, 0, MAX77775_WCIN_IM);

	__pm_relax(charger->wcin_det_ws);
}

static irqreturn_t max77775_wcin_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;

	pr_info("%s: irq(%d)\n", __func__, irq);

	max77775_update_reg(charger->i2c, MAX77775_CHG_REG_INT_MASK,
			    MAX77775_WCIN_IM, MAX77775_WCIN_IM);
	__pm_stay_awake(charger->wcin_det_ws);
	queue_delayed_work(charger->wqueue, &charger->wcin_det_work,
			   msecs_to_jiffies(500));

	return IRQ_HANDLED;
}
#endif

static irqreturn_t max77775_sysovlo_irq(int irq, void *data)
{
	struct max77775_charger_data *charger = data;
	union power_supply_propval value = {0, };

	pr_info("%s\n", __func__);
	__pm_wakeup_event(charger->sysovlo_ws, jiffies_to_msecs(HZ * 5));

	psy_do_property("battery", set, POWER_SUPPLY_EXT_PROP_SYSOVLO, value);

	max77775_set_sysovlo(charger, 0);
	return IRQ_HANDLED;
}

#ifdef CONFIG_OF
static int max77775_charger_parse_dt(struct max77775_charger_data *charger)
{
	struct device_node *np;
	struct device_node *spss_region_dn;
	max77775_charger_platform_data_t *pdata = charger->pdata;
	int ret = 0;

	spss_region_dn = of_find_node_by_name(NULL, "qcom,spcom");
	if (spss_region_dn == NULL) {
#if IS_ENABLED(CONFIG_QCOM_SPSS)
		pr_info("[%s] coudln't find qcom,spcom, config enabled\n", __func__);
#else
		pr_info("[%s] coudln't find qcom,spcom\n", __func__);
#endif
		charger->spcom = false;
	} else {
		charger->spcom = true;
		pr_info("[%s] found spcom\n", __func__);
	}

	np = of_find_node_by_name(NULL, "battery");
	if (!np) {
		pr_err("%s: np(battery) NULL\n", __func__);
	} else {
		ret = of_property_read_u32(np, "battery,chg_float_voltage",
					   &pdata->chg_float_voltage);
		if (ret) {
			pr_info("%s: battery,chg_float_voltage is Empty\n", __func__);
			pdata->chg_float_voltage = 4200;
		}
		charger->float_voltage = pdata->chg_float_voltage;

		pdata->boosting_voltage_aicl = of_property_read_bool(np,
						     "battery,boosting_voltage_aicl");

		ret = of_property_read_u32(np, "battery,chg_ocp_current",
					   &pdata->chg_ocp_current);
		if (ret) {
			pr_info("%s: battery,chg_ocp_current is Empty\n", __func__);
			pdata->chg_ocp_current = 5600; /* mA */
		}

		ret = of_property_read_u32(np, "battery,chg_ocp_dtc",
					   &pdata->chg_ocp_dtc);
		if (ret) {
			pr_info("%s: battery,chg_ocp_dtc is Empty\n", __func__);
			pdata->chg_ocp_dtc = 6; /* ms */
		}

		ret = of_property_read_u32(np, "battery,topoff_time",
					   &pdata->topoff_time);
		if (ret) {
			pr_info("%s: battery,topoff_time is Empty\n", __func__);
			pdata->topoff_time = 30; /* min */
		}

		ret = of_property_read_string(np, "battery,wireless_charger_name",
					(char const **)&pdata->wireless_charger_name);
		if (ret)
			pr_info("%s: Wireless charger name is Empty\n", __func__);

		ret = of_property_read_u32(np, "battery,full_check_type_2nd",
					   &pdata->full_check_type_2nd);
		if (ret)
			pr_info("%s : Full check type 2nd is Empty\n", __func__);

		ret = of_property_read_u32(np, "battery,wireless_cc_cv",
						&pdata->wireless_cc_cv);
		if (ret)
			pr_info("%s : wireless_cc_cv is Empty\n", __func__);

		ret = of_property_read_u32(np, "battery,nv_wc_headroom",
								&pdata->nv_wc_headroom);
		if (ret) {
			pr_info("%s : nv_wc_headroom is Empty\n", __func__);
			pdata->nv_wc_headroom = WIRELESS_VRECT_ADJ_ROOM_1; /* 277mV */
		}

		pr_info("%s: fv : %d, ocp_curr : %d, ocp_dtc : %d, topoff_time : %d\n",
				__func__, charger->float_voltage, pdata->chg_ocp_current,
				pdata->chg_ocp_dtc, pdata->topoff_time);
	}

	np = of_find_node_by_name(NULL, "max77775-charger");
	if (!np) {
		pr_err("%s: np(max77775-charger) NULL\n", __func__);
	} else {
		ret = of_property_read_u32(np, "charger,fac_vsys", &pdata->fac_vsys);
		if (ret) {
			pr_info("%s : fac_vsys is Empty\n", __func__);
			pdata->fac_vsys = 3800; /* mV */
		}
#if defined(CONFIG_SEC_FACTORY)
		pdata->factory_wcin_irq =
		    of_property_read_bool(np, "charger,factory_wcin_irq");
#endif
		pdata->user_wcin_irq =
		    of_property_read_bool(np, "charger,user_wcin_irq");

		pdata->enable_sysovlo_irq =
		    of_property_read_bool(np, "charger,enable_sysovlo_irq");

		pdata->enable_noise_wa =
		    of_property_read_bool(np, "charger,enable_noise_wa");

		pdata->enable_dpm =
		    of_property_read_bool(np, "charger,enable_dpm");

		if (of_property_read_u32(np, "charger,dpm_icl", &pdata->dpm_icl)) {
			pr_info("%s : dpm_icl is Empty\n", __func__);
			pdata->dpm_icl = 1800;
		}

		pdata->disqbat = of_get_named_gpio(np, "charger,disqbat", 0);
		if (pdata->disqbat < 0) {
			pr_info("%s : can't get disqbat\n", __func__);
			pdata->disqbat = 0;
		}
		pr_info("%s: pdata->disqbat %d\n", __func__, pdata->disqbat);

		if (of_property_read_u32(np, "charger,fsw", &pdata->fsw)) {
			pr_info("%s : fsw is Empty\n", __func__);
			pdata->fsw = MAX77775_CHG_FSW_1_5MHz;
		}
		charger->fsw_now = pdata->fsw;

		ret = of_property_read_u32(np, "charger,wc_current_step",
					   &pdata->wc_current_step);
		if (ret) {
			pr_info("%s: battery,wc_current_step is Empty\n", __func__);
			pdata->wc_current_step = WC_CURRENT_STEP; /* default 100mA */
			ret = 0;
		}

		pr_info("%s: fac_vsys:%d, fsw:%d, wc_current_step:%d\n", __func__,
			pdata->fac_vsys, pdata->fsw, pdata->wc_current_step);
	}

	np = of_find_node_by_name(NULL, "max77775-fuelgauge");
	if (!np) {
		pr_err("%s: np(max77775-fuelgauge) NULL\n", __func__);
	} else {
		charger->jig_low_active = of_property_read_bool(np,
						"fuelgauge,jig_low_active");
		charger->jig_gpio = of_get_named_gpio(np, "fuelgauge,jig_gpio", 0);
		if (charger->jig_gpio < 0) {
			pr_err("%s: error reading jig_gpio = %d\n",
				__func__, charger->jig_gpio);
			charger->jig_gpio = 0;
		}
	}

	return ret;
}
#endif

static const struct power_supply_desc max77775_charger_power_supply_desc = {
	.name = "max77775-charger",
	.type = POWER_SUPPLY_TYPE_UNKNOWN,
	.properties = max77775_charger_props,
	.num_properties = ARRAY_SIZE(max77775_charger_props),
	.get_property = max77775_chg_get_property,
	.set_property = max77775_chg_set_property,
	.no_thermal = true,
};

static char *max77775_otg_supply_list[] = {
	"otg",
};

static const struct power_supply_desc max77775_otg_power_supply_desc = {
	.name = "max77775-otg",
	.type = POWER_SUPPLY_TYPE_UNKNOWN,
	.properties = max77775_otg_props,
	.num_properties = ARRAY_SIZE(max77775_otg_props),
	.get_property = max77775_otg_get_property,
	.set_property = max77775_otg_set_property,
};

static int max77775_charger_probe(struct platform_device *pdev)
{
	struct max77775_dev *max77775 = dev_get_drvdata(pdev->dev.parent);
	struct max77775_platform_data *pdata = dev_get_platdata(max77775->dev);
	max77775_charger_platform_data_t *charger_data;
	struct max77775_charger_data *charger;
	struct power_supply_config charger_cfg = { };
	int ret = 0;
	u8 reg_data;

	pr_info("%s: max77775 Charger Driver Loading\n", __func__);

	charger = kzalloc(sizeof(*charger), GFP_KERNEL);
	if (!charger)
		return -ENOMEM;

	charger_data = kzalloc(sizeof(max77775_charger_platform_data_t), GFP_KERNEL);
	if (!charger_data) {
		ret = -ENOMEM;
		goto err_free;
	}

	mutex_init(&charger->charger_mutex);
	mutex_init(&charger->mode_mutex);
	mutex_init(&charger->icl_mutex);
	mutex_init(&charger->irq_aicl_mutex);

	charger->dev = &pdev->dev;
	charger->i2c = max77775->charger;
	charger->pmic_i2c = max77775->i2c;
	charger->pdata = charger_data;
	charger->aicl_curr = 0;
	charger->slow_charging = false;
	charger->otg_on = false;
	charger->uno_on = false;
	charger->max77775_pdata = pdata;
	charger->wc_pre_current = WC_CURRENT_START;
	charger->cable_type = SEC_BATTERY_CABLE_NONE;
	charger->hp_otg = false;
	charger->bypass_mode = false;
	charger->bat_det = true;
	charger->dpm_last_icl = 100;
	charger->cv_mode_check = false;
	charger->ari_cnt = 0;

	atomic_set(&charger->shutdown_cnt, 0);

#if defined(CONFIG_OF)
	ret = max77775_charger_parse_dt(charger);
	if (ret < 0)
		pr_err("%s not found charger dt! ret[%d]\n", __func__, ret);
#endif
#if IS_ENABLED(CONFIG_WRL_MODE4_FG_SETTING)
	is_wireless_mode_4_set = false;
#endif
	platform_set_drvdata(pdev, charger);

	max77775_charger_initialize(charger);

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);
	if (reg_data & MAX77775_WCIN_OK)
#if defined(CONFIG_USE_POGO)
		charger->cable_type = SEC_BATTERY_CABLE_POGO;
#else
		charger->cable_type = SEC_BATTERY_CABLE_WIRELESS;
#endif
	charger->input_current = max77775_get_input_current(charger);
	charger->charging_current = max77775_get_charge_current(charger);

	if (max77775_read_reg(max77775->i2c, MAX77775_PMIC_REG_PMICREV, &reg_data) < 0) {
		pr_err("device not found on this channel (this is not an error)\n");
		ret = -ENOMEM;
		goto err_pdata_free;
	} else {
		charger->pmic_ver = (reg_data & 0x7);
		pr_info("%s : device found : ver.0x%x\n", __func__, charger->pmic_ver);
	}

	(void)debugfs_create_file("max77775-regs",
				S_IRUGO, NULL, (void *)charger,
				  &max77775_debugfs_fops);

	charger->wqueue = create_singlethread_workqueue(dev_name(&pdev->dev));
	if (!charger->wqueue) {
		pr_err("%s: Fail to Create Workqueue\n", __func__);
		goto err_pdata_free;
	}
#if defined(CONFIG_USE_POGO)
	charger->wcin_det_ws = wakeup_source_register(&pdev->dev, "charger-wcin-det");
#endif
	charger->aicl_ws = wakeup_source_register(&pdev->dev, "charger-aicl");
	charger->wc_current_ws = wakeup_source_register(&pdev->dev, "charger->wc-current");
	charger->otg_ws = wakeup_source_register(&pdev->dev, "charger->otg");
	charger->wc_chg_current_ws = wakeup_source_register(&pdev->dev, "charger->wc-chg-current");
	charger->set_icl_wcin_otg_ws = wakeup_source_register(&pdev->dev, "charger->sec-icl-wcin-otg");

#if defined(CONFIG_USE_POGO)
	INIT_DELAYED_WORK(&charger->wcin_det_work, max77775_wcin_det_work);
#endif
	INIT_DELAYED_WORK(&charger->aicl_work, max77775_aicl_isr_work);
	INIT_DELAYED_WORK(&charger->wc_current_work, max77775_wc_current_work);
	INIT_DELAYED_WORK(&charger->wc_chg_current_work, max77775_wc_chg_current_work);
	INIT_DELAYED_WORK(&charger->set_icl_wcin_otg_work, set_icl_wcin_otg_work);

	charger_cfg.drv_data = charger;
	charger->psy_chg = power_supply_register(&pdev->dev,
				&max77775_charger_power_supply_desc, &charger_cfg);
	if (IS_ERR(charger->psy_chg)) {
		ret = PTR_ERR(charger->psy_chg);
		pr_err("%s: Failed to Register psy_chg(%d)\n", __func__, ret);
		goto err_power_supply_register;
	}

	charger->psy_otg = power_supply_register(&pdev->dev,
				  &max77775_otg_power_supply_desc, &charger_cfg);
	if (IS_ERR(charger->psy_otg)) {
		ret = PTR_ERR(charger->psy_otg);
		pr_err("%s: Failed to Register otg_chg(%d)\n", __func__, ret);
		goto err_power_supply_register_otg;
	}
	charger->psy_otg->supplied_to = max77775_otg_supply_list;
	charger->psy_otg->num_supplicants = ARRAY_SIZE(max77775_otg_supply_list);

	if (charger->pdata->chg_irq) {
		INIT_DELAYED_WORK(&charger->isr_work, max77775_chg_isr_work);

		ret = request_threaded_irq(charger->pdata->chg_irq, NULL,
				max77775_chg_irq_thread, 0,
				"charger-irq", charger);
		if (ret) {
			pr_err("%s: Failed to Request IRQ\n", __func__);
			goto err_irq;
		}

		ret = enable_irq_wake(charger->pdata->chg_irq);
		if (ret < 0)
			pr_err("%s: Failed to Enable Wakeup Source(%d)\n", __func__, ret);
	}

	max77775_read_reg(charger->i2c, MAX77775_CHG_REG_INT_OK, &reg_data);

	charger->irq_bypass = pdata->irq_base + MAX77775_CHG_IRQ_BYP_I;
	ret = request_threaded_irq(charger->irq_bypass, NULL,
					max77775_bypass_irq, 0,
					"bypass-irq", charger);
	if (ret < 0)
		pr_err("%s: fail to request bypass IRQ: %d: %d\n",
		       __func__, charger->irq_bypass, ret);

	charger->irq_batp = pdata->irq_base + MAX77775_CHG_IRQ_BATP_I;
	ret = request_threaded_irq(charger->irq_batp, NULL,
					max77775_batp_irq, 0,
					"batp-irq", charger);
	if (ret < 0)
		pr_err("%s: fail to request Battery Present IRQ: %d: %d\n",
		       __func__, charger->irq_batp, ret);

#if defined(CONFIG_MAX77775_CHECK_B2SOVRC)
	if ((sec_debug_get_debug_level() & 0x1) == 0x1) {
		/* only work for debug level is mid */
		charger->irq_bat = pdata->irq_base + MAX77775_CHG_IRQ_BAT_I;
		ret = request_threaded_irq(charger->irq_bat, NULL,
					   max77775_bat_irq, 0,
					   "bat-irq", charger);
		if (ret < 0)
			pr_err("%s: fail to request Battery IRQ: %d: %d\n",
				   __func__, charger->irq_bat, ret);
	}
#endif

#if defined(CONFIG_USE_POGO)
	if (charger->pdata->factory_wcin_irq || charger->pdata->user_wcin_irq) {
		charger->irq_wcin = pdata->irq_base + MAX77775_CHG_IRQ_WCIN_I;
		ret = request_threaded_irq(charger->irq_wcin,
					   NULL, max77775_wcin_irq,
					   IRQF_TRIGGER_FALLING, "wcin-irq", charger);
		if (ret < 0)
			pr_err("%s: fail to request wcin det IRQ: %d: %d\n",
				   __func__, charger->irq_wcin, ret);
	}
#endif

	if (charger->pdata->enable_sysovlo_irq) {
		charger->sysovlo_ws = wakeup_source_register(&pdev->dev, "max77775-sysovlo");
		/* Enable BIAS */
		max77775_update_reg(max77775->i2c, MAX77775_PMIC_REG_MAINCTRL1,
				    0x80, 0x80);
		/* set IRQ thread */
		charger->irq_sysovlo =
		    pdata->irq_base + MAX77775_SYSTEM_IRQ_SYSOVLO_INT;
		ret = request_threaded_irq(charger->irq_sysovlo, NULL,
						max77775_sysovlo_irq, 0,
						"sysovlo-irq", charger);
		if (ret < 0)
			pr_err("%s: fail to request sysovlo IRQ: %d: %d\n",
			       __func__, charger->irq_sysovlo, ret);
		enable_irq_wake(charger->irq_sysovlo);
	}

	ret = max77775_chg_create_attrs(&charger->psy_chg->dev);
	if (ret) {
		dev_err(charger->dev, "%s : Failed to max77775_chg_create_attrs\n", __func__);
		goto err_atts;
	}

	/* watchdog kick */
	max77775_chg_set_wdtmr_kick(charger);

	sec_chg_set_dev_init(SC_DEV_MAIN_CHG);

	pr_info("%s: MAX77775 Charger Driver Loaded\n", __func__);

	return 0;

err_atts:
	free_irq(charger->pdata->chg_irq, charger);
err_irq:
	power_supply_unregister(charger->psy_otg);
err_power_supply_register_otg:
	power_supply_unregister(charger->psy_chg);
err_power_supply_register:
	destroy_workqueue(charger->wqueue);
	wakeup_source_unregister(charger->sysovlo_ws);
	wakeup_source_unregister(charger->otg_ws);
	wakeup_source_unregister(charger->wc_current_ws);
	wakeup_source_unregister(charger->aicl_ws);
	wakeup_source_unregister(charger->wc_chg_current_ws);
	wakeup_source_unregister(charger->set_icl_wcin_otg_ws);
#if defined(CONFIG_USE_POGO)
	wakeup_source_unregister(charger->wcin_det_ws);
#endif
err_pdata_free:
	kfree(charger_data);
err_free:
	kfree(charger);

	return ret;
}

static int max77775_charger_remove(struct platform_device *pdev)
{
	struct max77775_charger_data *charger = platform_get_drvdata(pdev);

	pr_info("%s: ++\n", __func__);

	destroy_workqueue(charger->wqueue);

	if (charger->i2c) {
		u8 reg_data;

		reg_data = MAX77775_MODE_4_BUCK_ON;
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, reg_data);
		reg_data = 0x0F;
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09, reg_data);
		reg_data = 0x10;
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_10, reg_data);
		reg_data = 0x60;
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12, reg_data);
	} else {
		pr_err("%s: no max77775 i2c client\n", __func__);
	}

	if (charger->irq_sysovlo)
		free_irq(charger->irq_sysovlo, charger);
#if defined(CONFIG_USE_POGO)
	if (charger->irq_wcin)
		free_irq(charger->irq_wcin, charger);
#endif
	if (charger->pdata->chg_irq)
		free_irq(charger->pdata->chg_irq, charger);
	if (charger->psy_chg)
		power_supply_unregister(charger->psy_chg);
	if (charger->psy_otg)
		power_supply_unregister(charger->psy_otg);

	wakeup_source_unregister(charger->sysovlo_ws);
	wakeup_source_unregister(charger->otg_ws);
	wakeup_source_unregister(charger->wc_current_ws);
	wakeup_source_unregister(charger->aicl_ws);
	wakeup_source_unregister(charger->wc_chg_current_ws);
	wakeup_source_unregister(charger->set_icl_wcin_otg_ws);
#if defined(CONFIG_USE_POGO)
	wakeup_source_unregister(charger->wcin_det_ws);
#endif

	kfree(charger);

	pr_info("%s: --\n", __func__);

	return 0;
}

#if defined CONFIG_PM
static int max77775_charger_prepare(struct device *dev)
{
	struct max77775_charger_data *charger = dev_get_drvdata(dev);

	pr_info("%s\n", __func__);

	if ((charger->cable_type == SEC_BATTERY_CABLE_USB ||
		charger->cable_type == SEC_BATTERY_CABLE_TA)
		&& charger->input_current >= 500) {
		u8 reg_data;

		max77775_read_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09, &reg_data);
		reg_data &= MAX77775_CHG_CHGIN_LIM;
		max77775_usbc_icurr_autoibus_on(reg_data);
	}

	return 0;
}

static int max77775_charger_suspend(struct device *dev)
{
	return 0;
}

static int max77775_charger_resume(struct device *dev)
{
	return 0;
}

static void max77775_charger_complete(struct device *dev)
{
	struct max77775_charger_data *charger = dev_get_drvdata(dev);

	pr_info("%s\n", __func__);

	if (!max77775_get_autoibus(charger))
		max77775_set_fw_noautoibus(MAX77775_AUTOIBUS_AT_OFF);
}
#else
#define max77775_charger_prepare NULL
#define max77775_charger_suspend NULL
#define max77775_charger_resume NULL
#define max77775_charger_complete NULL
#endif

static void max77775_charger_shutdown(struct platform_device *pdev)
{
	struct max77775_charger_data *charger = platform_get_drvdata(pdev);

	pr_info("%s: ++\n", __func__);

	atomic_inc(&charger->shutdown_cnt);

	if (max77775_get_facmode())
		goto free_chg;	/* prevent SMPL during SMD ARRAY shutdown */

	if (charger->i2c) {
		u8 reg_data;

		reg_data = MAX77775_MODE_4_BUCK_ON;	/* Buck on, Charge off */
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_00, reg_data);
#if !defined(CONFIG_SEC_FACTORY)
		if ((is_wired_type(charger->cable_type))
			&& (charger->cable_type != SEC_BATTERY_CABLE_USB))
			reg_data = 0x3B;	/* CHGIN_ILIM 1500mA */
		else
#endif
			reg_data = 0x13;	/* CHGIN_ILIM 500mA */
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_09, reg_data);
		reg_data = 0x13;	/* WCIN_ILIM 500mA */
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_10, reg_data);
		reg_data = 0x60;	/* CHGINSEL/WCINSEL enable */
		max77775_write_reg(charger->i2c, MAX77775_CHG_REG_CNFG_12, reg_data);

#if defined(CONFIG_SHIPMODE_BY_VBAT) && !defined(CONFIG_SEC_FACTORY)
		/* case with stray voltage due to TA connection */
		if (!is_nocharge_type(charger->cable_type) || lpcharge) {
			if (max77775_check_current_level())
				max77775_check_auto_shipmode_level(charger, 2);
			else
				max77775_check_auto_shipmode_level(charger, 1);
		} else
			max77775_check_auto_shipmode_level(charger, 0);
#else
		max77775_set_auto_ship_mode(charger, 1);
#endif
	} else {
		pr_err("%s: no max77775 i2c client\n", __func__);
	}

free_chg:
	if (charger->irq_aicl)
		free_irq(charger->irq_aicl, charger);
	if (charger->irq_chgin)
		free_irq(charger->irq_chgin, charger);
	if (charger->irq_bypass)
		free_irq(charger->irq_bypass, charger);
	if (charger->irq_batp)
		free_irq(charger->irq_batp, charger);
#if defined(CONFIG_MAX77775_CHECK_B2SOVRC)
	if (charger->irq_bat)
		free_irq(charger->irq_bat, charger);
#endif
	if (charger->irq_sysovlo)
		free_irq(charger->irq_sysovlo, charger);
	if (charger->pdata->chg_irq) {
		free_irq(charger->pdata->chg_irq, charger);
		cancel_delayed_work(&charger->isr_work);
	}

	cancel_delayed_work(&charger->aicl_work);
	cancel_delayed_work(&charger->wc_current_work);
	cancel_delayed_work(&charger->wc_chg_current_work);
#if defined(CONFIG_USE_POGO)
	cancel_delayed_work(&charger->wcin_det_work);
#endif
	cancel_delayed_work(&charger->set_icl_wcin_otg_work);

	pr_info("%s: --\n", __func__);
}

static const struct dev_pm_ops max77775_charger_pm_ops = {
	.prepare = max77775_charger_prepare,
	.suspend = max77775_charger_suspend,
	.resume = max77775_charger_resume,
	.complete = max77775_charger_complete,
};

static struct platform_driver max77775_charger_driver = {
	.driver = {
		   .name = "max77775-charger",
		   .owner = THIS_MODULE,
#ifdef CONFIG_PM
		   .pm = &max77775_charger_pm_ops,
#endif
	},
	.probe = max77775_charger_probe,
	.remove = max77775_charger_remove,
	.shutdown = max77775_charger_shutdown,
};

static int __init max77775_charger_init(void)
{
	pr_info("%s:\n", __func__);
	return platform_driver_register(&max77775_charger_driver);
}

static void __exit max77775_charger_exit(void)
{
	platform_driver_unregister(&max77775_charger_driver);
}

module_init(max77775_charger_init);
module_exit(max77775_charger_exit);

MODULE_DESCRIPTION("Samsung MAX77775 Charger Driver");
MODULE_AUTHOR("Samsung Electronics");
MODULE_LICENSE("GPL");
