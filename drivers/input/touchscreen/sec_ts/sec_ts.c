/* drivers/input/touchscreen/sec_ts.c
 *
 * Copyright (C) 2011 Samsung Electronics Co., Ltd.
 * http://www.samsungsemi.com/
 *
 * Core file for Samsung TSC driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

struct sec_ts_data *tsp_info;

#include "sec_ts.h"

#ifdef CONFIG_SECURE_TOUCH
enum subsystem {
	TZ = 1,
	APSS = 3
};

#define TZ_BLSP_MODIFY_OWNERSHIP_ID 3
#endif

struct sec_ts_data *ts_dup;

#ifdef USE_POWER_RESET_WORK
static void sec_ts_reset_work(struct work_struct *work);
#endif
//static void sec_ts_read_info_work(struct work_struct *work);

#ifdef USE_OPEN_CLOSE
static int sec_ts_input_open(struct input_dev *dev);
static void sec_ts_input_close(struct input_dev *dev);
#endif

int sec_ts_read_information(struct sec_ts_data *ts);

#ifdef CONFIG_SECURE_TOUCH
static int sec_ts_change_pipe_owner(struct sec_ts_data *ts, enum subsystem subsystem)
{
	/* scm call disciptor */
	struct scm_desc desc;
	int ret = 0;

	/* number of arguments */
	desc.arginfo = SCM_ARGS(2);
	/* BLSPID (1 - 12) */
	desc.args[0] = ts->client->adapter->nr - 1;
	/* Owner if TZ or APSS */
	desc.args[1] = subsystem;

	ret = scm_call2(SCM_SIP_FNID(SCM_SVC_TZ, TZ_BLSP_MODIFY_OWNERSHIP_ID), &desc);
	if (ret) {
		dev_err(&ts->client->dev, "%s: ret: %d\n", __func__, ret);
		return ret;
	}

	dev_dbg(&ts->client->dev, "%s: return: %llu\n", __func__, desc.ret[0]);

	return desc.ret[0];
}

static irqreturn_t sec_ts_irq_thread(int irq, void *ptr);

static irqreturn_t secure_filter_interrupt(struct sec_ts_data *ts)
{
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		if (atomic_cmpxchg(&ts->secure_pending_irqs, 0, 1) == 0) {
			sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");

#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
			complete(&ts->st_irq_received);
#endif
		} else {
			dev_info(&ts->client->dev, "%s: pending irq:%d\n",
						__func__, (int)atomic_read(&ts->secure_pending_irqs));
		}

		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int secure_touch_clk_prepare_enable(struct sec_ts_data *ts)
{
	int ret;

	if (!ts->core_clk || !ts->iface_clk) {
		dev_err(&ts->client->dev, "%s: error clk\n", __func__);
		return -ENODEV;
	}

	ret = clk_prepare_enable(ts->core_clk);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: failed core clk\n", __func__);
		goto err_core_clk;
	}

	ret = clk_prepare_enable(ts->iface_clk);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: failed iface clk\n", __func__);
		goto err_iface_clk;
	}

	return 0;

err_iface_clk:
	clk_disable_unprepare(ts->core_clk);
err_core_clk:
	return -ENODEV;
}

static void secure_touch_clk_unprepare_disable(struct sec_ts_data *ts)
{
	if (!ts->core_clk || !ts->iface_clk) {
		dev_err(&ts->client->dev, "%s: error clk\n", __func__);
		return;
	}

	clk_disable_unprepare(ts->core_clk);
	clk_disable_unprepare(ts->iface_clk);
}

/**
 * Sysfs attr group for secure touch & interrupt handler for Secure world.
 * @atomic : syncronization for secure_enabled
 * @pm_runtime : set rpm_resume or rpm_ilde
 */
static ssize_t secure_touch_enable_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d", atomic_read(&ts->secure_enabled));
}

static ssize_t secure_touch_enable_store(struct device *dev,
			struct device_attribute *addr, const char *buf, size_t count)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
	int ret;
	unsigned long data;

	if (count > 2) {
		dev_err(&ts->client->dev,
			"%s: cmd length is over (%s,%d)!!\n",
			__func__, buf, (int)strlen(buf));
		return -EINVAL;
	}

	ret = kstrtoul(buf, 10, &data);
	if (ret != 0) {
		dev_err(&ts->client->dev, "%s: failed to read:%d\n",
					__func__, ret);
		return -EINVAL;
	}

	if (data == 1) {
		if (ts->reset_is_on_going) {
			dev_err(&ts->client->dev, "%s: reset is on going because i2c fail\n", __func__);
			return -EBUSY;
		}

		/* Enable Secure World */
		if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
			dev_err(&ts->client->dev, "%s: already enabled\n", __func__);
			return -EBUSY;
		}

		/* syncronize_irq -> disable_irq + enable_irq
		 * concern about timing issue.
		 */
		disable_irq(ts->client->irq);

		/* Fix normal active mode : idle mode is failed to i2c for 1 time */
		ret = sec_ts_fix_tmode(ts, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);
		if (ret < 0) {
			dev_err(&ts->client->dev, "%s: failed to fix tmode\n",
					__func__);
			return -EIO;
		}

		/* Release All Finger */
		sec_ts_unlocked_release_all_finger(ts);

		if (pm_runtime_get_sync(ts->client->adapter->dev.parent) < 0) {
			dev_err(&ts->client->dev, "%s: failed to get pm_runtime\n", __func__);
			return -EIO;
		}

		if (secure_touch_clk_prepare_enable(ts) < 0) {
			pm_runtime_put_sync(ts->client->adapter->dev.parent);
			dev_err(&ts->client->dev, "%s: failed to clk enable\n", __func__);
			return -ENXIO;
		}

		sec_ts_change_pipe_owner(ts, TZ);

		reinit_completion(&ts->secure_powerdown);
		reinit_completion(&ts->secure_interrupt);
#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
		reinit_completion(&ts->st_irq_received);
#endif
		atomic_set(&ts->secure_enabled, 1);
		atomic_set(&ts->secure_pending_irqs, 0);

		enable_irq(ts->client->irq);

		dev_info(&ts->client->dev, "%s: secure touch enable\n", __func__);
	} else if (data == 0) {
		/* Disable Secure World */
		if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_DISABLE) {
			dev_err(&ts->client->dev, "%s: already disabled\n", __func__);
			return count;
		}

		sec_ts_change_pipe_owner(ts, APSS);

		secure_touch_clk_unprepare_disable(ts);
		pm_runtime_put_sync(ts->client->adapter->dev.parent);
		atomic_set(&ts->secure_enabled, 0);

		sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");

		sec_ts_delay(10);

		sec_ts_irq_thread(ts->client->irq, ts);
		complete(&ts->secure_interrupt);
		complete(&ts->secure_powerdown);
#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
		complete(&ts->st_irq_received);
#endif

		dev_info(&ts->client->dev, "%s: secure touch disable\n", __func__);

		ret = sec_ts_release_tmode(ts);
		if (ret < 0) {
			dev_err(&ts->client->dev, "%s: failed to release tmode\n",
					__func__);
			return -EIO;
		}

	} else {
		dev_err(&ts->client->dev, "%s: unsupport value:%d\n", __func__, data);
		return -EINVAL;
	}

	return count;
}

#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
static int secure_get_irq(struct device *dev)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
	int val = 0;

	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_DISABLE) {
		dev_err(&ts->client->dev, "%s: disabled\n", __func__);
		return -EBADF;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, -1, 0) == -1) {
		dev_err(&ts->client->dev, "%s: pending irq -1\n", __func__);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, 1, 0) == 1)
		val = 1;

	dev_err(&ts->client->dev, "%s: pending irq is %d\n",
				__func__, atomic_read(&ts->secure_pending_irqs));

	complete(&ts->secure_interrupt);

	return val;
}
#endif

static ssize_t secure_touch_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
	int val = 0;

	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_DISABLE) {
		dev_err(&ts->client->dev, "%s: disabled\n", __func__);
		return -EBADF;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, -1, 0) == -1) {
		dev_err(&ts->client->dev, "%s: pending irq -1\n", __func__);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&ts->secure_pending_irqs, 1, 0) == 1)
		val = 1;

	dev_err(&ts->client->dev, "%s: pending irq is %d\n",
				__func__, atomic_read(&ts->secure_pending_irqs));

	complete(&ts->secure_interrupt);

	return snprintf(buf, PAGE_SIZE, "%u", val);
}

static ssize_t secure_ownership_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "1");
}

static DEVICE_ATTR(secure_touch_enable, (S_IRUGO | S_IWUSR | S_IWGRP),
				secure_touch_enable_show, secure_touch_enable_store);
static DEVICE_ATTR(secure_touch, S_IRUGO, secure_touch_show, NULL);

static DEVICE_ATTR(secure_ownership, S_IRUGO, secure_ownership_show, NULL);

static struct attribute *secure_attr[] = {
	&dev_attr_secure_touch_enable.attr,
	&dev_attr_secure_touch.attr,
	&dev_attr_secure_ownership.attr,
	NULL,
};

static struct attribute_group secure_attr_group = {
	.attrs = secure_attr,
};


static int secure_touch_init(struct sec_ts_data *ts)
{
	dev_info(&ts->client->dev, "%s\n", __func__);

	init_completion(&ts->secure_interrupt);
	init_completion(&ts->secure_powerdown);
#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
	init_completion(&ts->st_irq_received);
#endif

	ts->core_clk = clk_get(&ts->client->adapter->dev, "core_clk");
	if (IS_ERR_OR_NULL(ts->core_clk)) {
		dev_err(&ts->client->dev, "%s: failed to get core_clk: %ld\n",
					__func__, PTR_ERR(ts->core_clk));
		goto err_core_clk;
	}

	ts->iface_clk = clk_get(&ts->client->adapter->dev, "iface_clk");
	if (IS_ERR_OR_NULL(ts->iface_clk)) {
		dev_err(&ts->client->dev, "%s: failed to get iface_clk: %ld\n",
					__func__, PTR_ERR(ts->iface_clk));
		goto err_iface_clk;
	}

#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
	register_tui_hal_ts(&ts->input_dev->dev, &ts->secure_enabled,
						&ts->st_irq_received, secure_get_irq,
						secure_touch_enable_store);
#endif

	return 0;

err_iface_clk:
	clk_put(ts->core_clk);
err_core_clk:
	ts->core_clk = NULL;
	ts->iface_clk = NULL;

	return -ENODEV;
}

static void secure_touch_remove(struct sec_ts_data *ts)
{
	if (!IS_ERR_OR_NULL(ts->core_clk))
		clk_put(ts->core_clk);

	if (!IS_ERR_OR_NULL(ts->iface_clk))
		clk_put(ts->iface_clk);
}

static void secure_touch_stop(struct sec_ts_data *ts, bool stop)
{
	if (atomic_read(&ts->secure_enabled)) {
		atomic_set(&ts->secure_pending_irqs, -1);

		sysfs_notify(&ts->input_dev->dev.kobj, NULL, "secure_touch");

#if defined(CONFIG_TRUSTONIC_TRUSTED_UI)
		complete(&ts->st_irq_received);
#endif

		if (stop)
			wait_for_completion_interruptible(&ts->secure_powerdown);

		dev_info(&ts->client->dev, "%s: %d\n", __func__, stop);
	}
}
#endif

int sec_ts_i2c_write(struct sec_ts_data *ts, u8 reg, u8 *data, int len)
{
	u8 buf[I2C_WRITE_BUFFER_SIZE + 1];
	int ret;
	unsigned char retry;
	struct i2c_msg msg;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EBUSY;
	}
#endif
#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if (TRUSTEDUI_MODE_INPUT_SECURED & trustedui_get_current_mode()) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TRUSTED_UI is enabled!\n", __func__);
		return -EIO;
		}
#endif

	if (len > I2C_WRITE_BUFFER_SIZE) {
		dev_err(&ts->client->dev, "%s: len is larger than buffer size\n", __func__);
		return -EINVAL;
	}

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF\n", __func__);
		goto err;
	}

	buf[0] = reg;
	memcpy(buf + 1, data, len);

	msg.addr = ts->client->addr;
	msg.flags = 0;
	msg.len = len + 1;
	msg.buf = buf;
	mutex_lock(&ts->i2c_mutex);
	for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
		if ((ret = i2c_transfer(ts->client->adapter, &msg, 1)) == 1)
			break;

		if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
			dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
			mutex_unlock(&ts->i2c_mutex);
			goto err;
		}

		usleep_range(1 * 1000, 1 * 1000);

		if (retry > 1) {
			dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
			ts->comm_err_count++;
		}
	}

	mutex_unlock(&ts->i2c_mutex);

	if (retry == SEC_TS_I2C_RETRY_CNT) {
		dev_err(&ts->client->dev, "%s: I2C write over retry limit\n", __func__);
		ret = -EIO;
#ifdef USE_POR_AFTER_I2C_RETRY
		if (ts->probe_done && !ts->reset_is_on_going)
			schedule_delayed_work(&ts->reset_work, msecs_to_jiffies(TOUCH_RESET_DWORK_TIME));
#endif
	}

	if (ret == 1)
		return 0;
err:
	return -EIO;
}

int sec_ts_i2c_read(struct sec_ts_data *ts, u8 reg, u8 *data, int len)
{
	u8 buf[4];
	int ret;
	unsigned char retry;
	struct i2c_msg msg[2];
	int remain = len;

	if (!len) {
		dev_err(&ts->client->dev,
			"%s: I2c message length is wrong!\n", __func__);
		goto err;
	}
#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EBUSY;
	}
#endif
#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if (TRUSTEDUI_MODE_INPUT_SECURED & trustedui_get_current_mode()) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TRUSTED_UI is enabled!\n", __func__);
		return -EIO;
	}
#endif

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF\n", __func__);
		goto err;
	}

	buf[0] = reg;

	msg[0].addr = ts->client->addr;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = buf;

	msg[1].addr = ts->client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = data;

	mutex_lock(&ts->i2c_mutex);

	if (len <= ts->i2c_burstmax) {

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, msg, 2);
			if (ret == 2)
				break;
			usleep_range(1 * 1000, 1 * 1000);
			if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
				dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
				mutex_unlock(&ts->i2c_mutex);
				goto err;
			}

			if (retry > 1) {
				dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

	} else {
		/*
		 * I2C read buffer is 256 byte. do not support long buffer over than 256.
		 * So, try to seperate reading data about 256 bytes.
		 */

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, msg, 1);
			if (ret == 1)
				break;
			usleep_range(1 * 1000, 1 * 1000);
			if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
				dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
				mutex_unlock(&ts->i2c_mutex);
				goto err;
			}

			if (retry > 1) {
				dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

		do {
			if (remain > ts->i2c_burstmax)
				msg[1].len = ts->i2c_burstmax;
			else
				msg[1].len = remain;

			remain -= ts->i2c_burstmax;

			for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
				ret = i2c_transfer(ts->client->adapter, &msg[1], 1);
				if (ret == 1)
					break;
				usleep_range(1 * 1000, 1 * 1000);
				if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
					dev_err(&ts->client->dev, "%s: POWER_STATUS : OFF, retry:%d\n", __func__, retry);
					mutex_unlock(&ts->i2c_mutex);
					goto err;
				}

				if (retry > 1) {
					dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
					ts->comm_err_count++;
				}
			}

			msg[1].buf += msg[1].len;

		} while (remain > 0);

	}

	mutex_unlock(&ts->i2c_mutex);

	if (retry == SEC_TS_I2C_RETRY_CNT) {
		dev_err(&ts->client->dev, "%s: I2C read over retry limit\n", __func__);
		ret = -EIO;
#ifdef USE_POR_AFTER_I2C_RETRY
		if (ts->probe_done && !ts->reset_is_on_going)
			schedule_delayed_work(&ts->reset_work, msecs_to_jiffies(TOUCH_RESET_DWORK_TIME));
#endif

	}

	return ret;

err:
	return -EIO;
}

static int sec_ts_i2c_write_burst(struct sec_ts_data *ts, u8 *data, int len)
{
	int ret;
	int retry;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TUI is enabled\n", __func__);
		return -EBUSY;
	}
#endif

	mutex_lock(&ts->i2c_mutex);
	for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
		if ((ret = i2c_master_send(ts->client, data, len)) == len)
			break;

		usleep_range(1 * 1000, 1 * 1000);

		if (retry > 1) {
			dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
			ts->comm_err_count++;
		}
	}

	mutex_unlock(&ts->i2c_mutex);
	if (retry == SEC_TS_I2C_RETRY_CNT) {
		dev_err(&ts->client->dev, "%s: I2C write over retry limit\n", __func__);
		ret = -EIO;
	}

	return ret;
}

static int sec_ts_i2c_read_bulk(struct sec_ts_data *ts, u8 *data, int len)
{
	int ret;
	unsigned char retry;
	int remain = len;
	struct i2c_msg msg;

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		dev_err(&ts->client->dev,
			"%s: TSP no accessible from Linux, TUI is enabled\n", __func__);
		return -EBUSY;
	}
#endif

	msg.addr = ts->client->addr;
	msg.flags = I2C_M_RD;
	msg.len = len;
	msg.buf = data;

	mutex_lock(&ts->i2c_mutex);

	do {
		if (remain > ts->i2c_burstmax)
			msg.len = ts->i2c_burstmax;
		else
			msg.len = remain;

		remain -= ts->i2c_burstmax;

		for (retry = 0; retry < SEC_TS_I2C_RETRY_CNT; retry++) {
			ret = i2c_transfer(ts->client->adapter, &msg, 1);
			if (ret == 1)
				break;
			usleep_range(1 * 1000, 1 * 1000);

			if (retry > 1) {
				dev_err(&ts->client->dev, "%s: I2C retry %d\n", __func__, retry + 1);
				ts->comm_err_count++;
			}
		}

	if (retry == SEC_TS_I2C_RETRY_CNT) {
		dev_err(&ts->client->dev, "%s: I2C read over retry limit\n", __func__);
		ret = -EIO;

		break;
	}
		msg.buf += msg.len;

	} while (remain > 0);

	mutex_unlock(&ts->i2c_mutex);

	if (ret == 1)
		return 0;

	return -EIO;
}
static int sec_ts_read_from_sponge(struct sec_ts_data *ts, u8 *data)
{
	int ret;

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_READ_PARAM, data, 2);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: fail to read sponge command\n", __func__);

	ret = sec_ts_i2c_read(ts, SEC_TS_CMD_SPONGE_READ_PARAM, (u8 *)data, sizeof((u8 *)(data)));
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: fail to read sponge command\n", __func__);

	return ret;
}

#if defined(CONFIG_TOUCHSCREEN_DUMP_MODE)
#include <linux/sec_debug.h>
extern struct tsp_dump_callbacks dump_callbacks;
static struct delayed_work *p_ghost_check;

static void sec_ts_check_rawdata(struct work_struct *work)
{
	struct sec_ts_data *ts = container_of(work, struct sec_ts_data, ghost_check.work);

	if (ts->tsp_dump_lock == 1) {
		dev_err(&ts->client->dev, "%s: ignored ## already checking..\n", __func__);
		return;
	}
	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: ignored ## IC is power off\n", __func__);
		return;
	}

	ts->tsp_dump_lock = 1;
	dev_info(&ts->client->dev, "%s: start ##\n", __func__);
	sec_ts_run_rawdata_all((void *)ts);
	msleep(100);

	dev_info(&ts->client->dev, "%s: done ##\n", __func__);
	ts->tsp_dump_lock = 0;

}

static void dump_tsp_log(void)
{
	pr_info("%s: %s %s: start\n", SEC_TS_I2C_NAME, SECLOG, __func__);

#ifdef CONFIG_BATTERY_SAMSUNG
	if (lpcharge == 1) {
		pr_err("%s: %s %s: ignored ## lpm charging Mode!!\n", SEC_TS_I2C_NAME, SECLOG, __func__);
		return;
	}
#endif

	if (p_ghost_check == NULL) {
		pr_err("%s: %s %s: ignored ## tsp probe fail!!\n", SEC_TS_I2C_NAME, SECLOG, __func__);
		return;
	}
	schedule_delayed_work(p_ghost_check, msecs_to_jiffies(100));
}
#endif


void sec_ts_delay(unsigned int ms)
{
	if (ms < 20)
		usleep_range(ms * 1000, ms * 1000);
	else
		msleep(ms);
}

int sec_ts_wait_for_ready(struct sec_ts_data *ts, unsigned int ack)
{
	int rc = -1;
	int retry = 0;
	u8 tBuff[SEC_TS_EVENT_BUFF_SIZE] = {0,};

	while (sec_ts_i2c_read(ts, SEC_TS_READ_ONE_EVENT, tBuff, SEC_TS_EVENT_BUFF_SIZE)) {
		if (((tBuff[0] >> 2) & 0xF) == TYPE_STATUS_EVENT_INFO) {
			if (tBuff[1] == ack) {
				rc = 0;
				break;
			}
		} else if (((tBuff[0] >> 2) & 0xF) == TYPE_STATUS_EVENT_VENDOR_INFO) {
			if (tBuff[1] == ack) {
				rc = 0;
				break;
			}
		}

		if (retry++ > SEC_TS_WAIT_RETRY_CNT) {
			dev_err(&ts->client->dev, "%s: Time Over\n", __func__);
			break;
		}
		sec_ts_delay(20);
	}

	dev_info(&ts->client->dev,
		"%s: %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X [%d]\n",
		__func__, tBuff[0], tBuff[1], tBuff[2], tBuff[3],
		tBuff[4], tBuff[5], tBuff[6], tBuff[7], retry);

	return rc;
}

int sec_ts_read_calibration_report(struct sec_ts_data *ts)
{
	int ret;
	u8 buf[5] = { 0 };

	buf[0] = SEC_TS_READ_CALIBRATION_REPORT;

	ret = sec_ts_i2c_read(ts, buf[0], &buf[1], 4);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: failed to read, %d\n", __func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev, "%s: count:%d, pass count:%d, fail count:%d, status:0x%X\n",
				__func__, buf[1], buf[2], buf[3], buf[4]);

	return buf[4];
}

void sec_ts_reinit(struct sec_ts_data *ts)
{
	u8 w_data[2] = {0x00, 0x00};
	int ret = 0;
/*
	dev_info(&ts->client->dev,
				"%s : charger=0x%x, Cover=0x%x, Power mode=0x%x\n",
				__func__, ts->charger_mode, ts->touch_functions, ts->lowpower_status);
*/
	/* charger mode */
	if (ts->charger_mode != SEC_TS_BIT_CHARGER_MODE_NO) {
		w_data[0] = ts->charger_mode;
		ret = ts->sec_ts_i2c_write(ts, SET_TS_CMD_SET_CHARGER_MODE, (u8 *)&w_data[0], 1);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to send command(0x%x)",
						__func__, SET_TS_CMD_SET_CHARGER_MODE);
	}

	/* Cover mode */
	if (ts->touch_functions & SEC_TS_BIT_SETFUNC_COVER) {
		w_data[0] = ts->cover_cmd;
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_COVERTYPE, (u8 *)&w_data[0], 1);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to send command(0x%x)",
						__func__, SEC_TS_CMD_SET_COVERTYPE);

		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&(ts->touch_functions), 2);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to send command(0x%x)",
						__func__, SEC_TS_CMD_SET_TOUCHFUNCTION);
	}

	if (ts->use_sponge)
		sec_ts_set_custom_library(ts);

	/* Power mode */
/*	if (ts->lowpower_status == TO_LOWPOWER_MODE) {
		w_data[0] = (ts->lowpower_mode & SEC_TS_MODE_LOWPOWER_FLAG) >> 1;
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_WAKEUP_GESTURE_MODE, (u8 *)&w_data[0], 1);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to send command(0x%x)",
						__func__, SEC_TS_CMD_WAKEUP_GESTURE_MODE);

		w_data[0] = TO_LOWPOWER_MODE;
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_POWER_MODE, (u8 *)&w_data[0], 1);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to send command(0x%x)",
						__func__, SEC_TS_CMD_SET_POWER_MODE);

		sec_ts_delay(50);

		if (ts->lowpower_mode & SEC_TS_MODE_SPONGE_AOD) {
			int i, ret;
			u8 data[10] = {0x02, 0};
		
			for (i = 0; i < 4; i++) {
				data[i * 2 + 2] = ts->rect_data[i] & 0xFF;
				data[i * 2 + 3] = (ts->rect_data[i] >> 8) & 0xFF;
			}

			ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_WRITE_PARAM, &data[0], 10);
			if (ret < 0)
				dev_err(&ts->client->dev, "%s: Failed to write offset\n", __func__);
		
			ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_NOTIFY_PACKET, NULL, 0);
			if (ret < 0)
				dev_err(&ts->client->dev, "%s: Failed to send notify\n", __func__);

		}
*/
//	} else {

	sec_ts_set_grip_type(ts, ONLY_EDGE_HANDLER);

	if (ts->dex_mode) {
		dev_info(&ts->client->dev, "%s: set dex mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_DEX_MODE, &ts->dex_mode, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
					"%s: failed to set dex mode %x\n", __func__, ts->dex_mode);
	}

	if (ts->brush_mode) {
		dev_info(&ts->client->dev, "%s: set brush mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_BRUSH_MODE, &ts->brush_mode, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
					"%s: failed to set brush mode\n", __func__);
	}

	if (ts->touchable_area) {
		dev_info(&ts->client->dev, "%s: set 16:9 mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHABLE_AREA, &ts->touchable_area, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
					"%s: failed to set 16:9 mode\n", __func__);
	}

//	}
	return;
}

#define MAX_EVENT_COUNT 32
static void sec_ts_read_event(struct sec_ts_data *ts)
{
	int ret;
	u8 t_id;
	u8 event_id;
	u8 left_event_count;
	u8 read_event_buff[MAX_EVENT_COUNT][SEC_TS_EVENT_BUFF_SIZE] = { { 0 } };
	u8 *event_buff;
	struct sec_ts_event_coordinate *p_event_coord;
	struct sec_ts_gesture_status *p_gesture_status;
	struct sec_ts_event_status *p_event_status;
	int curr_pos;
	int remain_event_count = 0;
/*
	if (ts->power_status == SEC_TS_STATE_LPM) {

		wake_lock_timeout(&ts->wakelock, msecs_to_jiffies(3 * MSEC_PER_SEC));
		ret = wait_for_completion_interruptible_timeout(&ts->resume_done, msecs_to_jiffies(3 * MSEC_PER_SEC));
		if (ret == 0) {
			dev_err(&ts->client->dev, "%s: LPM: pm resume is not handled\n", __func__);
			return;
		}

		if (ret < 0) {
			dev_err(&ts->client->dev, "%s: LPM: -ERESTARTSYS if interrupted, %d\n", __func__, ret);
			return;
		}

		dev_info(&ts->client->dev, "%s: run LPM interrupt handler, %d\n", __func__, ret);
	}
*/
	ret = t_id = event_id = curr_pos = remain_event_count = 0;
	/* repeat READ_ONE_EVENT until buffer is empty(No event) */
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_ONE_EVENT, (u8 *)read_event_buff[0], SEC_TS_EVENT_BUFF_SIZE);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: i2c read one event failed\n", __func__);
		return;
	}

	if (ts->temp == 0x01)
		dev_info(&ts->client->dev, "ONE: %02X %02X %02X %02X %02X %02X %02X %02X\n",
			read_event_buff[0][0], read_event_buff[0][1], read_event_buff[0][2], read_event_buff[0][3],
			read_event_buff[0][4], read_event_buff[0][5], read_event_buff[0][6], read_event_buff[0][7]);

	if (read_event_buff[0][0] == 0) {
		dev_info(&ts->client->dev, "%s: event buffer is empty\n", __func__);
		return;
	}

	left_event_count = read_event_buff[0][7] & 0x1F;
	remain_event_count = left_event_count;

	if (left_event_count > MAX_EVENT_COUNT - 1) {
		dev_err(&ts->client->dev, "%s: event buffer overflow\n", __func__);

		/* write clear event stack command when read_event_count > MAX_EVENT_COUNT */
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_CLEAR_EVENT_STACK, NULL, 0);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: i2c write clear event failed\n", __func__);
		return;
	}

	if (left_event_count > 0) {
		ret = sec_ts_i2c_read(ts, SEC_TS_READ_ALL_EVENT, (u8 *)read_event_buff[1],
				sizeof(u8) * (SEC_TS_EVENT_BUFF_SIZE) * (left_event_count));
		if (ret < 0) {
			dev_err(&ts->client->dev, "%s: i2c read one event failed\n", __func__);
			return;
		}
	}

	do {
		event_buff = read_event_buff[curr_pos];
		event_id = event_buff[0] & 0x3;

		if (ts->temp == 0x01)
			dev_info(&ts->client->dev, "ALL: %02X %02X %02X %02X %02X %02X %02X %02X\n",
				event_buff[0], event_buff[1], event_buff[2], event_buff[3],
				event_buff[4], event_buff[5], event_buff[6], event_buff[7]);

		switch (event_id) {
		case SEC_TS_STATUS_EVENT:
			p_event_status = (struct sec_ts_event_status *)event_buff;

			/* tchsta == 0 && ttype == 0 && eid == 0 : buffer empty */
			if (p_event_status->stype > 0)
				dev_info(&ts->client->dev, "%s: STATUS %x %x %x %x %x %x %x %x\n", __func__,
						event_buff[0], event_buff[1], event_buff[2],
						event_buff[3], event_buff[4], event_buff[5],
						event_buff[6], event_buff[7]);

			/* watchdog reset -> send SENSEON command */ /*=>?????*/
			if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO) &&
				(p_event_status->status_id == SEC_TS_ACK_BOOT_COMPLETE) &&
				(p_event_status->status_data_1 == 0x20)) {

				sec_ts_unlocked_release_all_finger(ts);

				ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
				if (ret < 0)
					dev_err(&ts->client->dev, "%s: fail to write Sense_on\n", __func__);

				sec_ts_reinit(ts);
			}

			/* event queue full-> all finger release */
			if ((p_event_status->stype == TYPE_STATUS_EVENT_ERR) &&
				(p_event_status->status_id == SEC_TS_ERR_EVENT_QUEUE_FULL)) {
				dev_err(&ts->client->dev, "%s: IC Event Queue is full\n", __func__);
				sec_ts_unlocked_release_all_finger(ts);
			}

			if ((p_event_status->stype == TYPE_STATUS_EVENT_ERR) &&
				(p_event_status->status_id == SEC_TS_ERR_EVENT_ESD)) {
				dev_err(&ts->client->dev, "%s: ESD detected. run reset\n", __func__);
#ifdef USE_RESET_DURING_POWER_ON
				schedule_work(&ts->reset_work.work);
#endif
			}

			if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO) &&
				(p_event_status->status_id == SEC_TS_ACK_WET_MODE)) {
				ts->wet_mode = p_event_status->status_data_1;
				dev_info(&ts->client->dev, "%s: water wet mode %d\n",
					__func__, ts->wet_mode);
				if (ts->wet_mode)
					ts->wet_count++;

				}

			if ((p_event_status->stype == TYPE_STATUS_EVENT_SPONGE_INFO) &&
				(p_event_status->status_id == SEC_TS_EVENT_SPONGE_FORCE_KEY)) {
				if (ts->power_status == SEC_TS_STATE_POWER_ON) {
					if (p_event_status->status_data_1 & SEC_TS_SPONGE_EVENT_PRESSURE_TOUCHED) {
						ts->all_force_count++;
						ts->scrub_id = SPONGE_EVENT_TYPE_PRESSURE_TOUCHED;
					} else {
						if (ts->scrub_id == SPONGE_EVENT_TYPE_AOD_HOMEKEY_PRESS) {
							input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
							ts->scrub_id = SPONGE_EVENT_TYPE_AOD_HOMEKEY_RELEASE;
						} else {
							ts->scrub_id = SPONGE_EVENT_TYPE_PRESSURE_RELEASED;
						}
					}

//					input_report_key(ts->input_dev, KEY_BLACK_UI_GESTURE, 1);
				} else {
					if (p_event_status->status_data_1 & SEC_TS_SPONGE_EVENT_PRESSURE_RELEASED) {
						input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
//						input_report_key(ts->input_dev, KEY_BLACK_UI_GESTURE, 1);
						ts->scrub_id = SPONGE_EVENT_TYPE_AOD_HOMEKEY_RELEASE_NO_HAPTIC;
						input_sync(ts->input_dev);

						haptic_homekey_release();
					} else {
						input_report_key(ts->input_dev, KEY_HOMEPAGE, 1);
						input_sync(ts->input_dev);

						ts->scrub_id = SPONGE_EVENT_TYPE_AOD_HOMEKEY_PRESS;
						haptic_homekey_press();
						ts->all_force_count++;
					}
				}

				ts->scrub_x = ((p_event_status->status_data_4 >> 4) & 0xF) << 8 | (p_event_status->status_data_3 & 0xFF);
				ts->scrub_y = ((p_event_status->status_data_4 >> 0) & 0xF) << 8 | (p_event_status->status_data_2 & 0xFF);

#ifdef CONFIG_SAMSUNG_PRODUCT_SHIP
				dev_info(&ts->client->dev, "%s: PRESSURE[%d]\n", __func__, ts->scrub_id);
#else
				dev_info(&ts->client->dev, "%s: PRESSURE[%d %d %d]\n", __func__,
						ts->scrub_id, ts->scrub_x, ts->scrub_y);
#endif

				input_sync(ts->input_dev);
//				input_report_key(ts->input_dev, KEY_BLACK_UI_GESTURE, 0);
			}

			break;

		case SEC_TS_COORDINATE_EVENT:
			if (ts->input_closed) {
				dev_err(&ts->client->dev, "%s: device is closed\n", __func__);
				break;
			}
			p_event_coord = (struct sec_ts_event_coordinate *)event_buff;

			t_id = (p_event_coord->tid - 1);

			if (t_id < MAX_SUPPORT_TOUCH_COUNT + MAX_SUPPORT_HOVER_COUNT) {
				ts->coord[t_id].id = t_id;
				ts->coord[t_id].action = p_event_coord->tchsta;
				ts->coord[t_id].x = (p_event_coord->x_11_4 << 4) | (p_event_coord->x_3_0);
				ts->coord[t_id].y = (p_event_coord->y_11_4 << 4) | (p_event_coord->y_3_0);
				ts->coord[t_id].z = p_event_coord->z & 0x3F;
				ts->coord[t_id].ttype = p_event_coord->ttype_3_2 << 2 | p_event_coord->ttype_1_0 << 0;
				ts->coord[t_id].major = p_event_coord->major;
				ts->coord[t_id].minor = p_event_coord->minor;

				if (!ts->coord[t_id].palm && (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM))
					ts->coord[t_id].palm_count++;

				ts->coord[t_id].palm = (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM);
				ts->coord[t_id].left_event = p_event_coord->left_event;

				if (ts->coord[t_id].z <= 0)
					ts->coord[t_id].z = 1;

				if ((ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_NORMAL)
						|| (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_PALM)
						|| (ts->coord[t_id].ttype == SEC_TS_TOUCHTYPE_GLOVE)) {

					if (ts->coord[t_id].action == SEC_TS_COORDINATE_ACTION_RELEASE) {
						ktime_get_real_ts64(&ts->time_released[t_id]);
						
						if (ts->time_longest < (ts->time_released[t_id].tv_sec - ts->time_pressed[t_id].tv_sec))
							ts->time_longest = (ts->time_released[t_id].tv_sec - ts->time_pressed[t_id].tv_sec);

						input_mt_slot(ts->input_dev, t_id);
						if (ts->plat_data->support_mt_pressure)
							input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);

						if (ts->touch_count > 0)
							ts->touch_count--;
						if (ts->touch_count == 0) {
							input_report_key(ts->input_dev, BTN_TOUCH, 0);
							input_report_key(ts->input_dev, BTN_TOOL_FINGER, 0);
							ts->check_multi = 0;
						}

					} else if (ts->coord[t_id].action == SEC_TS_COORDINATE_ACTION_PRESS) {
						ktime_get_real_ts64(&ts->time_pressed[t_id]);

						ts->touch_count++;
						ts->all_finger_count++;

						ts->max_z_value = max((unsigned int)ts->coord[t_id].z, ts->max_z_value);
						ts->min_z_value = min((unsigned int)ts->coord[t_id].z, ts->min_z_value);
						ts->sum_z_value += (unsigned int)ts->coord[t_id].z;

						input_mt_slot(ts->input_dev, t_id);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 1);
						input_report_key(ts->input_dev, BTN_TOUCH, 1);
						input_report_key(ts->input_dev, BTN_TOOL_FINGER, 1);

						input_report_abs(ts->input_dev, ABS_MT_POSITION_X, ts->coord[t_id].x);
						input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, ts->coord[t_id].y);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, ts->coord[t_id].major);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MINOR, ts->coord[t_id].minor);
						if (ts->plat_data->support_mt_pressure)
							input_report_abs(ts->input_dev, ABS_MT_PRESSURE, ts->coord[t_id].z);

						if ((ts->touch_count > 4) && (ts->check_multi == 0)) {
							ts->check_multi = 1;
							ts->multi_count++;
						}

					} else if (ts->coord[t_id].action == SEC_TS_COORDINATE_ACTION_MOVE) {
						input_mt_slot(ts->input_dev, t_id);
						input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 1);
						input_report_key(ts->input_dev, BTN_TOUCH, 1);
						input_report_key(ts->input_dev, BTN_TOOL_FINGER, 1);

						input_report_abs(ts->input_dev, ABS_MT_POSITION_X, ts->coord[t_id].x);
						input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, ts->coord[t_id].y);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, ts->coord[t_id].major);
						input_report_abs(ts->input_dev, ABS_MT_TOUCH_MINOR, ts->coord[t_id].minor);

						if (ts->plat_data->support_mt_pressure)
							input_report_abs(ts->input_dev, ABS_MT_PRESSURE, ts->coord[t_id].z);
						ts->coord[t_id].mcount++;
					} else {
						dev_dbg(&ts->client->dev,
								"%s: do not support coordinate action(%d)\n", __func__, ts->coord[t_id].action);
					}
				} else {
					dev_dbg(&ts->client->dev,
							"%s: do not support coordinate type(%d)\n", __func__, ts->coord[t_id].ttype);
				}
			} else {
				dev_err(&ts->client->dev, "%s: tid(%d) is out of range\n", __func__, t_id);
			}
			break;

		case SEC_TS_GESTURE_EVENT:
			p_gesture_status = (struct sec_ts_gesture_status *)event_buff;
			if ((p_gesture_status->eid == 0x02) && (p_gesture_status->stype == 0x00)) {
				u8 sponge[3] = { 0 };

				ret = sec_ts_read_from_sponge(ts, sponge);
				if (ret < 0)
					dev_err(&ts->client->dev, "%s: fail to read sponge data\n", __func__);

				dev_info(&ts->client->dev, "%s: Sponge, %x, %x, %x\n",
							__func__, sponge[0], sponge[1], sponge[2]);

				if (p_gesture_status->gesture_id == SEC_TS_GESTURE_CODE_SPAY ||
					p_gesture_status->gesture_id == SEC_TS_GESTURE_CODE_DOUBLE_TAP) {
					/* will be fixed to data structure */
					if (sponge[1] & SEC_TS_MODE_SPONGE_AOD) {
						u8 data[5] = { 0x0A, 0x00, 0x00, 0x00, 0x00 };

						ret = sec_ts_read_from_sponge(ts, data);
						if (ret < 0)
							dev_err(&ts->client->dev, "%s: fail to read sponge data\n", __func__);

						if (data[4] & SEC_TS_AOD_GESTURE_DOUBLETAB)
							ts->scrub_id = SPONGE_EVENT_TYPE_AOD_DOUBLETAB;

						ts->scrub_x = (data[1] & 0xFF) << 8 | (data[0] & 0xFF);
						ts->scrub_y = (data[3] & 0xFF) << 8 | (data[2] & 0xFF);
#ifdef CONFIG_SAMSUNG_PRODUCT_SHIP
						dev_info(&ts->client->dev, "%s: aod: %d\n",
								__func__, ts->scrub_id);
#else
						dev_info(&ts->client->dev, "%s: aod: %d, %d, %d\n",
								__func__, ts->scrub_id, ts->scrub_x, ts->scrub_y);
#endif
						ts->all_aod_tap_count++;
					}
					if (sponge[1] & SEC_TS_MODE_SPONGE_SPAY) {
						ts->scrub_id = SPONGE_EVENT_TYPE_SPAY;
						dev_info(&ts->client->dev, "%s: SPAY: %d\n",
									__func__, ts->scrub_id);
						ts->all_spay_count++;
					}
//					input_report_key(ts->input_dev, KEY_BLACK_UI_GESTURE, 1);
					input_sync(ts->input_dev);
//					input_report_key(ts->input_dev, KEY_BLACK_UI_GESTURE, 0);
				}
			}
			break;

		default:
			dev_err(&ts->client->dev, "%s: unknown event %x %x %x %x %x %x\n", __func__,
					event_buff[0], event_buff[1], event_buff[2],
					event_buff[3], event_buff[4], event_buff[5]);
			break;
		}

		if (t_id < MAX_SUPPORT_TOUCH_COUNT + MAX_SUPPORT_HOVER_COUNT) {
			if (ts->coord[t_id].action == SEC_TS_COORDINATE_ACTION_PRESS) {
/*#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
				dev_info(&ts->client->dev,
					"%s[P] tID:%d x:%d y:%d z:%d major:%d minor:%d tc:%d type:%X\n",
					ts->dex_name,
					t_id, ts->coord[t_id].x, ts->coord[t_id].y, ts->coord[t_id].z,
					ts->coord[t_id].major, ts->coord[t_id].minor, ts->touch_count,
					ts->coord[t_id].ttype);
#else
				dev_info(&ts->client->dev,
					"%s[P] tID:%d z:%d major:%d minor:%d tc:%d type:%X\n",
					ts->dex_name,
					t_id, ts->coord[t_id].z, ts->coord[t_id].major,
					ts->coord[t_id].minor, ts->touch_count, ts->coord[t_id].ttype);
#endif*/

			} else if (ts->coord[t_id].action == SEC_TS_COORDINATE_ACTION_RELEASE) {
/*#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
				dev_info(&ts->client->dev,
					"%s[R] tID:%d mc:%d tc:%d lx:%d ly:%d v:%02X%02X cal:%02X(%02X) id(%d,%d) p:%d P%02XT%04X\n",
					ts->dex_name,
					t_id, ts->coord[t_id].mcount, ts->touch_count,
					ts->coord[t_id].x, ts->coord[t_id].y,
					ts->plat_data->img_version_of_ic[2],
					ts->plat_data->img_version_of_ic[3],
					ts->cal_status, ts->nv, ts->tspid_val,
					ts->tspicid_val, ts->coord[t_id].palm_count,
					ts->cal_count, ts->tune_fix_ver );
#else
				dev_info(&ts->client->dev,
					"%s[R] tID:%d mc:%d tc:%d v:%02X%02X cal:%02X(%02X) id(%d,%d) p:%d P%02XT%04X F%02X%02X\n",
					ts->dex_name,
					t_id, ts->coord[t_id].mcount, ts->touch_count,
					ts->plat_data->img_version_of_ic[2],
					ts->plat_data->img_version_of_ic[3],
					ts->cal_status, ts->nv, ts->tspid_val,
					ts->tspicid_val, ts->coord[t_id].palm_count,
					ts->cal_count, ts->tune_fix_ver,
					ts->pressure_cal_base, ts->pressure_cal_delta);
#endif*/
				ts->coord[t_id].action = SEC_TS_COORDINATE_ACTION_NONE;
				ts->coord[t_id].mcount = 0;
				ts->coord[t_id].palm_count = 0;
			}
		}

		curr_pos++;
		remain_event_count--;
	} while (remain_event_count >= 0);

	input_sync(ts->input_dev);
}

static irqreturn_t sec_ts_irq_thread(int irq, void *ptr)
{
	struct sec_ts_data *ts = (struct sec_ts_data *)ptr;

#ifdef CONFIG_SECURE_TOUCH
	if (secure_filter_interrupt(ts) == IRQ_HANDLED) {
		wait_for_completion_interruptible_timeout(&ts->secure_interrupt,
					msecs_to_jiffies(5 * MSEC_PER_SEC));

		dev_info(&ts->client->dev,
					"%s: secure interrupt handled\n", __func__);

		return IRQ_HANDLED;
	}
#endif

	mutex_lock(&ts->eventlock);

	sec_ts_read_event(ts);

	mutex_unlock(&ts->eventlock);

	return IRQ_HANDLED;
}

int get_tsp_status(void)
{
	return 0;
}
EXPORT_SYMBOL(get_tsp_status);

void sec_ts_set_charger(bool enable)
{
	return;
/*
	int ret;
	u8 noise_mode_on[] = {0x01};
	u8 noise_mode_off[] = {0x00};

	if (enable) {
		dev_info(&ts->client->dev, "sec_ts_set_charger : charger CONNECTED!!\n");
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_NOISE_MODE, noise_mode_on, sizeof(noise_mode_on));
		if (ret < 0)
			dev_err(&ts->client->dev, "sec_ts_set_charger: fail to write NOISE_ON\n");
	} else {
		dev_info(&ts->client->dev, "sec_ts_set_charger : charger DISCONNECTED!!\n");
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_NOISE_MODE, noise_mode_off, sizeof(noise_mode_off));
		if (ret < 0)
			dev_err(&ts->client->dev, "sec_ts_set_charger: fail to write NOISE_OFF\n");
	}
 */
}
EXPORT_SYMBOL(sec_ts_set_charger);

int sec_ts_glove_mode_enables(struct sec_ts_data *ts, int mode)
{
	int ret;

	if (mode)
		ts->touch_functions = (ts->touch_functions | SEC_TS_BIT_SETFUNC_GLOVE | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC);
	else
		ts->touch_functions = ((ts->touch_functions & (~SEC_TS_BIT_SETFUNC_GLOVE)) | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC);

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: pwr off, glove:%d, status:%x\n", __func__,
					mode, ts->touch_functions);
		goto glove_enable_err;
	}

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&ts->touch_functions, 2);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: Failed to send command", __func__);
		goto glove_enable_err;
	}

	dev_info(&ts->client->dev, "%s: glove:%d, status:%x\n", __func__,
		mode, ts->touch_functions);

	return 0;

glove_enable_err:
	return -EIO;
}
EXPORT_SYMBOL(sec_ts_glove_mode_enables);

int sec_ts_set_cover_type(struct sec_ts_data *ts, bool enable)
{
	int ret;

	dev_info(&ts->client->dev, "%s: %d\n", __func__, ts->cover_type);


	switch (ts->cover_type) {
	case SEC_TS_VIEW_WIRELESS:
	case SEC_TS_VIEW_COVER:
	case SEC_TS_VIEW_WALLET:
	case SEC_TS_FLIP_WALLET:
	case SEC_TS_LED_COVER:
	case SEC_TS_MONTBLANC_COVER:
	case SEC_TS_CLEAR_FLIP_COVER:
	case SEC_TS_QWERTY_KEYBOARD_EUR:
	case SEC_TS_QWERTY_KEYBOARD_KOR:
		ts->cover_cmd = (u8)ts->cover_type;
		break;
	case SEC_TS_CHARGER_COVER:
	case SEC_TS_COVER_NOTHING1:
	case SEC_TS_COVER_NOTHING2:
	default:
		ts->cover_cmd = 0;
		dev_err(&ts->client->dev, "%s: not chage touch state, %d\n",
				__func__, ts->cover_type);
		break;
	}

	if (enable)
		ts->touch_functions = (ts->touch_functions | SEC_TS_BIT_SETFUNC_COVER | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC);
	else
		ts->touch_functions = ((ts->touch_functions & (~SEC_TS_BIT_SETFUNC_COVER)) | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC);

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: pwr off, close:%d, status:%x\n", __func__,
					enable, ts->touch_functions);
		goto cover_enable_err;
	}

	if (enable) {
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_COVERTYPE, &ts->cover_cmd, 1);
		if (ret < 0) {
			dev_err(&ts->client->dev, "%s: Failed to send covertype command: %d", __func__, ts->cover_cmd);
			goto cover_enable_err;
		}
	}

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&(ts->touch_functions), 2);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: Failed to send command", __func__);
		goto cover_enable_err;
	}

	dev_info(&ts->client->dev, "%s: close:%d, status:%x\n", __func__,
		enable, ts->touch_functions);

	return 0;

cover_enable_err:
	return -EIO;


}
EXPORT_SYMBOL(sec_ts_set_cover_type);

void sec_ts_set_grip_type(struct sec_ts_data *ts, u8 set_type)
{
	u8 mode = G_NONE;

	dev_info(&ts->client->dev, "%s: re-init grip(%d), edh:%d, edg:%d, lan:%d\n", __func__,
		set_type, ts->grip_edgehandler_direction, ts->grip_edge_range, ts->grip_landscape_mode);

	/* edge handler */
	if (ts->grip_edgehandler_direction != 0)
		mode |= G_SET_EDGE_HANDLER;

	if (set_type == GRIP_ALL_DATA) {
		/* edge */
		if (ts->grip_edge_range != 60)
			mode |= G_SET_EDGE_ZONE;

		/* dead zone */
		if (ts->grip_landscape_mode == 1)	/* default 0 mode, 32 */
			mode |= G_SET_LANDSCAPE_MODE;
		else
			mode |= G_SET_NORMAL_MODE;
	}
}

/* for debugging--------------------------------------------------------------------------------------*/

static int sec_ts_pinctrl_configure(struct sec_ts_data *ts, bool enable)
{
	struct pinctrl_state *state;

	dev_info(&ts->client->dev, "%s: %s\n", __func__, enable ? "ACTIVE" : "SUSPEND");

	if (enable) {
		state = pinctrl_lookup_state(ts->plat_data->pinctrl, "on_state");
		if (IS_ERR(ts->plat_data->pinctrl))
			dev_err(&ts->client->dev, "%s: could not get active pinstate\n", __func__);
	} else {
		state = pinctrl_lookup_state(ts->plat_data->pinctrl, "off_state");
		if (IS_ERR(ts->plat_data->pinctrl))
			dev_err(&ts->client->dev, "%s: could not get suspend pinstate\n", __func__);
	}

	if (!IS_ERR_OR_NULL(state))
		return pinctrl_select_state(ts->plat_data->pinctrl, state);

	return 0;

}

static int sec_ts_power(void *data, bool on)
{
	struct sec_ts_data *ts = (struct sec_ts_data *)data;
	const struct sec_ts_plat_data *pdata = ts->plat_data;
	int ret = 0;

	if (on) {
		if (ts->power_status == SEC_TS_STATE_POWER_ON)
			return ret;

		ret = regulator_enable(pdata->regulator_dvdd);
		if (ret) {
			dev_err(&ts->client->dev, "%s: Failed to enable avdd: %d\n", __func__, ret);
			goto out;
		}

		sec_ts_delay(1);

		ret = regulator_enable(pdata->regulator_avdd);
		if (ret) {
			dev_err(&ts->client->dev, "%s: Failed to enable vdd: %d\n", __func__, ret);
			goto out;
		}
		ts->power_status = SEC_TS_STATE_POWER_ON;
	} else {
		if (ts->power_status == SEC_TS_STATE_POWER_OFF)
			return ret;

		regulator_disable(pdata->regulator_dvdd);
		regulator_disable(pdata->regulator_avdd);
		ts->power_status = SEC_TS_STATE_POWER_OFF;
	}

out:
	dev_err(&ts->client->dev, "%s: %s: avdd:%s, dvdd:%s\n", __func__, on ? "on" : "off",
		regulator_is_enabled(pdata->regulator_avdd) ? "on" : "off",
		regulator_is_enabled(pdata->regulator_dvdd) ? "on" : "off");

	return ret;
}

static int sec_ts_parse_dt(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct sec_ts_plat_data *pdata = dev->platform_data;
	struct device_node *np = dev->of_node;
	u32 coords[2];
	int ret = 0;
	int count = 0;
	u32 ic_match_value;
	int lcdtype = 0;
#if 0 //defined(CONFIG_EXYNOS_DECON_FB)
	int connected;
#endif

	pdata->tsp_icid = of_get_named_gpio(np, "sec,tsp-icid_gpio", 0);
	if (gpio_is_valid(pdata->tsp_icid)) {
		dev_info(dev, "%s: TSP_ICID : %d\n", __func__, gpio_get_value(pdata->tsp_icid));
		if (of_property_read_u32(np, "sec,icid_match_value", &ic_match_value)) {
			dev_err(dev, "%s: Failed to get icid match value\n", __func__);
			return -EINVAL;
		}

		if (gpio_get_value(pdata->tsp_icid) != ic_match_value) {
			dev_err(dev, "%s: Do not match TSP_ICID\n", __func__);
			return -EINVAL;
		}
	} else {
		dev_err(dev, "%s: Failed to get tsp-icid gpio\n", __func__);
	}

	pdata->tsp_vsync = of_get_named_gpio(np, "sec,tsp_vsync_gpio", 0);
	if (gpio_is_valid(pdata->tsp_vsync))
		dev_info(&client->dev, "%s: vsync %s\n", __func__,
				gpio_get_value(pdata->tsp_vsync) ? "disable" : "enable");

	pdata->irq_gpio = of_get_named_gpio(np, "sec,irq_gpio", 0);
	if (gpio_is_valid(pdata->irq_gpio)) {
		ret = gpio_request_one(pdata->irq_gpio, GPIOF_DIR_IN, "sec,tsp_int");
		if (ret) {
			dev_err(&client->dev, "%s: Unable to request tsp_int [%d]\n", __func__, pdata->irq_gpio);
			return -EINVAL;
		}
	} else {
		dev_err(&client->dev, "%s: Failed to get irq gpio\n", __func__);
		return -EINVAL;
	}

	client->irq = gpio_to_irq(pdata->irq_gpio);

	if (of_property_read_u32(np, "sec,irq_type", &pdata->irq_type)) {
		dev_err(dev, "%s: Failed to get irq_type property\n", __func__);
		pdata->irq_type = IRQF_TRIGGER_LOW | IRQF_ONESHOT;
	}

	if (of_property_read_u32(np, "sec,i2c-burstmax", &pdata->i2c_burstmax)) {
		dev_dbg(&client->dev, "%s: Failed to get i2c_burstmax property\n", __func__);
		pdata->i2c_burstmax = 256;
	}

	if (of_property_read_u32_array(np, "sec,max_coords", coords, 2)) {
		dev_err(&client->dev, "%s: Failed to get max_coords property\n", __func__);
		return -EINVAL;
	}
	pdata->max_x = coords[0] - 1;
	pdata->max_y = coords[1] - 1;

#ifdef PAT_CONTROL
	if (of_property_read_u32(np, "sec,pat_function", &pdata->pat_function) < 0) {
		pdata->pat_function = 0;
		dev_err(dev, "%s: Failed to get pat_function property\n", __func__);
	}

	if (of_property_read_u32(np, "sec,afe_base", &pdata->afe_base) < 0) {
		pdata->afe_base = 0;
		dev_err(dev, "%s: Failed to get afe_base property\n", __func__);
	}
#endif

	pdata->tsp_id = of_get_named_gpio(np, "sec,tsp-id_gpio", 0);
	if (gpio_is_valid(pdata->tsp_id))
		dev_info(dev, "%s: TSP_ID : %d\n", __func__, gpio_get_value(pdata->tsp_id));
	else
		dev_err(dev, "%s: Failed to get tsp-id gpio\n", __func__);

	count = of_property_count_strings(np, "sec,firmware_name");
	if (count <= 0) {
		pdata->firmware_name = NULL;
	} else {
		if (gpio_is_valid(pdata->tsp_id))
			of_property_read_string_index(np, "sec,firmware_name", gpio_get_value(pdata->tsp_id), &pdata->firmware_name);
		else
			of_property_read_string_index(np, "sec,firmware_name", 0, &pdata->firmware_name);
	}

	if (of_property_read_string_index(np, "sec,project_name", 0, &pdata->project_name))
		dev_err(&client->dev, "%s: skipped to get project_name property\n", __func__);
	if (of_property_read_string_index(np, "sec,project_name", 1, &pdata->model_name))
		dev_err(&client->dev, "%s: skipped to get model_name property\n", __func__);

#if defined(CONFIG_FB_MSM_MDSS_SAMSUNG)
	lcdtype = get_lcd_attached("GET");
	if (lcdtype < 0) {
		dev_err(&client->dev, "%s: lcd is not attached\n", __func__);
		return -ENODEV;
	}
#endif

#if 0//defined(CONFIG_EXYNOS_DECON_FB)
	connected = get_lcd_info("connected");
	if (connected < 0) {
		dev_err(dev, "%s: Failed to get lcd info\n", __func__);
		return -EINVAL;
	}

	if (!connected) {
		dev_err(&client->dev, "%s: lcd is disconnected\n", __func__);
		return -ENODEV;
	}

	dev_info(&client->dev, "%s: lcd is connected\n", __func__);

	lcdtype = get_lcd_info("id");
	if (lcdtype < 0) {
		dev_err(dev, "%s: Failed to get lcd info\n", __func__);
		return -EINVAL;
	}
#endif

	dev_info(&client->dev, "%s: lcdtype 0x%08X\n", __func__, lcdtype);

	if (strncmp(pdata->model_name, "G950", 4) == 0)
		pdata->panel_revision = 0;
	else
		pdata->panel_revision = ((lcdtype >> 8) & 0xFF) >> 4;

	pdata->power = sec_ts_power;

	if (of_property_read_u32(np, "sec,always_lpmode", &pdata->always_lpmode) < 0)
		pdata->always_lpmode = 0;

	if (of_property_read_u32(np, "sec,bringup", &pdata->bringup) < 0)
		pdata->bringup = 0;

	if (of_property_read_u32(np, "sec,mis_cal_check", &pdata->mis_cal_check) < 0)
		pdata->mis_cal_check = 0;

	pdata->regulator_boot_on = of_property_read_bool(np, "sec,regulator_boot_on");
	pdata->support_sidegesture = of_property_read_bool(np, "sec,support_sidegesture");
	pdata->support_dex = of_property_read_bool(np, "support_dex_mode");

#ifdef CONFIG_SEC_FACTORY
	pdata->support_mt_pressure = true;
#endif

#ifdef PAT_CONTROL
	dev_err(&client->dev, "%s: i2c buffer limit: %d, lcd_id:%06X, bringup:%d, FW:%s(%d), id:%d,%d, pat_function:%d mis_cal:%d dex:%d, gesture:%d\n",
			__func__, pdata->i2c_burstmax, lcdtype, pdata->bringup, pdata->firmware_name,
			count, pdata->tsp_id, pdata->tsp_icid, pdata->pat_function,
			pdata->mis_cal_check, pdata->support_dex, pdata->support_sidegesture);
#else
	dev_err(&client->dev, "%s: i2c buffer limit: %d, lcd_id:%06X, bringup:%d, FW:%s(%d), id:%d,%d, dex:%d, gesture:%d\n",
		__func__, pdata->i2c_burstmax, lcdtype, pdata->bringup, pdata->firmware_name,
		count, pdata->tsp_id, pdata->tsp_icid, pdata->support_dex, pdata->support_sidegesture);
#endif
	return ret;
}

int sec_ts_read_information(struct sec_ts_data *ts)
{
	unsigned char data[13] = { 0 };
	int ret;

	memset(data, 0x0, 3);
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_ID, data, 3);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read device id(%d)\n",
					__func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev,
				"%s: %X, %X, %X\n",
				__func__, data[0], data[1], data[2]);
	memset(data, 0x0, 11);
	ret = sec_ts_i2c_read(ts,  SEC_TS_READ_PANEL_INFO, data, 11);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read sub id(%d)\n",
					__func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev,
				"%s: nTX:%X, nRX:%X, rY:%d, rX:%d\n",
				__func__, data[8], data[9],
				(data[2] << 8) | data[3], (data[0] << 8) | data[1]);

	/* Set X,Y Resolution from IC information. */
	if (((data[0] << 8) | data[1]) > 0)
		ts->plat_data->max_x = ((data[0] << 8) | data[1]) - 1;

	if (((data[2] << 8) | data[3]) > 0)
		ts->plat_data->max_y = ((data[2] << 8) | data[3]) - 1;

	ts->tx_count = data[8];
	ts->rx_count = data[9];

	data[0] = 0;
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_BOOT_STATUS, data, 1);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read sub id(%d)\n",
					__func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev,
				"%s: STATUS : %X\n",
				__func__, data[0]);

	memset(data, 0x0, 4);
	ret = sec_ts_i2c_read(ts, SEC_TS_READ_TS_STATUS, data, 4);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read sub id(%d)\n",
					__func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev,
				"%s: TOUCH STATUS : %02X, %02X, %02X, %02X\n",
				__func__, data[0], data[1], data[2], data[3]);
	ret = sec_ts_i2c_read(ts, SEC_TS_CMD_SET_TOUCHFUNCTION,  (u8 *)&(ts->touch_functions), 2);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read touch functions(%d)\n",
					__func__, ret);
		return ret;
	}

	dev_info(&ts->client->dev,
				"%s: Functions : %02X\n",
				__func__, ts->touch_functions);

	return ret;
}

#ifdef SEC_TS_SUPPORT_SPONGELIB
int sec_ts_set_custom_library(struct sec_ts_data *ts)
{
	u8 data[3] = { 0 };
	int ret;
/*
	dev_err(&ts->client->dev, "%s: Sponge (0x%02x)\n",
				__func__, ts->lowpower_mode);
*/
	data[2] = ts->lowpower_mode;

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_WRITE_PARAM, &data[0], 3);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: Failed to Sponge\n", __func__);

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_NOTIFY_PACKET, NULL, 0);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: Failed to send NOTIFY SPONGE\n", __func__);

	return ret;
}

int sec_ts_check_custom_library(struct sec_ts_data *ts)
{
	u8 data[10] = { 0 };
	int ret = -1;

	ret = ts->sec_ts_i2c_read(ts, SEC_TS_CMD_SPONGE_GET_INFO, &data[0], 10);

	dev_info(&ts->client->dev,
				"%s: (%d) %c%c%c%c, || %02X, %02X, %02X, %02X, || %02X, %02X\n",
				__func__, ret, data[0], data[1], data[2], data[3], data[4],
				data[5], data[6], data[7], data[8], data[9]);

	/* compare model name with device tree */
	if (ts->plat_data->model_name)
		ret = strncmp(data, ts->plat_data->model_name, 4);

	if (ret == 0)
		ts->use_sponge = true;
	else
		ts->use_sponge = false;

	dev_err(&ts->client->dev, "%s: use %s\n",
				__func__, ts->use_sponge ? "SPONGE" : "VENDOR");

	return ret;
}
#endif

static void sec_ts_set_input_prop(struct sec_ts_data *ts, struct input_dev *dev, u8 propbit)
{
	static char sec_ts_phys[64] = { 0 };

	snprintf(sec_ts_phys, sizeof(sec_ts_phys), "%s/input1",
			dev->name);
	dev->phys = sec_ts_phys;
	dev->id.bustype = BUS_I2C;
	dev->dev.parent = &ts->client->dev;

	set_bit(EV_SYN, dev->evbit);
	set_bit(EV_KEY, dev->evbit);
	set_bit(EV_ABS, dev->evbit);
	set_bit(EV_SW, dev->evbit);
	set_bit(BTN_TOUCH, dev->keybit);
	set_bit(BTN_TOOL_FINGER, dev->keybit);
//	set_bit(KEY_BLACK_UI_GESTURE, dev->keybit);
#ifdef SEC_TS_SUPPORT_TOUCH_KEY
	if (ts->plat_data->support_mskey) {
		int i;

		for (i = 0 ; i < ts->plat_data->num_touchkey ; i++)
			set_bit(ts->plat_data->touchkey[i].keycode, dev->keybit);

		set_bit(EV_LED, dev->evbit);
		set_bit(LED_MISC, dev->ledbit);
	}
#endif
	set_bit(propbit, dev->propbit);
	set_bit(KEY_HOMEPAGE, dev->keybit);

	input_set_abs_params(dev, ABS_MT_POSITION_X, 0, ts->plat_data->max_x, 0, 0);
	input_set_abs_params(dev, ABS_MT_POSITION_Y, 0, ts->plat_data->max_y, 0, 0);
	input_set_abs_params(dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(dev, ABS_MT_TOUCH_MINOR, 0, 255, 0, 0);
	if (ts->plat_data->support_mt_pressure)
		input_set_abs_params(dev, ABS_MT_PRESSURE, 0, 255, 0, 0);

	if (propbit == INPUT_PROP_POINTER)
		input_mt_init_slots(dev, MAX_SUPPORT_TOUCH_COUNT, INPUT_MT_POINTER);
	else
		input_mt_init_slots(dev, MAX_SUPPORT_TOUCH_COUNT, INPUT_MT_DIRECT);

	input_set_drvdata(dev, ts);
}

static int sec_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct sec_ts_data *ts;
	struct sec_ts_plat_data *pdata;
	int ret = 0;
	bool force_update = false;
	bool valid_firmware_integrity = false;
	unsigned char data[5] = { 0 };
	unsigned char deviceID[5] = { 0 };
	unsigned char result = 0;

	dev_info(&client->dev, "%s\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "%s: EIO err!\n", __func__);
		return -EIO;
	}

	/* parse dt */
	if (client->dev.of_node) {
		pdata = devm_kzalloc(&client->dev,
				sizeof(struct sec_ts_plat_data), GFP_KERNEL);

		if (!pdata) {
			dev_err(&client->dev, "%s: Failed to allocate platform data\n", __func__);
			goto error_allocate_pdata;
		}

		client->dev.platform_data = pdata;

		ret = sec_ts_parse_dt(client);
		if (ret) {
			dev_err(&client->dev, "%s: Failed to parse dt\n", __func__);
			goto error_allocate_mem;
		}
	} else {
		pdata = client->dev.platform_data;
		if (!pdata) {
			dev_err(&client->dev, "%s: No platform data found\n", __func__);
			goto error_allocate_pdata;
		}
	}

	if (!pdata->power) {
		dev_err(&client->dev, "%s: No power contorl found\n", __func__);
		goto error_allocate_mem;
	}

	pdata->pinctrl = devm_pinctrl_get(&client->dev);
	if (IS_ERR(pdata->pinctrl))
		dev_err(&client->dev, "%s: could not get pinctrl\n", __func__);

	ts = kzalloc(sizeof(struct sec_ts_data), GFP_KERNEL);
	if (!ts)
		goto error_allocate_mem;

	pdata->regulator_dvdd = devm_regulator_get(&client->dev, "dvdd");
	if (IS_ERR(pdata->regulator_dvdd)) {
		dev_err(&ts->client->dev, "%s: Failed to get dvdd regulator.\n", __func__);
		ret = PTR_ERR(pdata->regulator_dvdd);
		goto error_dvdd_regulator_put;
	}

	pdata->regulator_avdd = devm_regulator_get(&client->dev, "avdd");
	if (IS_ERR(pdata->regulator_avdd)) {
		dev_err(&ts->client->dev, "%s: Failed to get avdd regulator.\n", __func__);
		ret = PTR_ERR(pdata->regulator_avdd);
		goto error_avdd_regulator_put;
	}

	ts->client = client;
	ts->plat_data = pdata;
	ts->crc_addr = 0x0001FE00;
	ts->fw_addr = 0x00002000;
	ts->para_addr = 0x18000;
	ts->flash_page_size = SEC_TS_FW_BLK_SIZE_DEFAULT;
	ts->sec_ts_i2c_read = sec_ts_i2c_read;
	ts->sec_ts_i2c_write = sec_ts_i2c_write;
	ts->sec_ts_i2c_write_burst = sec_ts_i2c_write_burst;
	ts->sec_ts_i2c_read_bulk = sec_ts_i2c_read_bulk;
	ts->i2c_burstmax = pdata->i2c_burstmax;
#ifdef USE_POWER_RESET_WORK
	INIT_DELAYED_WORK(&ts->reset_work, sec_ts_reset_work);
#endif
//	INIT_DELAYED_WORK(&ts->work_read_info, sec_ts_read_info_work);

	i2c_set_clientdata(client, ts);

	if (gpio_is_valid(ts->plat_data->tsp_id))
		ts->tspid_val = gpio_get_value(ts->plat_data->tsp_id);

	if (gpio_is_valid(ts->plat_data->tsp_icid))
		ts->tspicid_val = gpio_get_value(ts->plat_data->tsp_icid);

	ts->input_dev = input_allocate_device();
	if (!ts->input_dev) {
		dev_err(&ts->client->dev, "%s: allocate device err!\n", __func__);
		ret = -ENOMEM;
		goto err_allocate_input_dev;
	}

	if (ts->plat_data->support_dex) {
		ts->input_dev_pad = input_allocate_device();
		if (!ts->input_dev_pad) {
			dev_err(&ts->client->dev, "%s: allocate device err!\n", __func__);
			ret = -ENOMEM;
			goto err_allocate_input_dev_pad;
		}
	}

	ts->touch_count = 0;
	ts->sec_ts_i2c_write = sec_ts_i2c_write;
	ts->sec_ts_i2c_read = sec_ts_i2c_read;
	ts->sec_ts_read_sponge = sec_ts_read_from_sponge;

	ts->max_z_value = 0;
	ts->min_z_value = 0xFFFFFFFF;
	ts->sum_z_value = 0;

	mutex_init(&ts->lock);
	mutex_init(&ts->device_mutex);
	mutex_init(&ts->i2c_mutex);
	mutex_init(&ts->eventlock);

//	wake_lock_init(&ts->wakelock, WAKE_LOCK_SUSPEND, "tsp_wakelock");
	init_completion(&ts->resume_done);
	complete_all(&ts->resume_done);

/*	if (pdata->always_lpmode)
		ts->lowpower_mode |= SEC_TS_MODE_SPONGE_FORCE_KEY;
	else
		ts->lowpower_mode &= ~SEC_TS_MODE_SPONGE_FORCE_KEY;
*/
	ts->lowpower_mode = false;
	dev_info(&client->dev, "%s: init resource\n", __func__);

	sec_ts_pinctrl_configure(ts, true);

	/* power enable */
	sec_ts_power(ts, true);
	if (!pdata->regulator_boot_on)
		sec_ts_delay(70);
	ts->external_factory = false;

	sec_ts_wait_for_ready(ts, SEC_TS_ACK_BOOT_COMPLETE);

	dev_info(&client->dev, "%s: power enable\n", __func__);

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_DEVICE_ID, deviceID, 5);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: failed to read device ID(%d)\n", __func__, ret);
	else
		dev_info(&ts->client->dev,
			"%s: TOUCH DEVICE ID : %02X, %02X, %02X, %02X, %02X\n", __func__,
			deviceID[0], deviceID[1], deviceID[2], deviceID[3], deviceID[4]);

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_FIRMWARE_INTEGRITY, &result, 1);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: failed to integrity check (%d)\n", __func__, ret);
	} else {
		if (result & 0x80) {
			valid_firmware_integrity = true;
		} else if (result & 0x40) {
			valid_firmware_integrity = false;
			dev_err(&ts->client->dev, "%s: invalid firmware (0x%x)\n", __func__, result);
		} else {
			valid_firmware_integrity = false;
			dev_err(&ts->client->dev, "%s: invalid integrity result (0x%x)\n", __func__, result);
		}
	}

	ret = sec_ts_i2c_read(ts, SEC_TS_READ_BOOT_STATUS, &data[0], 1);
	if (ret < 0) {
		dev_err(&ts->client->dev,
					"%s: failed to read sub id(%d)\n",
					__func__, ret);
	} else {
		ret = sec_ts_i2c_read(ts, SEC_TS_READ_TS_STATUS, &data[1], 4);
		if (ret < 0) {
			dev_err(&ts->client->dev,
						"%s: failed to touch status(%d)\n",
						__func__, ret);
		}
	}
	dev_info(&ts->client->dev,
		"%s: TOUCH STATUS : %02X || %02X, %02X, %02X, %02X\n",
		__func__, data[0], data[1], data[2], data[3], data[4]);

	if (data[0] == SEC_TS_STATUS_BOOT_MODE)
		ts->checksum_result = 1;
	
	if ((((data[0] == SEC_TS_STATUS_APP_MODE) && (data[2] == TOUCH_SYSTEM_MODE_FLASH)) ||
		(ret < 0)) && (valid_firmware_integrity == false))
		force_update = true;
	else
		force_update = false;

#ifdef SEC_TS_FW_UPDATE_ON_PROBE
//	ret = sec_ts_firmware_update_on_probe(ts, force_update);
//	if (ret < 0)
//		goto err_init;
#else
	dev_info(&ts->client->dev, "%s: fw update on probe disabled!\n", __func__);
#endif

	ret = sec_ts_read_information(ts);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: fail to read information 0x%x\n", __func__, ret);
		goto err_init;
	}

	ts->touch_functions |= SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC;
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&ts->touch_functions, 2);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: Failed to send touch func_mode command", __func__);

	/* Sense_on */
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: fail to write Sense_on\n", __func__);
		goto err_init;
	}

	ts->pFrame = kzalloc(ts->tx_count * ts->rx_count * 2, GFP_KERNEL);
	if (!ts->pFrame) {
		ret = -ENOMEM;
		goto err_allocate_frame;
	}

	if (ts->plat_data->support_dex) {
		ts->input_dev_pad->name = "sec_touchpad";
		sec_ts_set_input_prop(ts, ts->input_dev_pad, INPUT_PROP_POINTER);
	}
	ts->dex_name = "";

	ts->input_dev->name = "sec_touchscreen";
	sec_ts_set_input_prop(ts, ts->input_dev, INPUT_PROP_DIRECT);
#ifdef USE_OPEN_CLOSE
	ts->input_dev->open = sec_ts_input_open;
	ts->input_dev->close = sec_ts_input_close;
#endif
	ts->input_dev_touch = ts->input_dev;

	ret = input_register_device(ts->input_dev);
	if (ret) {
		dev_err(&ts->client->dev, "%s: Unable to register %s input device\n", __func__, ts->input_dev->name);
		goto err_input_register_device;
	}
	if (ts->plat_data->support_dex) {
		ret = input_register_device(ts->input_dev_pad);
		if (ret) {
			dev_err(&ts->client->dev, "%s: Unable to register %s input device\n", __func__, ts->input_dev_pad->name);
			goto err_input_pad_register_device;
		}
	}

	dev_info(&ts->client->dev, "%s: request_irq = %d\n", __func__, client->irq);

	ret = request_threaded_irq(client->irq, NULL, sec_ts_irq_thread,
			ts->plat_data->irq_type, SEC_TS_I2C_NAME, ts);
	if (ret < 0) {
		dev_err(&ts->client->dev, "%s: Unable to request threaded irq\n", __func__);
		goto err_irq;
	}

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	tsp_info = ts;

	trustedui_set_tsp_irq(client->irq);
	dev_info(&client->dev, "%s[%d] called!\n",
		__func__, client->irq);
#endif

	/* need remove below resource @ remove driver */
#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
//	sec_ts_raw_device_init(ts);
#endif
//	sec_ts_fn_init(ts);

#ifdef CONFIG_SECURE_TOUCH
	if (sysfs_create_group(&ts->input_dev->dev.kobj, &secure_attr_group) < 0)
		dev_err(&ts->client->dev, "%s: do not make secure group\n", __func__);
	else
		secure_touch_init(ts);
#endif

	device_init_wakeup(&client->dev, true);

#ifdef SEC_TS_SUPPORT_SPONGELIB
	sec_ts_check_custom_library(ts);
	if (ts->use_sponge)
		sec_ts_set_custom_library(ts);

#endif

//	schedule_delayed_work(&ts->work_read_info, msecs_to_jiffies(5000));

#if defined(CONFIG_TOUCHSCREEN_DUMP_MODE)
	dump_callbacks.inform_dump = dump_tsp_log;
	INIT_DELAYED_WORK(&ts->ghost_check, sec_ts_check_rawdata);
	p_ghost_check = &ts->ghost_check;
#endif

	ts_dup = ts;
	ts->probe_done = true;

	dev_err(&ts->client->dev, "%s: done\n", __func__);
//	input_log_fix();

	return 0;

	/* need to be enabled when new goto statement is added */
/*
#ifdef CONFIG_SECURE_TOUCH
	secure_touch_remove(ts);
#endif
	sec_ts_fn_remove(ts);
	free_irq(client->irq, ts);
*/
err_irq:
	if (ts->plat_data->support_dex) {
		input_unregister_device(ts->input_dev_pad);
		ts->input_dev_pad = NULL;
	}
err_input_pad_register_device:
	input_unregister_device(ts->input_dev);
	ts->input_dev = NULL;
	ts->input_dev_touch = NULL;
err_input_register_device:
	kfree(ts->pFrame);
err_allocate_frame:
err_init:
//	wake_lock_destroy(&ts->wakelock);
	sec_ts_power(ts, false);
	if (ts->plat_data->support_dex) {
		if (ts->input_dev_pad)
			input_free_device(ts->input_dev_pad);
	}
err_allocate_input_dev_pad:
	if (ts->input_dev)
		input_free_device(ts->input_dev);

err_allocate_input_dev:
error_avdd_regulator_put:
error_dvdd_regulator_put:
	kfree(ts);

error_allocate_mem:
	if (gpio_is_valid(pdata->irq_gpio))
		gpio_free(pdata->irq_gpio);
	if (gpio_is_valid(pdata->tsp_id))
		gpio_free(pdata->tsp_id);
	if (gpio_is_valid(pdata->tsp_icid))
		gpio_free(pdata->tsp_icid);

error_allocate_pdata:
	if (ret == -ECONNREFUSED)
		sec_ts_delay(100);
	ret = -ENODEV;
#ifdef CONFIG_TOUCHSCREEN_DUMP_MODE
	p_ghost_check = NULL;
#endif
	ts_dup = NULL;
#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	tsp_info = NULL;
#endif
	dev_err(&client->dev, "%s: failed(%d)\n", __func__, ret);
//	input_log_fix();
	return ret;
}

void sec_ts_unlocked_release_all_finger(struct sec_ts_data *ts)
{
	int i;

	for (i = 0; i < MAX_SUPPORT_TOUCH_COUNT; i++) {
		input_mt_slot(ts->input_dev, i);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);

		if ((ts->coord[i].action == SEC_TS_COORDINATE_ACTION_PRESS) ||
			(ts->coord[i].action == SEC_TS_COORDINATE_ACTION_MOVE)) {

			ts->coord[i].action = SEC_TS_COORDINATE_ACTION_RELEASE;
			dev_info(&ts->client->dev,
					"%s: [RA] tID:%d mc:%d tc:%d v:%02X%02X cal:%02X(%02X) id(%d,%d) p:%d\n",
					__func__, i, ts->coord[i].mcount, ts->touch_count,
					ts->plat_data->img_version_of_ic[2],
					ts->plat_data->img_version_of_ic[3],
					ts->cal_status, ts->nv, ts->tspid_val,
					ts->tspicid_val, ts->coord[i].palm_count);

			ktime_get_real_ts64(&ts->time_released[i]);
			
			if (ts->time_longest < (ts->time_released[i].tv_sec - ts->time_pressed[i].tv_sec))
				ts->time_longest = (ts->time_released[i].tv_sec - ts->time_pressed[i].tv_sec);
		}

		ts->coord[i].mcount = 0;
		ts->coord[i].palm_count = 0;

	}

	input_mt_slot(ts->input_dev, 0);

	input_report_key(ts->input_dev, BTN_TOUCH, false);
	input_report_key(ts->input_dev, BTN_TOOL_FINGER, false);
	ts->touchkey_glove_mode_status = false;
	ts->touch_count = 0;
	ts->check_multi = 0;

	input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
	input_sync(ts->input_dev);

}

void sec_ts_locked_release_all_finger(struct sec_ts_data *ts)
{
	int i;

	mutex_lock(&ts->eventlock);

	for (i = 0; i < MAX_SUPPORT_TOUCH_COUNT; i++) {
		input_mt_slot(ts->input_dev, i);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);

		if ((ts->coord[i].action == SEC_TS_COORDINATE_ACTION_PRESS) ||
			(ts->coord[i].action == SEC_TS_COORDINATE_ACTION_MOVE)) {

			ts->coord[i].action = SEC_TS_COORDINATE_ACTION_RELEASE;
			dev_info(&ts->client->dev,
					"%s: [RA] tID:%d mc: %d tc:%d, v:%02X%02X, cal:%X(%X|%X), id(%d,%d), p:%d\n",
					__func__, i, ts->coord[i].mcount, ts->touch_count,
					ts->plat_data->img_version_of_ic[2],
					ts->plat_data->img_version_of_ic[3],
					ts->cal_status, ts->nv, ts->cal_count, ts->tspid_val,
					ts->tspicid_val, ts->coord[i].palm_count);

			ktime_get_real_ts64(&ts->time_released[i]);
			
			if (ts->time_longest < (ts->time_released[i].tv_sec - ts->time_pressed[i].tv_sec))
				ts->time_longest = (ts->time_released[i].tv_sec - ts->time_pressed[i].tv_sec);
		}

		ts->coord[i].mcount = 0;
		ts->coord[i].palm_count = 0;

	}

	input_mt_slot(ts->input_dev, 0);

	input_report_key(ts->input_dev, BTN_TOUCH, false);
	input_report_key(ts->input_dev, BTN_TOOL_FINGER, false);
	ts->touchkey_glove_mode_status = false;
	ts->touch_count = 0;
	ts->check_multi = 0;

	input_report_key(ts->input_dev, KEY_HOMEPAGE, 0);
	input_sync(ts->input_dev);

	mutex_unlock(&ts->eventlock);

}

#ifdef USE_POWER_RESET_WORK
static void sec_ts_reset_work(struct work_struct *work)
{
	struct sec_ts_data *ts = container_of(work, struct sec_ts_data,
							reset_work.work);

#ifdef CONFIG_SECURE_TOUCH
	if (atomic_read(&ts->secure_enabled) == SECURE_TOUCH_ENABLE) {
		dev_err(&ts->client->dev, "%s: secure touch enabled\n", __func__);
		return;
	}
#endif
	ts->reset_is_on_going = true;
	dev_info(&ts->client->dev, "%s\n", __func__);

	sec_ts_stop_device(ts);

	sec_ts_delay(30);

	sec_ts_start_device(ts);

/*
	if (ts->input_dev_touch->disabled) {
		dev_err(&ts->client->dev , "%s: call input_close\n", __func__);

		sec_ts_input_close(ts->input_dev);

		if ((ts->lowpower_mode & SEC_TS_MODE_SPONGE_AOD) && ts->use_sponge) {
			int i, ret;
			u8 data[10] = {0x02, 0};

			for (i = 0; i < 4; i++) {
				data[i * 2 + 2] = ts->rect_data[i] & 0xFF;
				data[i * 2 + 3] = (ts->rect_data[i] >> 8) & 0xFF;
			}

			disable_irq(ts->client->irq);
			ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_WRITE_PARAM, &data[0], 10);
			if (ret < 0)
				dev_err(&ts->client->dev, "%s: Failed to write offset\n", __func__);

			ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SPONGE_NOTIFY_PACKET, NULL, 0);
			if (ret < 0)
				dev_err(&ts->client->dev, "%s: Failed to send notify\n", __func__);
			enable_irq(ts->client->irq);
		}
	}
*/
	ts->reset_is_on_going = false;
}
#endif

/*int sec_ts_set_lowpowermode(struct sec_ts_data *ts, u8 mode)
{
	int ret;
	int retrycnt = 0;
	u8 data;
	char para = 0;

	dev_err(&ts->client->dev, "%s: %s(%X)\n", __func__,
			mode == TO_LOWPOWER_MODE ? "ENTER" : "EXIT", ts->lowpower_mode);

	if (mode) {
		if (ts->use_sponge)
			sec_ts_set_custom_library(ts);

		data = (ts->lowpower_mode & SEC_TS_MODE_LOWPOWER_FLAG) >> 1;
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_WAKEUP_GESTURE_MODE, &data, 1);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to set\n", __func__);
	}

retry_pmode:
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_POWER_MODE, &mode, 1);
	if (ret < 0)
		dev_err(&ts->client->dev,
				"%s: failed\n", __func__);
	sec_ts_delay(50);


	ret = sec_ts_i2c_read(ts, SEC_TS_CMD_SET_POWER_MODE, &para, 1);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: read power mode failed!\n", __func__);
	else
		dev_info(&ts->client->dev, "%s: power mode - write(%d) read(%d)\n", __func__, mode, para);

	if (mode != para) {
		retrycnt++;
		if (retrycnt < 5)
			goto retry_pmode;
	}

	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_CLEAR_EVENT_STACK, NULL, 0);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: i2c write clear event failed\n", __func__);


	sec_ts_locked_release_all_finger(ts);

	if (device_may_wakeup(&ts->client->dev)) {
		if (mode)
			enable_irq_wake(ts->client->irq);
		else
			disable_irq_wake(ts->client->irq);
	}

	ts->lowpower_status = mode;
	dev_info(&ts->client->dev, "%s: end\n", __func__);

	return ret;
}
*/
#ifdef USE_OPEN_CLOSE
static int sec_ts_input_open(struct input_dev *dev)
{
	struct sec_ts_data *ts = input_get_drvdata(dev);
	int ret;

	ts->input_closed = false;

	dev_info(&ts->client->dev, "%s\n", __func__);

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if(TRUSTEDUI_MODE_TUI_SESSION & trustedui_get_current_mode()){	
		dev_err(&ts->client->dev, "%s TUI cancel event call!\n", __func__);
		msleep(100);
		tui_force_close(1);
		msleep(200);
		if(TRUSTEDUI_MODE_TUI_SESSION & trustedui_get_current_mode()){	
			dev_err(&ts->client->dev, "%s TUI flag force clear!\n",	__func__);
			trustedui_clear_mask(TRUSTEDUI_MODE_VIDEO_SECURED|TRUSTEDUI_MODE_INPUT_SECURED);
			trustedui_set_mode(TRUSTEDUI_MODE_OFF);
		}
	}
#endif

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_stop(ts, 0);
#endif

/*	if (ts->lowpower_status) {

#ifdef USE_RESET_EXIT_LPM
		schedule_delayed_work(&ts->reset_work, msecs_to_jiffies(TOUCH_RESET_DWORK_TIME));
#else
		sec_ts_set_lowpowermode(ts, TO_TOUCH_MODE);
#endif
		ts->power_status = SEC_TS_STATE_POWER_ON;
	} else {*/
		ret = sec_ts_start_device(ts);
		if (ret < 0)
			dev_err(&ts->client->dev, "%s: Failed to start device\n", __func__);
//	}

	/* because edge and dead zone will recover soon */
	sec_ts_set_grip_type(ts, ONLY_EDGE_HANDLER);

	return 0;
}

static void sec_ts_input_close(struct input_dev *dev)
{
	struct sec_ts_data *ts = input_get_drvdata(dev);

	ts->input_closed = true;

	dev_info(&ts->client->dev, "%s\n", __func__);

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if(TRUSTEDUI_MODE_TUI_SESSION & trustedui_get_current_mode()){	
		dev_err(&ts->client->dev, "%s TUI cancel event call!\n", __func__);
		msleep(100);
		tui_force_close(1);
		msleep(200);
		if(TRUSTEDUI_MODE_TUI_SESSION & trustedui_get_current_mode()){	
			dev_err(&ts->client->dev, "%s TUI flag force clear!\n",	__func__);
			trustedui_clear_mask(TRUSTEDUI_MODE_VIDEO_SECURED|TRUSTEDUI_MODE_INPUT_SECURED);
			trustedui_set_mode(TRUSTEDUI_MODE_OFF);
		}
	}
#endif

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_stop(ts, 1);
#endif
#ifdef USE_POWER_RESET_WORK
	cancel_delayed_work(&ts->reset_work);
#endif
/*
#ifndef CONFIG_SEC_FACTORY
	ts->lowpower_mode |= SEC_TS_MODE_SPONGE_FORCE_KEY;
#endif
	if (ts->lowpower_mode) {
		sec_ts_set_lowpowermode(ts, TO_LOWPOWER_MODE);
		ts->power_status = SEC_TS_STATE_LPM;
	} else {*/
		sec_ts_stop_device(ts);
//	}
}
#endif

static void sec_ts_remove(struct i2c_client *client)
{
	struct sec_ts_data *ts = i2c_get_clientdata(client);

	dev_info(&ts->client->dev, "%s\n", __func__);

//	cancel_delayed_work_sync(&ts->work_read_info);
//	flush_delayed_work(&ts->work_read_info);

	disable_irq_nosync(ts->client->irq);
	free_irq(ts->client->irq, ts);
	dev_info(&ts->client->dev, "%s: irq disabled\n", __func__);

#ifdef USE_POWER_RESET_WORK
	cancel_delayed_work_sync(&ts->reset_work);
	flush_delayed_work(&ts->reset_work);

	dev_info(&ts->client->dev, "%s: flush queue\n", __func__);

#endif

//	sec_ts_fn_remove(ts);

#ifdef CONFIG_TOUCHSCREEN_DUMP_MODE
	p_ghost_check = NULL;
#endif
	device_init_wakeup(&client->dev, false);
//	wake_lock_destroy(&ts->wakelock);

	ts->lowpower_mode = false;
	ts->probe_done = false;

	if (ts->plat_data->support_dex) {
		input_mt_destroy_slots(ts->input_dev_pad);
		input_unregister_device(ts->input_dev_pad);
	}

	ts->input_dev = ts->input_dev_touch;
	input_mt_destroy_slots(ts->input_dev);
	input_unregister_device(ts->input_dev);

#ifdef CONFIG_SECURE_TOUCH
	secure_touch_remove(ts);
#endif
	ts->input_dev_pad = NULL;
	ts->input_dev = NULL;
	ts->input_dev_touch = NULL;
	ts_dup = NULL;
	ts->plat_data->power(ts, false);

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	tsp_info = NULL;
#endif
	kfree(ts);
}

static void sec_ts_shutdown(struct i2c_client *client)
{
	struct sec_ts_data *ts = i2c_get_clientdata(client);

	dev_info(&ts->client->dev, "%s\n", __func__);

	sec_ts_remove(client);
}

int sec_ts_stop_device(struct sec_ts_data *ts)
{
	dev_info(&ts->client->dev, "%s\n", __func__);

	mutex_lock(&ts->device_mutex);

	if (ts->power_status == SEC_TS_STATE_POWER_OFF) {
		dev_err(&ts->client->dev, "%s: already power off\n", __func__);
		goto out;
	}

	ts->power_status = SEC_TS_STATE_POWER_OFF;

	disable_irq(ts->client->irq);
	sec_ts_locked_release_all_finger(ts);

	ts->plat_data->power(ts, false);

	if (ts->plat_data->enable_sync)
		ts->plat_data->enable_sync(false);

	sec_ts_pinctrl_configure(ts, false);

out:
	mutex_unlock(&ts->device_mutex);
	return 0;
}

int sec_ts_start_device(struct sec_ts_data *ts)
{
	int ret;

	dev_info(&ts->client->dev, "%s\n", __func__);

	sec_ts_pinctrl_configure(ts, true);

	mutex_lock(&ts->device_mutex);

	if (ts->power_status == SEC_TS_STATE_POWER_ON) {
		dev_err(&ts->client->dev, "%s: already power on\n", __func__);
		goto out;
	}

	sec_ts_locked_release_all_finger(ts);

	ts->plat_data->power(ts, true);
	sec_ts_delay(70);
	ts->power_status = SEC_TS_STATE_POWER_ON;
	sec_ts_wait_for_ready(ts, SEC_TS_ACK_BOOT_COMPLETE);

	if (ts->plat_data->enable_sync)
		ts->plat_data->enable_sync(true);

	if (ts->flip_enable) {
		ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_COVERTYPE, &ts->cover_cmd, 1);

		ts->touch_functions = ts->touch_functions | SEC_TS_BIT_SETFUNC_COVER;
		dev_info(&ts->client->dev,
				"%s: cover cmd write type:%d, mode:%x, ret:%d", __func__, ts->touch_functions, ts->cover_cmd, ret);
	} else {
		ts->touch_functions = (ts->touch_functions & (~SEC_TS_BIT_SETFUNC_COVER));
		dev_info(&ts->client->dev,
			"%s: cover open, not send cmd", __func__);
	}

	ts->touch_functions = ts->touch_functions | SEC_TS_DEFAULT_ENABLE_BIT_SETFUNC;
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHFUNCTION, (u8 *)&ts->touch_functions, 2);
	if (ret < 0)
		dev_err(&ts->client->dev,
			"%s: Failed to send touch function command", __func__);

	if (ts->use_sponge)
		sec_ts_set_custom_library(ts);

	sec_ts_set_grip_type(ts, ONLY_EDGE_HANDLER);

	if (ts->dex_mode) {
		dev_info(&ts->client->dev, "%s: set dex mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_DEX_MODE, &ts->dex_mode, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
				"%s: failed to set dex mode %x\n", __func__, ts->dex_mode);
	}

	if (ts->brush_mode) {
		dev_info(&ts->client->dev, "%s: set brush mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_BRUSH_MODE, &ts->brush_mode, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
						"%s: failed to set brush mode\n", __func__);
	}

	if (ts->touchable_area) {
		dev_info(&ts->client->dev, "%s: set 16:9 mode\n", __func__);
		ret = ts->sec_ts_i2c_write(ts, SEC_TS_CMD_SET_TOUCHABLE_AREA, &ts->touchable_area, 1);
		if (ret < 0)
			dev_err(&ts->client->dev,
						"%s: failed to set 16:9 mode\n", __func__);
	}

	/* Sense_on */
	ret = sec_ts_i2c_write(ts, SEC_TS_CMD_SENSE_ON, NULL, 0);
	if (ret < 0)
		dev_err(&ts->client->dev, "%s: fail to write Sense_on\n", __func__);

	enable_irq(ts->client->irq);

out:
	mutex_unlock(&ts->device_mutex);
	return 0;
}

#ifdef CONFIG_PM
static int sec_ts_pm_suspend(struct device *dev)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
/*
	if (ts->lowpower_mode)
		reinit_completion(&ts->resume_done);
*/
	sec_ts_stop_device(ts);
	return 0;
}

static int sec_ts_pm_resume(struct device *dev)
{
	struct sec_ts_data *ts = dev_get_drvdata(dev);
/*
	if (ts->lowpower_mode)
		complete_all(&ts->resume_done);
*/
	sec_ts_start_device(ts);
	return 0;
}
#endif

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
void trustedui_mode_on(void)
{
	if (!tsp_info)
		return;

	sec_ts_unlocked_release_all_finger(tsp_info);
}

void trustedui_mode_off(void)
{
	if (!tsp_info)
		return;
}
#endif


static const struct i2c_device_id sec_ts_id[] = {
	{ SEC_TS_I2C_NAME, 0 },
	{ },
};

#ifdef CONFIG_PM
static const struct dev_pm_ops sec_ts_dev_pm_ops = {
	.suspend = sec_ts_pm_suspend,
	.resume = sec_ts_pm_resume,
};
#endif

#ifdef CONFIG_OF
static const struct of_device_id sec_ts_match_table[] = {
	{ .compatible = "sec,sec_ts",},
	{ },
};
#else
#define sec_ts_match_table NULL
#endif

static struct i2c_driver sec_ts_driver = {
	.probe		= sec_ts_probe,
	.remove		= sec_ts_remove,
	.shutdown	= sec_ts_shutdown,
	.id_table	= sec_ts_id,
	.driver = {
		.owner	= THIS_MODULE,
		.name	= SEC_TS_I2C_NAME,
#ifdef CONFIG_OF
		.of_match_table = sec_ts_match_table,
#endif
#ifdef CONFIG_PM
		.pm = &sec_ts_dev_pm_ops,
#endif
	},
};

static int __init sec_ts_init(void)
{
#ifdef CONFIG_BATTERY_SAMSUNG
	if (lpcharge == 1) {
		pr_err("%s: Do not load driver due to : lpm %d\n",
				__func__, lpcharge);
		return -ENODEV;
	}
#endif
	pr_err("%s\n", __func__);

	return i2c_add_driver(&sec_ts_driver);
}

static void __exit sec_ts_exit(void)
{
	i2c_del_driver(&sec_ts_driver);
}

MODULE_AUTHOR("Hyobae, Ahn<hyobae.ahn@samsung.com>");
MODULE_DESCRIPTION("Samsung Electronics TouchScreen driver");
MODULE_LICENSE("GPL");

module_init(sec_ts_init);
module_exit(sec_ts_exit);
