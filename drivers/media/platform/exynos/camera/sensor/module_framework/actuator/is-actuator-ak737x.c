/*
 * Samsung Exynos5 SoC series Actuator driver
 *
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/i2c.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/videodev2.h>
#include <videodev2_exynos_camera.h>

#include "is-actuator-ak737x.h"
#include "is-device-sensor.h"
#include "is-device-sensor-peri.h"
#include "is-core.h"
#include "is-time.h"
#include "is-sysfs.h"

#include "is-helper-ixc.h"

#include "interface/is-interface-library.h"

static struct device *camera_focus_dev[ACTUATOR_MAX_ENUM];

#define AK737X_DEFAULT_FIRST_POSITION		960  /* 12bits */
#define AK737X_DEFAULT_FIRST_DELAY			2000
#define AK737X_DEFAULT_SLEEP_TO_STANDBY_DELAY		1000
#define AK737X_DEFAULT_ACTIVE_TO_STANDBY_DELAY		200
#define AK737X_DEFAULT_HALL_MIN_INTERVAL			75
#define AK737X_DEFAULT_HALL_HW_PARAM_TOLERANCE		200

static int sensor_ak737x_write_position(struct i2c_client *client,
			u32 val, struct is_actuator *actuator)
{
	int ret = 0;
	u8 val_high = 0, val_low = 0;

	WARN_ON(!client);

	if (!client->adapter) {
		err("Could not find adapter!\n");
		ret = -ENODEV;
		goto p_err;
	}

	if (val > AK737X_POS_MAX_SIZE) {
		err("Invalid af position(position : %d, Max : %d).\n",
					val, AK737X_POS_MAX_SIZE);
		ret = -EINVAL;
		goto p_err;
	}

	val_high = (val & 0x0FFF) >> 4;
	val_low = (val & 0x000F) << 4;

	ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_POS_HIGH, val_high);
	if (ret < 0)
		goto p_err;
	ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_POS_LOW, val_low);
	if (ret < 0)
		goto p_err;

p_err:
	return ret;
}

static int sensor_ak737x_temperature_sensor_on(struct i2c_client *client,
	struct is_actuator *actuator)
{
	int ret = 0;

	WARN_ON(!client);

	ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_TEMPERATURE_SENSOR_ADDR, AK737X_REG_TEMPERATURE_SENSOR_ON);
	if (ret < 0)
		goto p_err;

	usleep_range(300, 310);

	dbg_actuator("%s\n", __func__);

p_err:
	return ret;
}

static int sensor_ak737x_read_temperature(struct v4l2_subdev *subdev, struct i2c_client *client)
{
	int ret = 0;
	u8 read_val = 0;
	struct is_actuator *actuator;

	WARN_ON(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	WARN_ON(!client);

	if (!client->adapter) {
		err("Could not find adapter!\n");
		ret = -ENODEV;
		goto p_err;
	}

	ret = actuator->ixc_ops->addr8_read8(client, AK737X_REG_TEMPERATURE_READ_ADDR, &read_val);
	if (ret < 0)
		goto p_err;

	actuator->temperature = read_val;

	dbg_actuator("%s - temperature(%d)\n", __func__, actuator->temperature);
	actuator->temperature_available = true;

p_err:
	return ret;
}

static int sensor_ak737x_read_voltage(struct v4l2_subdev *subdev, struct i2c_client *client)
{
	int ret = 0;
	u8 val_msb = 0, val_lsb = 0;
	struct is_actuator *actuator;

	WARN_ON(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	WARN_ON(!client);

	if (!client->adapter) {
		err("Could not find adapter!\n");
		ret = -ENODEV;
		goto p_err;
	}

	ret = actuator->ixc_ops->addr8_read8(client, AK737X_REG_VOLTAGE_READ_ADDR_MSB, &val_msb);
	if (ret < 0)
		goto p_err;

	ret = actuator->ixc_ops->addr8_read8(client, AK737X_REG_VOLTAGE_READ_ADDR_LSB, &val_lsb);
	if (ret < 0)
		goto p_err;

	actuator->voltage = ((val_msb & 0xFF) << 2) | ((val_lsb & 0xC0) >> 6);

	dbg_actuator("%s - voltage(%d)\n", __func__, actuator->voltage);
	actuator->voltage_available = true;

p_err:
	return ret;
}

static int sensor_ak737x_valid_check(struct i2c_client *client)
{
	int i;
	struct is_sysfs_actuator *sysfs_actuator;

	WARN_ON(!client);

	sysfs_actuator = is_get_sysfs_actuator();
	if (sysfs_actuator->init_step > 0) {
		for (i = 0; i < sysfs_actuator->init_step; i++) {
			if (sysfs_actuator->init_positions[i] < 0) {
				warn("invalid position value, default setting to position");
				return 0;
			} else if (sysfs_actuator->init_delays[i] < 0) {
				warn("invalid delay value, default setting to delay");
				return 0;
			}
		}
	} else
		return 0;

	return sysfs_actuator->init_step;
}

static void sensor_ak737x_print_log(int step)
{
	int i;
	struct is_sysfs_actuator *sysfs_actuator;

	sysfs_actuator = is_get_sysfs_actuator();
	if (step > 0) {
		dbg_actuator("initial position ");
		for (i = 0; i < step; i++)
			dbg_actuator(" %d", sysfs_actuator->init_positions[i]);
		dbg_actuator(" setting");
	}
}

static int sensor_ak737x_init_position(struct i2c_client *client,
		struct is_actuator *actuator)
{
	int i;
	int ret = 0;
	int init_step = 0;
	struct is_sysfs_actuator *sysfs_actuator;

	sysfs_actuator = is_get_sysfs_actuator();
	init_step = sensor_ak737x_valid_check(client);

	if (init_step > 0) {
		for (i = 0; i < init_step; i++) {
			ret = sensor_ak737x_write_position(client,
				sysfs_actuator->init_positions[i], actuator);
			if (ret < 0)
				goto p_err;

			mdelay(sysfs_actuator->init_delays[i]);
		}

		actuator->position = sysfs_actuator->init_positions[i];

		sensor_ak737x_print_log(init_step);

	} else {
		/* use previous position at initial time */
		if (actuator->position == 0)
			actuator->position = actuator->vendor_first_pos;

		ret = sensor_ak737x_write_position(client, actuator->position, actuator);
		if (ret < 0)
			goto p_err;

		usleep_range(actuator->vendor_first_delay, actuator->vendor_first_delay + 10);

		dbg_actuator("initial position %d setting\n", actuator->vendor_first_pos);
	}

p_err:
	return ret;
}

static int sensor_ak737x_soft_landing_on_recording(struct v4l2_subdev *subdev)
{
	int ret = 0;
	int i;
	struct is_actuator *actuator;
	struct i2c_client *client = NULL;

	WARN_ON(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	client = actuator->client;
	if (unlikely(!client)) {
		err("client is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	IXC_MUTEX_LOCK(actuator->ixc_lock);

	if (actuator->vendor_soft_landing_list_len > 0) {
		pr_info("[%s][%d] E\n", __func__, actuator->device);

		if (actuator->vendor_soft_landing_seqid == 1) {
			/* setting mode on */
			ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_SETTING_MODE_ON, 0x3B);
			if (ret < 0)
				goto p_err;
			/* change Gain parameter */
			ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CHANGE_GAIN2_PARAMETER, 0x0A);
			if (ret < 0)
				goto p_err;
		} else if (actuator->vendor_soft_landing_seqid == 2 || actuator->vendor_soft_landing_seqid == 3) {
			/* setting mode on */
			ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_SETTING_MODE_ON, 0x3B);
			if (ret < 0)
				goto p_err;
			/* change Gamma parameter */
			ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CHANGE_GAMMA_PARAMETER, 0x40);
			if (ret < 0)
				goto p_err;
			/* change Gain1 parameter */
			ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CHANGE_GAIN1_PARAMETER, 0x08);
			if (ret < 0)
				goto p_err;
			/* change Gain2 parameter */
			if (actuator->vendor_soft_landing_seqid == 3) {
				ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CHANGE_GAIN3_PARAMETER, 0x08);
			} else {
				ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CHANGE_GAIN2_PARAMETER, 0x08);
			}

			if (ret < 0)
				goto p_err;
		}

		for (i = 0; i < actuator->vendor_soft_landing_list_len; i += 2) {
			ret = sensor_ak737x_write_position(client, actuator->vendor_soft_landing_list[i], actuator);
			if (ret < 0)
				goto p_err;

			msleep(actuator->vendor_soft_landing_list[i + 1]);
		}

		pr_info("[%s][%d] X\n", __func__, actuator->device);
	}

p_err:
	IXC_MUTEX_UNLOCK(actuator->ixc_lock);

	return ret;
}

int sensor_ak737x_actuator_init(struct v4l2_subdev *subdev, u32 val)
{
	int ret = 0;
	int i = 0;
	struct is_actuator *actuator;
	struct i2c_client *client = NULL;
	struct is_module_enum *module;
#ifdef DEBUG_ACTUATOR_TIME
	ktime_t st = ktime_get();
#endif

	ktime_t current_time;
	u32 first_i2c_delay = 0;
	u32 product_id_list[AK737X_MAX_PRODUCT_LIST] = {0, };
	u32 product_id_len = 0;
	u8 product_id = 0;
	const u32 *product_id_spec;

	struct device *dev;
	struct device_node *dnode;
	struct is_device_sensor *device;

	FIMC_BUG(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	FIMC_BUG(!actuator);

	client = actuator->client;
	FIMC_BUG(!client);

	device = v4l2_get_subdev_hostdata(subdev);
	FIMC_BUG(!device);

	module = actuator->sensor_peri->module;
	FIMC_BUG(!module)

	dev = &client->dev;
	dnode = dev->of_node;

	product_id_spec = of_get_property(dnode, "vendor_product_id", &product_id_len);
	if (!product_id_spec)
		err("vendor_product_id num read is fail(%d)", ret);

	product_id_len /= (unsigned int)sizeof(*product_id_spec);

	ret = of_property_read_u32_array(dnode, "vendor_product_id", product_id_list, product_id_len);
	if (ret)
		err("vendor_product_id read is fail(%d)", ret);

	current_time = ktime_get_boottime();

	if (current_time < module->act_available_time) {
		first_i2c_delay = (u32)((module->act_available_time - current_time) / 1000L);

		if (first_i2c_delay > 20000) {
			info("Check! first_i2c_delay %d[us] -> 20[ms]\n", first_i2c_delay);
			first_i2c_delay = 20000;
		}

		usleep_range(first_i2c_delay, first_i2c_delay + 10);
		info("[%s] need to actuator first_i2c_delay : %d[us]", __func__, first_i2c_delay);
	}

	IXC_MUTEX_LOCK(actuator->ixc_lock);

	if (product_id_len < 2 || (product_id_len % 2) != 0
		|| product_id_len > AK737X_MAX_PRODUCT_LIST) {
		err("[%s] Invalid product_id in dts\n", __func__);
		ret = -EINVAL;
		goto p_err;
	}

	actuator->state = ACTUATOR_STATE_INIT;
	actuator->temperature_available = false;
	actuator->voltage_available = false;

	if (actuator->vendor_use_standby_mode) {
		/* sleep to standby mode */
		actuator->state = ACTUATOR_STATE_STANDBY;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_STANDBY);
		if (ret < 0)
			goto p_err;

		usleep_range(actuator->vendor_sleep_to_standby_delay, actuator->vendor_sleep_to_standby_delay + 10);
	}

	for (i = 0; i < product_id_len; i += 2) {
		ret = actuator->ixc_ops->addr8_read8(client, product_id_list[i], &product_id);
		if (ret < 0)
			goto p_err;

		pr_info("[%s][%d] dt[addr=0x%X,id=0x%X], product_id=0x%X\n",
				__func__, actuator->device, product_id_list[i], product_id_list[i+1], product_id);

		if (product_id_list[i+1] == product_id) {
			actuator->vendor_product_id = product_id_list[i+1];
			break;
		}
	}

	if (i == product_id_len) {
		err("[%s] Invalid product_id in module\n", __func__);
		ret = -EINVAL;
		goto p_err;
	}

	/* secure camera doesn't use sleep mode */
	if (actuator->vendor_use_sleep_mode
		&& device->ex_scenario != IS_SCENARIO_SECURE) {
		/* Go sleep mode */
		actuator->state = ACTUATOR_STATE_SLEEP;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_SLEEP);
		if (ret < 0)
			goto p_err;
	} else {
		ret = sensor_ak737x_init_position(client, actuator);
		if (ret < 0)
			goto p_err;

		/* Go active mode */
		actuator->state = ACTUATOR_STATE_ACTIVE;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_ACTIVE);
		if (ret < 0)
			goto p_err;

		if (actuator->vendor_use_temperature) {
			ret = sensor_ak737x_temperature_sensor_on(client, actuator);
			if (ret < 0)
				goto p_err;
		}
	}

#ifdef DEBUG_ACTUATOR_TIME
	pr_info("[%s] time %ldus", __func__, PABLO_KTIME_US_DELTA_NOW(st));
#endif

p_err:
	IXC_MUTEX_UNLOCK(actuator->ixc_lock);

	/* to prevent duplicated init */
	actuator->actuator_data.actuator_init = false;

	return ret;
}

int sensor_ak737x_actuator_get_status(struct v4l2_subdev *subdev, u32 *info)
{
	int ret = 0;
	struct is_actuator *actuator = NULL;
	struct i2c_client *client = NULL;
	enum is_actuator_status status = ACTUATOR_STATUS_NO_BUSY;
#ifdef DEBUG_ACTUATOR_TIME
	ktime_t st = ktime_get();
#endif

	dbg_actuator("%s\n", __func__);

	WARN_ON(!subdev);
	WARN_ON(!info);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	client = actuator->client;
	if (unlikely(!client)) {
		err("client is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	/*
	 * The info is busy flag.
	 * But, this module can't get busy flag.
	 */
	status = ACTUATOR_STATUS_NO_BUSY;
	*info = status;

	if (actuator->state == ACTUATOR_STATE_ACTIVE) {
		if (actuator->vendor_use_temperature) {
			sensor_ak737x_read_temperature(subdev, client);
		}

		if (actuator->vendor_use_voltage) {
			sensor_ak737x_read_voltage(subdev, client);
		}
	}

#ifdef DEBUG_ACTUATOR_TIME
	pr_info("[%s] time %ldus", __func__, PABLO_KTIME_US_DELTA_NOW(st));
#endif

p_err:
	return ret;
}

int sensor_ak737x_actuator_set_position(struct v4l2_subdev *subdev, u32 *info)
{
	int ret = 0;
	struct is_actuator *actuator;
	struct i2c_client *client;
	u32 position = 0;
	struct is_sysfs_actuator *sysfs_actuator = is_get_sysfs_actuator();
#ifdef DEBUG_ACTUATOR_TIME
	ktime_t st = ktime_get();
#endif

	WARN_ON(!subdev);
	WARN_ON(!info);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	client = actuator->client;
	if (unlikely(!client)) {
		err("client is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	IXC_MUTEX_LOCK(actuator->ixc_lock);
	position = *info;
	if (position > AK737X_POS_MAX_SIZE) {
		err("Invalid af position(position : %d, Max : %d).\n",
					position, AK737X_POS_MAX_SIZE);
		ret = -EINVAL;
		goto p_err;
	}

	/* debug option : fixed position testing */
	if (sysfs_actuator->enable_fixed)
		position = sysfs_actuator->fixed_position;

	/* position Set */
	ret = sensor_ak737x_write_position(client, position, actuator);
	if (ret < 0)
		goto p_err;
	actuator->position = position;

	dbg_actuator("%s [%d]: position(%d)\n", __func__, actuator->device, position);

#ifdef DEBUG_ACTUATOR_TIME
	pr_info("[%s] time %ldus", __func__, PABLO_KTIME_US_DELTA_NOW(st));
#endif
p_err:
	IXC_MUTEX_UNLOCK(actuator->ixc_lock);
	return ret;
}

static int sensor_ak737x_actuator_g_ctrl(struct v4l2_subdev *subdev, struct v4l2_control *ctrl)
{
	int ret = 0;
	u32 val = 0;

	switch (ctrl->id) {
	case V4L2_CID_ACTUATOR_GET_STATUS:
		ret = sensor_ak737x_actuator_get_status(subdev, &val);
		if (ret < 0) {
			err("err!!! ret(%d), actuator status(%d)", ret, val);
			ret = -EINVAL;
			goto p_err;
		}
		break;
	default:
		err("err!!! Unknown CID(%#x)", ctrl->id);
		ret = -EINVAL;
		goto p_err;
	}

	ctrl->value = val;

p_err:
	return ret;
}

static int sensor_ak737x_actuator_s_ctrl(struct v4l2_subdev *subdev, struct v4l2_control *ctrl)
{
	int ret = 0;

	switch (ctrl->id) {
	case V4L2_CID_ACTUATOR_SET_POSITION:
		ret = sensor_ak737x_actuator_set_position(subdev, &ctrl->value);
		if (ret) {
			err("failed to actuator set position: %d, (%d)\n", ctrl->value, ret);
			ret = -EINVAL;
			goto p_err;
		}
		break;
	default:
		err("err!!! Unknown CID(%#x)", ctrl->id);
		ret = -EINVAL;
		goto p_err;
	}

p_err:
	return ret;
}

long sensor_ak737x_actuator_ioctl(struct v4l2_subdev *subdev, unsigned int cmd, void *arg)
{
	int ret = 0;
	struct v4l2_control *ctrl;

	ctrl = (struct v4l2_control *)arg;
	switch (cmd) {
	case SENSOR_IOCTL_ACT_S_CTRL:
		ret = sensor_ak737x_actuator_s_ctrl(subdev, ctrl);
		if (ret) {
			err("err!!! actuator_s_ctrl failed(%d)", ret);
			goto p_err;
		}
		break;
	case SENSOR_IOCTL_ACT_G_CTRL:
		ret = sensor_ak737x_actuator_g_ctrl(subdev, ctrl);
		if (ret) {
			err("err!!! actuator_g_ctrl failed(%d)", ret);
			goto p_err;
		}
		break;
	default:
		err("err!!! Unknown command(%#x)", cmd);
		ret = -EINVAL;
		goto p_err;
	}
p_err:
	return (long)ret;
}

#ifdef USE_AF_SLEEP_MODE
static int sensor_ak737x_actuator_set_active(struct v4l2_subdev *subdev, int enable)
{
	int ret = 0;
	struct is_actuator *actuator;
	struct i2c_client *client = NULL;
	struct is_module_enum *module;
	struct is_device_sensor *device;

	FIMC_BUG(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	FIMC_BUG(!actuator);

	client = actuator->client;
	FIMC_BUG(!client);

	device = v4l2_get_subdev_hostdata(subdev);
	FIMC_BUG(!device);

	module = actuator->sensor_peri->module;
	FIMC_BUG(!module);

	if (!actuator->vendor_use_sleep_mode ||
		device->ex_scenario == IS_SCENARIO_SECURE) {
		info("%s : skip sleep/active mode, sleep_mode[%d], ex_scenario[%d]",
			__func__, actuator->vendor_use_sleep_mode, device->ex_scenario);
		return 0;
	}

	pr_info("%s [%d]=%d\n", __func__, actuator->device, enable);

	IXC_MUTEX_LOCK(actuator->ixc_lock);

	if (actuator->vendor_use_temperature)
		actuator->temperature_available = false;

	if (actuator->vendor_use_voltage)
		actuator->voltage_available = false;

	if (actuator->vendor_use_standby_mode) {
		/* Go standby mode */
		actuator->state = ACTUATOR_STATE_STANDBY;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_STANDBY);
		if (ret < 0)
			goto p_err;

		if (enable)
			usleep_range(actuator->vendor_sleep_to_standby_delay, actuator->vendor_sleep_to_standby_delay + 10);
		else
			usleep_range(actuator->vendor_active_to_standby_delay, actuator->vendor_active_to_standby_delay + 10);
	}

	if (enable) {
		sensor_ak737x_init_position(client, actuator);

		/* Go active mode */
		actuator->state = ACTUATOR_STATE_ACTIVE;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_ACTIVE);
		if (ret < 0)
			goto p_err;
		usleep_range(1000, 1010);
		if (actuator->vendor_use_temperature) {
			ret = sensor_ak737x_temperature_sensor_on(client, actuator);
			if (ret < 0)
				goto p_err;
		}
	} else {
		/* Go sleep mode */
		actuator->state = ACTUATOR_STATE_SLEEP;
		ret = actuator->ixc_ops->addr8_write8(client, AK737X_REG_CONT1, AK737X_MODE_SLEEP);
		if (ret < 0)
			goto p_err;
		usleep_range(200, 210);
	}

p_err:
	IXC_MUTEX_UNLOCK(actuator->ixc_lock);
	return ret;
}
#endif

int sensor_ak737x_actuator_get_hall_value(struct v4l2_subdev *subdev, u16 *hall_value)
{
	int ret = 0;
	struct is_actuator *actuator;
	struct i2c_client *client;
	u8 current_mode, hall_hbyte, hall_lbyte;

	*hall_value = 0;

	WARN_ON(!subdev);

	actuator = (struct is_actuator *)v4l2_get_subdevdata(subdev);
	WARN_ON(!actuator);

	client = actuator->client;
	if (unlikely(!client)) {
		err("client is NULL");
		ret = -EINVAL;
		return ret;
	}

	IXC_MUTEX_LOCK(actuator->ixc_lock);

	ret = actuator->ixc_ops->addr8_read8(client, 0x02, &current_mode);
	if (ret) {
		err("actuator i2c failed");
		ret = -EINVAL;
		goto p_err;
	}

	current_mode = current_mode & 0x60;
	if (current_mode != 0x00) {
		err("actuator is not active, current_mode=%d", current_mode);
		ret = -EINVAL;
		goto p_err;
	}

	actuator->ixc_ops->addr8_read8(client, 0x84, &hall_hbyte);
	actuator->ixc_ops->addr8_read8(client, 0x85, &hall_lbyte);
	*hall_value = ((u16)hall_hbyte) << 4 | ((u16)hall_lbyte) >> 4;

	info("[%s] 0x84=%d, 0x85=%d, hall_value=%d\n", __func__, hall_hbyte, hall_lbyte, *hall_value);

p_err:
	IXC_MUTEX_UNLOCK(actuator->ixc_lock);

	return ret;
}

static const struct v4l2_subdev_core_ops core_ops = {
	.init = sensor_ak737x_actuator_init,
	.ioctl = sensor_ak737x_actuator_ioctl,
};

static const struct v4l2_subdev_ops subdev_ops = {
	.core = &core_ops,
};

static struct is_actuator_ops actuator_ops = {
#ifdef USE_AF_SLEEP_MODE
	.set_active = sensor_ak737x_actuator_set_active,
#endif
	.soft_landing_on_recording = sensor_ak737x_soft_landing_on_recording,
	.get_hall_value = sensor_ak737x_actuator_get_hall_value,
};

static ssize_t focus_position_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "max focus position: %d\n",
			AK737X_POS_MAX_SIZE);
}

static ssize_t focus_position_store(struct device *dev,
		struct device_attribute *attr, const char *buf,
		size_t count)
{
	struct is_actuator *actuator;
	struct v4l2_subdev *subdev_actuator;
	int value = 0;

	if (!buf || kstrtouint(buf, 10, &value))
		return -1;

	actuator = (struct is_actuator *)dev_get_drvdata(dev);
	if (!actuator) {
		dev_err(dev, "flash is NULL");
		return -1;
	}

	if (!actuator->sensor_peri) {
		dev_err(dev, "actuator is not available");
		return -1;
	}

	subdev_actuator = actuator->subdev;
	if (!subdev_actuator) {
		dev_err(dev, "subdev_actuator is NULL");
		return -1;
	}

	dev_info(dev, "focus_position control: val(%d)\n", value);

	sensor_ak737x_actuator_set_position(subdev_actuator, &value);

	return count;
}

static DEVICE_ATTR_RW(focus_position);

int sensor_ak737x_actuator_probe_i2c(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	int ret = 0;
	struct is_core *core;
	struct v4l2_subdev *subdev_actuator = NULL;
	struct is_actuator *actuator = NULL;
	struct is_device_sensor *device = NULL;
	u32 sensor_id = 0;
	u32 first_pos = 0;
	u32 first_delay = 0;
	u32 sleep_to_standby_delay = 0;
	u32 active_to_standby_delay = 0;
	u32 vendor_hall_min_interval = 0;
	u32 vendor_hall_hw_param_tolerance = 0;
	bool vendor_use_sleep_mode = false;
	bool vendor_use_standby_mode = false;
	bool vendor_use_temperature = false;
	bool vendor_use_voltage = false;
	bool vendor_use_hall = false;
	struct device *dev;
	struct device_node *dnode;
	const u32 *vendor_soft_landing_list_spec;
	struct class *camera_class;
	char *filename = __getname();

	if (unlikely(!filename)) {
		err("Failed to get filename buffer");
		return -ENOMEM;
	}

	WARN_ON(!client);

	core = pablo_get_core_async();
	if (!core) {
		err("core device is not yet probed");
		ret = -EPROBE_DEFER;
		goto p_err;
	}

	dev = &client->dev;
	dnode = dev->of_node;

	if (of_property_read_bool(dnode, "vendor_use_sleep_mode"))
		vendor_use_sleep_mode = true;

	if (vendor_use_sleep_mode & of_property_read_bool(dnode, "vendor_use_standby_mode"))
		vendor_use_standby_mode = true;

	if (of_property_read_bool(dnode, "vendor_use_temperature"))
		vendor_use_temperature = true;

	if (of_property_read_bool(dnode, "vendor_use_voltage"))
		vendor_use_voltage = true;

	if (of_property_read_bool(dnode, "vendor_use_hall"))
		vendor_use_hall = true;

	ret = of_property_read_u32(dnode, "vendor_first_pos", &first_pos);
	if (ret) {
		first_pos = AK737X_DEFAULT_FIRST_POSITION;
		info("use default first_pos : %d\n", first_pos);
	}

	ret = of_property_read_u32(dnode, "vendor_first_delay", &first_delay);
	if (ret) {
		first_delay = AK737X_DEFAULT_FIRST_DELAY;
		info("use default first_delay : %d\n", first_delay);
	}

	ret = of_property_read_u32(dnode, "vendor_sleep_to_standby_delay", &sleep_to_standby_delay);
	if (ret) {
		sleep_to_standby_delay = AK737X_DEFAULT_SLEEP_TO_STANDBY_DELAY;
		info("use default sleep_to_standby_delay : %d\n", sleep_to_standby_delay);
	}

	ret = of_property_read_u32(dnode, "vendor_active_to_standby_delay", &active_to_standby_delay);
	if (ret) {
		active_to_standby_delay= AK737X_DEFAULT_ACTIVE_TO_STANDBY_DELAY;
		info("use default active_to_standby_delay : %d\n", active_to_standby_delay);
	}

	ret = of_property_read_u32(dnode, "vendor_hall_min_interval", &vendor_hall_min_interval);
	if (ret) {
		vendor_hall_min_interval = AK737X_DEFAULT_HALL_MIN_INTERVAL;
		info("use default vendor_hall_min_interval : %d\n", vendor_hall_min_interval);
	}

	ret = of_property_read_u32(dnode, "vendor_hall_hw_param_tolerance", &vendor_hall_hw_param_tolerance);
	if (ret) {
		vendor_hall_hw_param_tolerance = AK737X_DEFAULT_HALL_HW_PARAM_TOLERANCE;
		info("use default vendor_hall_hw_param_tolerance : %d\n", vendor_hall_hw_param_tolerance);
	}

	ret = of_property_read_u32(dnode, "id", &sensor_id);
	if (ret)
		err("id read is fail(%d)", ret);

	probe_info("%s sensor_id(%d)\n", __func__, sensor_id);

	device = &core->sensor[sensor_id];

	actuator = kzalloc(sizeof(struct is_actuator), GFP_KERNEL);
	if (!actuator) {
		err("actuator is NULL");
		ret = -ENOMEM;
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "vendor_soft_landing_seqid", &actuator->vendor_soft_landing_seqid);
	if (ret) {
		actuator->vendor_soft_landing_seqid = 0;
		warn("vendor_first_pos read is empty(%d)", ret);
	}

	vendor_soft_landing_list_spec = of_get_property(dnode, "vendor_soft_landing_list", &actuator->vendor_soft_landing_list_len);
	if (vendor_soft_landing_list_spec) {
		actuator->vendor_soft_landing_list_len /= (unsigned int)sizeof(*vendor_soft_landing_list_spec);

		ret = of_property_read_u32_array(dnode, "vendor_soft_landing_list",
											actuator->vendor_soft_landing_list, actuator->vendor_soft_landing_list_len);
		if (ret)
			warn("vendor_soft_landing_list is empty(%d)", ret);
	} else {
		actuator->vendor_soft_landing_list_len = 0;
	}

	subdev_actuator = kzalloc(sizeof(struct v4l2_subdev), GFP_KERNEL);
	if (!subdev_actuator) {
		err("subdev_actuator is NULL");
		ret = -ENOMEM;
		kfree(actuator);
		goto p_err;
	}

	actuator->id = ACTUATOR_NAME_AK737X;
	actuator->subdev = subdev_actuator;
	actuator->device = sensor_id;
	actuator->client = client;
	actuator->position = 0;
	actuator->max_position = AK737X_POS_MAX_SIZE;
	actuator->pos_size_bit = AK737X_POS_SIZE_BIT;
	actuator->pos_direction = AK737X_POS_DIRECTION;
	actuator->ixc_lock = NULL;
	actuator->need_softlanding = 0;
	actuator->actuator_ops = &actuator_ops;

	actuator->vendor_product_id = AK737X_PRODUCT_ID_AK7371; // AK737X - initial product_id : AK7371
	actuator->vendor_first_pos = first_pos;
	actuator->vendor_first_delay = first_delay;
	actuator->vendor_sleep_to_standby_delay = sleep_to_standby_delay;
	actuator->vendor_active_to_standby_delay = active_to_standby_delay;
	actuator->vendor_use_sleep_mode = vendor_use_sleep_mode;
	actuator->vendor_use_standby_mode = vendor_use_standby_mode;
	actuator->vendor_use_temperature = vendor_use_temperature;
	actuator->vendor_use_voltage = vendor_use_voltage;
	actuator->vendor_use_hall = vendor_use_hall;
	actuator->vendor_hall_min_interval = vendor_hall_min_interval;
	actuator->vendor_hall_hw_param_tolerance = vendor_hall_hw_param_tolerance;
	actuator->ixc_ops = pablo_get_i2c();

	device->subdev_actuator[sensor_id] = subdev_actuator;
	device->actuator[sensor_id] = actuator;

	v4l2_i2c_subdev_init(subdev_actuator, client, &subdev_ops);
	v4l2_set_subdevdata(subdev_actuator, actuator);
	v4l2_set_subdev_hostdata(subdev_actuator, device);

	snprintf(subdev_actuator->name, V4L2_SUBDEV_NAME_SIZE, "actuator-subdev.%d", actuator->id);

	camera_class = is_get_camera_class();
	sprintf(filename, "actuator%d", sensor_id);

	camera_focus_dev[sensor_id] = device_create(camera_class, NULL, 3, actuator, filename);

	if (IS_ERR(camera_focus_dev[sensor_id])) {
		dev_err(dev, "failed to create focus device\n");
		goto p_err;
	}

	ret = device_create_file(camera_focus_dev[sensor_id], &dev_attr_focus_position);
	if (ret)
		dev_err(camera_focus_dev[sensor_id],
			"failed to create device file %s\n",
			dev_attr_focus_position.attr.name);

p_err:
	__putname(filename);
	probe_info("%s done\n", __func__);
	return ret;
}
static const struct of_device_id exynos_is_ak737x_match[] = {
	{
		.compatible = "samsung,exynos-is-actuator-ak737x",
	},
	{},
};
MODULE_DEVICE_TABLE(of, exynos_is_ak737x_match);

static const struct i2c_device_id actuator_ak737x_idt[] = {
	{ ACTUATOR_NAME, 0 },
	{},
};

static struct i2c_driver actuator_ak737x_driver = {
	.probe	= sensor_ak737x_actuator_probe_i2c,
	.driver = {
		.name	= ACTUATOR_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = exynos_is_ak737x_match,
		.suppress_bind_attrs = true,
	},
	.id_table = actuator_ak737x_idt
};
builtin_i2c_driver(actuator_ak737x_driver);

MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: fimc-is");
