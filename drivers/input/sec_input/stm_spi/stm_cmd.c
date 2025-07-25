#include "stm_dev.h"
#include "stm_reg.h"

enum {
	TYPE_RAW_DATA = 0x30,			// only for winner, etc 0x31
	TYPE_FILTERED_RAW_DATA = 0x31,	// only for winner
	TYPE_BASELINE_DATA = 0x32,
	TYPE_STRENGTH_DATA = 0x33,
};

enum ito_error_type {
	ITO_FORCE_SHRT_GND		= 0x60,
	ITO_SENSE_SHRT_GND		= 0x61,
	ITO_FORCE_SHRT_VDD		= 0x62,
	ITO_SENSE_SHRT_VDD		= 0x63,
	ITO_FORCE_SHRT_FORCE	= 0x64,
	ITO_SENSE_SHRT_SENSE	= 0x65,
	ITO_FORCE_OPEN			= 0x66,
	ITO_SENSE_OPEN			= 0x67,
	ITO_KEY_OPEN			= 0x68
};

static ssize_t scrub_pos_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[256] = { 0 };

#if IS_ENABLED(CONFIG_SAMSUNG_PRODUCT_SHIP)
	input_info(true, ts->dev,
			"%s: id: %d\n", __func__, ts->plat_data->gesture_id);
#else
	input_info(true, ts->dev,
			"%s: id: %d, X:%d, Y:%d\n", __func__,
			ts->plat_data->gesture_id, ts->plat_data->gesture_x, ts->plat_data->gesture_y);
#endif
	snprintf(buff, sizeof(buff), "%d %d %d", ts->plat_data->gesture_id,
			ts->plat_data->gesture_x, ts->plat_data->gesture_y);

	ts->plat_data->gesture_x = 0;
	ts->plat_data->gesture_y = 0;

	return snprintf(buf, PAGE_SIZE, "%s", buff);
}

/* read param */
static ssize_t hw_param_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[516];
	char tbuff[128];
	char temp[128];

	memset(buff, 0x00, sizeof(buff));

	sec_input_get_common_hw_param(ts->plat_data, buff);

	/* module_id */
	memset(tbuff, 0x00, sizeof(tbuff));
	snprintf(tbuff, sizeof(tbuff), ",\"TMOD\":\"ST%02X%04X%02X%c%01X\",",
			ts->panel_revision, ts->fw_main_version_of_ic,
			ts->test_result.data[0],
#ifdef TCLM_CONCEPT
			ts->tdata->tclm_string[ts->tdata->nvdata.cal_position].s_name,
			ts->tdata->nvdata.cal_count & 0xF);
#else
			'0', 0);
#endif
	strlcat(buff, tbuff, sizeof(buff));

	/* vendor_id */
	memset(tbuff, 0x00, sizeof(tbuff));
	if (ts->plat_data->firmware_name) {
		memset(temp, 0x00, sizeof(temp));
		snprintf(temp, 9, "%s", ts->plat_data->firmware_name + 8);

		snprintf(tbuff, sizeof(tbuff), "\"TVEN\":\"STM_%s\"", temp);
	} else {
		snprintf(tbuff, sizeof(tbuff), "\"TVEN\":\"STM\"");
	}
	strlcat(buff, tbuff, sizeof(buff));

	input_info(true, ts->dev, "%s: %s\n", __func__, buff);

	return snprintf(buf, SEC_CMD_BUF_SIZE, "%s", buff);
}

/* clear param */
static ssize_t hw_param_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	sec_input_clear_common_hw_param(ts->plat_data);

	return count;
}

static ssize_t read_ambient_info_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_info(true, ts->dev,
			"\"TAMB_MAX\":\"%d\",\"TAMB_MAX_TX\":\"%d\",\"TAMB_MAX_RX\":\"%d\""
			"\"TAMB_MIN\":\"%d\",\"TAMB_MIN_TX\":\"%d\",\"TAMB_MIN_RX\":\"%d\"",
			ts->rawcap_max, ts->rawcap_max_tx, ts->rawcap_max_rx,
			ts->rawcap_min, ts->rawcap_min_tx, ts->rawcap_min_rx);

	return snprintf(buf, SEC_CMD_BUF_SIZE,
			"\"TAMB_MAX\":\"%d\",\"TAMB_MAX_TX\":\"%d\",\"TAMB_MAX_RX\":\"%d\","
			"\"TAMB_MIN\":\"%d\",\"TAMB_MIN_TX\":\"%d\",\"TAMB_MIN_RX\":\"%d\"",
			ts->rawcap_max, ts->rawcap_max_tx, ts->rawcap_max_rx,
			ts->rawcap_min, ts->rawcap_min_tx, ts->rawcap_min_rx);
}

static ssize_t sensitivity_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	unsigned char wbuf[3] = { 0 };
	unsigned long value = 0;
	int ret = 0;

	if (count > 2)
		return -EINVAL;

	ret = kstrtoul(buf, 10, &value);
	if (ret != 0)
		return ret;

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: [ERROR] Touch is stopped\n", __func__);
		return -EPERM;
	}

	cancel_delayed_work(&ts->work_print_info);

	wbuf[0] = STM_TS_CMD_SENSITIVITY_MODE;

	switch (value) {
	case 0:
		wbuf[1] = 0xFF; /* disable */
		break;
	case 1:
		wbuf[1] = 0x24; /* enable */
		wbuf[2] = 0x01;
		ts->sensitivity_mode = 1;
		break;
	case 2:
		wbuf[1] = 0x24; /* flex mode enable */
		wbuf[2] = 0x02;
		ts->sensitivity_mode = 2;
		break;
	default:
		break;
	}

	ret = ts->stm_ts_write(ts, &wbuf[0], 1, &wbuf[1], 2);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: write failed. ret: %d\n", __func__, ret);
		schedule_delayed_work(&ts->work_print_info, msecs_to_jiffies(TOUCH_PRINT_INFO_DWORK_TIME));
		return ret;
	}

	sec_delay(30);

	if (value == 0)
		schedule_delayed_work(&ts->work_print_info, msecs_to_jiffies(TOUCH_PRINT_INFO_DWORK_TIME));

	input_info(true, ts->dev, "%s: %ld\n", __func__, value);
	return count;
}

static ssize_t sensitivity_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	u8 *rbuf;
	u8 reg_read = STM_TS_READ_SENSITIVITY_VALUE;
	int ret, i;
	s16 value[12];
	u8 count = 9;
	char *buffer;
	ssize_t len;

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: [ERROR] Touch is stopped\n", __func__);
		return -EPERM;
	}

	if (ts->sensitivity_mode == 2)	/* flex mode */
		count = 12;

	rbuf = kzalloc(count * 2, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	buffer = kzalloc(SEC_CMD_BUF_SIZE, GFP_KERNEL);
	if (!buffer) {
		kfree(rbuf);
		return -ENOMEM;
	}

	ret = ts->stm_ts_read(ts, &reg_read, 1, rbuf, count * 2);
	if (ret < 0) {
		kfree(rbuf);
		kfree(buffer);
		input_err(true, ts->dev, "%s: read failed ret = %d\n", __func__, ret);
		return ret;
	}

	for (i = 0; i < count; i++) {
		char temp[16];

		memset(temp, 0x00, 16);
		value[i] = rbuf[i * 2] + (rbuf[i * 2 + 1] << 8);
		snprintf(temp, 16, "%d,", value[i]);
		strlcat(buffer, temp, SEC_CMD_BUF_SIZE);
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, buffer);
	len = snprintf(buf, SEC_CMD_BUF_SIZE, "%s", buffer);

	kfree(rbuf);
	kfree(buffer);

	return len;
}

ssize_t get_lp_dump_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	u8 string_data[10] = {0, };
	u16 current_index;
	u16 dump_start, dump_end, dump_cnt;
	int i, ret, dump_area, dump_gain;
	unsigned char *sec_spg_dat;
	u8 data[3] = {0};

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: Touch is stopped!\n", __func__);
		if (buf)
			return snprintf(buf, SEC_CMD_BUF_SIZE, "TSP turned off");
		else
			return 0;
	}

	if (atomic_read(&ts->reset_is_on_going)) {
		input_err(true, ts->dev, "%s: Reset is ongoing!\n", __func__);
		if (buf)
			return snprintf(buf, SEC_CMD_BUF_SIZE, "Reset is ongoing");
		else
			return 0;
	}

	/* preparing dump buffer */
	sec_spg_dat = vmalloc(SEC_TS_MAX_SPONGE_DUMP_BUFFER);
	if (!sec_spg_dat) {
		input_err(true, ts->dev, "%s : Failed!!\n", __func__);
		if (buf)
			return snprintf(buf, SEC_CMD_BUF_SIZE, "vmalloc failed");
		else
			return 0;
	}
	memset(sec_spg_dat, 0, SEC_TS_MAX_SPONGE_DUMP_BUFFER);

	disable_irq(ts->irq);

	string_data[0] = SEC_TS_CMD_SPONGE_LP_DUMP_CUR_IDX;

	ret = ts->stm_ts_read_sponge(ts, string_data, 2);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: Failed to read rect\n", __func__);
		if (buf)
			snprintf(buf, SEC_CMD_BUF_SIZE, "NG, Failed to read rect");
		goto out;
	}

	if (ts->sponge_inf_dump)
		dump_gain = 2;
	else
		dump_gain = 1;

	current_index = (string_data[1] & 0xFF) << 8 | (string_data[0] & 0xFF);
	dump_start = SEC_TS_CMD_SPONGE_LP_DUMP_EVENT;
	dump_end = dump_start + (ts->sponge_dump_format * ((ts->sponge_dump_event * dump_gain) - 1));

	if (current_index == 0) {
		input_info(true, ts->dev, "%s: length 0\n", __func__);
		if (buf)
			snprintf(buf, SEC_CMD_BUF_SIZE, "length 0");
		goto out;
	}

	if (current_index > dump_end || current_index < dump_start) {
		input_err(true, ts->dev,
				"Failed to Sponge LP log %d\n", current_index);
		if (buf)
			snprintf(buf, SEC_CMD_BUF_SIZE,
				"NG, Failed to Sponge LP log, current_index=%d",
				current_index);
		goto out;
	}

	/* legacy get_lp_dump */
	input_info(true, ts->dev, "%s: DEBUG format=%d, num=%d, start=%d, end=%d, current_index=%d\n",
			__func__, ts->sponge_dump_format, ts->sponge_dump_event, dump_start, dump_end, current_index);

	for (i = (ts->sponge_dump_event * dump_gain) - 1 ; i >= 0 ; i--) {
		u16 data0, data1, data2, data3, data4;
		char buff[30] = {0, };
		u16 string_addr;

		if (current_index < (ts->sponge_dump_format * i))
			string_addr = (ts->sponge_dump_format * ts->sponge_dump_event * dump_gain) + current_index - (ts->sponge_dump_format * i);
		else
			string_addr = current_index - (ts->sponge_dump_format * i);

		if (string_addr < dump_start)
			string_addr += (ts->sponge_dump_format * ts->sponge_dump_event * dump_gain);

		string_data[0] = string_addr & 0xFF;
		string_data[1] = (string_addr & 0xFF00) >> 8;

		if (ts->sponge_dump_format > 10) {
			input_err(true, ts->dev, "%s: wrong sponge sponge_dump_format size:%d\n", __func__, ts->sponge_dump_format);
			if (buf)
				snprintf(buf, SEC_CMD_BUF_SIZE, "NG,wrong sponge_dump_format");
			goto out;
		}

		ret = ts->stm_ts_read_sponge(ts, string_data, ts->sponge_dump_format);
		if (ret < 0) {
			input_err(true, ts->dev,
					"%s: Failed to read sponge\n", __func__);
			if (buf)
				snprintf(buf, SEC_CMD_BUF_SIZE,
					"NG, Failed to read sponge, addr=%d",
					string_addr);
			goto out;
		}

		data0 = (string_data[1] & 0xFF) << 8 | (string_data[0] & 0xFF);
		data1 = (string_data[3] & 0xFF) << 8 | (string_data[2] & 0xFF);
		data2 = (string_data[5] & 0xFF) << 8 | (string_data[4] & 0xFF);
		data3 = (string_data[7] & 0xFF) << 8 | (string_data[6] & 0xFF);
		data4 = (string_data[9] & 0xFF) << 8 | (string_data[8] & 0xFF);

		if (data0 || data1 || data2 || data3 || data4) {
			if (ts->sponge_dump_format == 10) {
				snprintf(buff, sizeof(buff),
						"%d: %04x%04x%04x%04x%04x\n",
						string_addr, data0, data1, data2, data3, data4);
			} else {
				snprintf(buff, sizeof(buff),
						"%d: %04x%04x%04x%04x\n",
						string_addr, data0, data1, data2, data3);
			}
			if (buf)
				strlcat(buf, buff, PAGE_SIZE);
		}
	}

	if (ts->sponge_inf_dump) {
		if (current_index >= ts->sponge_dump_border) {
			dump_cnt = ((current_index - (ts->sponge_dump_border)) / ts->sponge_dump_format) + 1;
			dump_area = 1;
			sec_spg_dat[0] = (u8)ts->sponge_dump_border & 0xff;
			sec_spg_dat[1] = (u8)(ts->sponge_dump_border >> 8);
		} else {
			dump_cnt = ((current_index - SEC_TS_CMD_SPONGE_LP_DUMP_EVENT) / ts->sponge_dump_format) + 1;
			dump_area = 0;
			sec_spg_dat[0] = SEC_TS_CMD_SPONGE_LP_DUMP_EVENT;
			sec_spg_dat[1] = 0;
		}

		if (dump_cnt * ts->sponge_dump_format > SEC_TS_MAX_SPONGE_DUMP_BUFFER) {
			input_err(true, ts->dev, "%s: wrong sponge sponge_dump_format size:%d dump_cnt:%d\n",
				__func__, ts->sponge_dump_format, dump_cnt);
			if (buf)
				snprintf(buf, SEC_CMD_BUF_SIZE, "NG,wrong sponge_dump_format");
			goto out;
		}

		ret = ts->stm_ts_read_sponge(ts, sec_spg_dat, dump_cnt * ts->sponge_dump_format);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: Failed to read sponge\n", __func__);
			goto out;
		}

		for (i = 0 ; i <= dump_cnt ; i++) {
			int e_offset = i * ts->sponge_dump_format;
			char ibuff[30] = {0, };
			u16 edata[5];

			edata[0] = (sec_spg_dat[1 + e_offset] & 0xFF) << 8 | (sec_spg_dat[0 + e_offset] & 0xFF);
			edata[1] = (sec_spg_dat[3 + e_offset] & 0xFF) << 8 | (sec_spg_dat[2 + e_offset] & 0xFF);
			edata[2] = (sec_spg_dat[5 + e_offset] & 0xFF) << 8 | (sec_spg_dat[4 + e_offset] & 0xFF);
			edata[3] = (sec_spg_dat[7 + e_offset] & 0xFF) << 8 | (sec_spg_dat[6 + e_offset] & 0xFF);
			edata[4] = (sec_spg_dat[9 + e_offset] & 0xFF) << 8 | (sec_spg_dat[8 + e_offset] & 0xFF);

			if (edata[0] || edata[1] || edata[2] || edata[3] || edata[4]) {
				snprintf(ibuff, sizeof(ibuff), "%03d: %04x%04x%04x%04x%04x\n",
						i + (ts->sponge_dump_event * dump_area),
						edata[0], edata[1], edata[2], edata[3], edata[4]);
#if IS_ENABLED(CONFIG_SEC_DEBUG_TSP_LOG)
				sec_tsp_sponge_log(ibuff);
#endif
			}
		}

		ts->sponge_dump_delayed_flag = false;
		data[0] = STM_TS_CMD_SPONGE_OFFSET_MODE_01;
		data[2] = ts->plat_data->sponge_mode |= SEC_TS_MODE_SPONGE_INF_DUMP_CLEAR;

		ret = ts->stm_ts_write_sponge(ts, data, 3);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: Failed to clear sponge dump\n", __func__);
		}
		ts->plat_data->sponge_mode &= ~SEC_TS_MODE_SPONGE_INF_DUMP_CLEAR;
	}
out:
	vfree(sec_spg_dat);
	enable_irq(ts->irq);

	if (buf)
		return strlen(buf);
	else
		return 0;
}

static ssize_t ear_detect_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_info(true, ts->dev, "%s: %d\n", __func__,
			ts->plat_data->ed_enable);

	return snprintf(buf, SEC_CMD_BUF_SIZE, "%d", ts->plat_data->ed_enable);
}

static ssize_t ear_detect_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret, value;
	u8 address = STM_TS_CMD_SET_EAR_DETECT;

	ret = kstrtoint(buf, 10, &value);
	if (ret < 0)
		return ret;

	if (ts->plat_data->support_ear_detect) {
		ts->plat_data->ed_enable = value;
		ret = ts->stm_ts_write(ts, &address, 1, &ts->plat_data->ed_enable, 1);
		input_info(true, ts->dev, "%s: set ear detect %s, ret = %d\n",
					__func__, ts->plat_data->ed_enable ? "enable" : "disable", ret);
	}

	return count;
}

static ssize_t virtual_prox_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_info(true, ts->dev, "%s: %d\n", __func__, ts->hover_event);

	return snprintf(buf, SEC_CMD_BUF_SIZE, "%d", ts->hover_event != 3 ? 0 : 3);
}

static ssize_t virtual_prox_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;
	u8 address;
	u8 data;

	if (!ts->plat_data->support_ear_detect) {
		input_err(true, ts->dev, "%s: ear detection is not supported\n", __func__);
		return -ENODEV;
	}

	ret = kstrtou8(buf, 8, &data);
	if (ret < 0)
		return ret;

	address = STM_TS_CMD_SET_EAR_DETECT;

	ret = ts->stm_ts_write(ts, &address, 1, &data, 1);
	input_info(true, ts->dev, "%s: set %d: ret:%d\n", __func__, data, ret);

	return count;
}

static ssize_t fod_pos_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[3] = { 0 };
	int i, ret;

	if (!ts->plat_data->support_fod) {
		input_err(true, ts->dev, "%s: fod is not supported\n", __func__);
		return snprintf(buf, SEC_CMD_BUF_SIZE, "NA");
	}

	if (!ts->plat_data->fod_data.vi_size) {
		input_err(true, ts->dev, "%s: not read fod_info yet\n", __func__);
		return snprintf(buf, SEC_CMD_BUF_SIZE, "NG");
	}

	if (!ts->plat_data->support_fod_lp_mode) {
		ret = stm_ts_fod_vi_event(ts);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: Failed to read\n", __func__);
			return snprintf(buf, SEC_CMD_BUF_SIZE, "NG");
		}
	}

	for (i = 0; i < ts->plat_data->fod_data.vi_size; i++) {
		snprintf(buff, 3, "%02X", ts->plat_data->fod_data.vi_data[i]);
		strlcat(buf, buff, SEC_CMD_BUF_SIZE);
	}

	return strlen(buf);
}

static ssize_t fod_info_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	return sec_input_get_fod_info(ts->dev, buf);
}

static ssize_t aod_active_area_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sec_cmd_data *sec = dev_get_drvdata(dev);
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_info(true, ts->dev, "%s: top:%d, edge:%d, bottom:%d\n",
			__func__, ts->plat_data->aod_data.active_area[0],
			ts->plat_data->aod_data.active_area[1], ts->plat_data->aod_data.active_area[2]);

	return snprintf(buf, SEC_CMD_BUF_SIZE, "%d,%d,%d",
			ts->plat_data->aod_data.active_area[0], ts->plat_data->aod_data.active_area[1],
			ts->plat_data->aod_data.active_area[2]);
}

static DEVICE_ATTR_RO(scrub_pos);
static DEVICE_ATTR_RW(hw_param);
static DEVICE_ATTR_RO(read_ambient_info);
static DEVICE_ATTR_RW(sensitivity_mode);
static DEVICE_ATTR_RO(get_lp_dump);
static DEVICE_ATTR_RW(ear_detect_enable);
static DEVICE_ATTR_RW(virtual_prox);
static DEVICE_ATTR_RO(fod_pos);
static DEVICE_ATTR_RO(fod_info);
static DEVICE_ATTR_RO(aod_active_area);

static struct attribute *cmd_attributes[] = {
	&dev_attr_scrub_pos.attr,
	&dev_attr_hw_param.attr,
	&dev_attr_read_ambient_info.attr,
	&dev_attr_sensitivity_mode.attr,
	&dev_attr_get_lp_dump.attr,
	&dev_attr_ear_detect_enable.attr,
	&dev_attr_virtual_prox.attr,
	&dev_attr_fod_pos.attr,
	&dev_attr_fod_info.attr,
	&dev_attr_aod_active_area.attr,
	NULL,
};

static struct attribute_group cmd_attr_group = {
	.attrs = cmd_attributes,
};

static void enter_factory_mode(struct stm_ts_data *ts, bool fac_mode)
{
	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF))
		return;

	ts->stm_ts_systemreset(ts, 50);

	stm_ts_release_all_finger(ts);

	if (fac_mode) {
		stm_ts_execute_autotune(ts, false);
		sec_delay(50);
	}

	stm_ts_set_scanmode(ts, ts->scan_mode);

	sec_delay(50);
}

static int stm_ts_check_index(struct stm_ts_data *ts)
{
	struct sec_cmd_data *sec = &ts->sec;
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int node;

	if (sec->cmd_param[0] < 0
			|| sec->cmd_param[0] >= ts->rx_count
			|| sec->cmd_param[1] < 0
			|| sec->cmd_param[1] >= ts->tx_count) {

		snprintf(buff, sizeof(buff), "%s", "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_err(true, ts->dev, "%s: parameter error: %u,%u\n",
				__func__, sec->cmd_param[0], sec->cmd_param[1]);
		node = -1;
		return node;
	}
	node = sec->cmd_param[1] * ts->rx_count + sec->cmd_param[0];
	input_info(true, ts->dev, "%s: node = %d\n", __func__, node);
	return node;
}

static void stm_ts_print_channel(struct stm_ts_data *ts, s16 *tx_data, s16 *rx_data)
{
	unsigned char *pStr = NULL;
	unsigned char pTmp[16] = { 0 };
	int len, max_num  = 0;
	int i = 0, k = 0;
	int tx_count = ts->tx_count;
	int rx_count = ts->rx_count;

	if (tx_count > 20)
		max_num = 10;
	else
		max_num = tx_count;

	if (!max_num)
		return;

	len = 7 * (max_num + 1);
	pStr = vzalloc(len);
	if (!pStr)
		return;

	/* Print TX channel */
	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " TX");
	strlcat(pStr, pTmp, len);

	for (k = 0; k < max_num; k++) {
		snprintf(pTmp, sizeof(pTmp), "    %02d", k);
		strlcat(pStr, pTmp, len);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " +");
	strlcat(pStr, pTmp, len);

	for (k = 0; k < max_num; k++) {
		snprintf(pTmp, sizeof(pTmp), "------");
		strlcat(pStr, pTmp, len);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " | ");
	strlcat(pStr, pTmp, len);

	for (i = 0; i < tx_count; i++) {
		if (i && i % max_num == 0) {
			input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);
			memset(pStr, 0x0, len);
			snprintf(pTmp, sizeof(pTmp), " | ");
			strlcat(pStr, pTmp, len);
		}

		snprintf(pTmp, sizeof(pTmp), " %5d", tx_data[i]);
		strlcat(pStr, pTmp, len);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	/* Print RX channel */
	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " RX");
	strlcat(pStr, pTmp, len);

	for (k = 0; k < max_num; k++) {
		snprintf(pTmp, sizeof(pTmp), "    %02d", k);
		strlcat(pStr, pTmp, len);
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " +");
	strlcat(pStr, pTmp, len);

	for (k = 0; k < max_num; k++) {
		snprintf(pTmp, sizeof(pTmp), "------");
		strlcat(pStr, pTmp, len);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	memset(pStr, 0x0, len);
	snprintf(pTmp, sizeof(pTmp), " | ");
	strlcat(pStr, pTmp, len);

	for (i = 0; i < rx_count; i++) {
		if (i && i % max_num == 0) {
			input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);
			memset(pStr, 0x0, len);
			snprintf(pTmp, sizeof(pTmp), " | ");
			strlcat(pStr, pTmp, len);
		}

		snprintf(pTmp, sizeof(pTmp), " %5d", rx_data[i]);
		strlcat(pStr, pTmp, len);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	vfree(pStr);
}

void stm_ts_print_frame(struct stm_ts_data *ts, short *min, short *max)
{
	int i = 0;
	int j = 0;
	u8 *pStr = NULL;
	u8 pTmp[16] = { 0 };
	int lsize = 6 * (ts->rx_count + 1);

	pStr = kzalloc(lsize, GFP_KERNEL);
	if (pStr == NULL)
		return;

	snprintf(pTmp, 4, "    ");
	strlcat(pStr, pTmp, lsize);

	for (i = 0; i < ts->rx_count; i++) {
		snprintf(pTmp, 6, "Rx%02d  ", i);
		strlcat(pStr, pTmp, lsize);
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	memset(pStr, 0x0, 6 * (ts->rx_count + 1));
	snprintf(pTmp, 2, " +");
	strlcat(pStr, pTmp, lsize);

	for (i = 0; i < ts->rx_count; i++) {
		snprintf(pTmp, 6, "------");
		strlcat(pStr, pTmp, lsize);
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);

	for (i = 0; i < ts->tx_count; i++) {
		memset(pStr, 0x0, 6 * (ts->rx_count + 1));
		snprintf(pTmp, 7, "Tx%02d | ", i);
		strlcat(pStr, pTmp, lsize);

		for (j = 0; j < ts->rx_count; j++) {
			snprintf(pTmp, 6, "%5d ", ts->pFrame[(i * ts->rx_count) + j]);
			strlcat(pStr, pTmp, lsize);

			if (ts->pFrame[(i * ts->rx_count) + j] < *min)
				*min = ts->pFrame[(i * ts->rx_count) + j];

			if (ts->pFrame[(i * ts->rx_count) + j] > *max)
				*max = ts->pFrame[(i * ts->rx_count) + j];
		}
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s, min:%d, max:%d\n", __func__, *min, *max);

	kfree(pStr);
}

int stm_ts_read_frame(struct stm_ts_data *ts, u8 type, short *min, short *max)
{
	struct stm_ts_syncframeheader *psyncframeheader;
	u8 reg[8] = { 0 };
	unsigned int totalbytes = 0;
	u8 *pRead;
	int ret = 0;
	int i = 0, j = 0;
	int retry = 10;

	pRead = kzalloc(ts->tx_count * ts->rx_count * 3 + 1, GFP_KERNEL);
	if (!pRead)
		return -ENOMEM;
	
	/* Request Data Type */
	reg[0] = 0xA4;
	reg[1] = 0x06;
	reg[2] = (u8)type;
	ts->stm_ts_write(ts, &reg[0], 3, NULL, 0);
	sec_delay(50);

	do {
		reg[0] = STM_TS_CMD_FRM_BUFF_R;
		reg[1] = 0x00;
		reg[2] = 0x00;
		ret = ts->stm_ts_read(ts, &reg[0], 3, &pRead[0], STM_TS_COMP_DATA_HEADER_SIZE);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: failed to read stm_ts_comp_data_header_size\n", __func__);
			goto ERROREXIT;
		}

		psyncframeheader = (struct stm_ts_syncframeheader *) &pRead[0];

		if ((psyncframeheader->header == 0xA5) && (psyncframeheader->host_data_mem_id == type))
			break;

		sec_delay(100);
	} while (retry--);

	if (retry == 0) {
		input_err(true, ts->dev,
				"%s: didn't match header or id. header = %02X, id = %02X\n",
				__func__, psyncframeheader->header, psyncframeheader->host_data_mem_id);
		ret = -STM_TS_ERROR_INVALID_CHIP_VERSION_ID;
		goto ERROREXIT;
	}

	totalbytes = (ts->tx_count * ts->rx_count  * 2);

	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = 0x00;
	reg[2] = STM_TS_COMP_DATA_HEADER_SIZE + psyncframeheader->dbg_frm_len;
	ret = ts->stm_ts_read(ts, &reg[0], 3, &pRead[0], totalbytes);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to read totalbytes\n", __func__);
		goto ERROREXIT;
	}

	for (i = 0; i < totalbytes / 2; i++)
		ts->pFrame[i] = (short)(pRead[i * 2] + (pRead[i * 2 + 1] << 8));

	switch (type) {
	case TYPE_RAW_DATA:
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s", "[Raw Data]\n");
		break;
	case TYPE_STRENGTH_DATA:
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: [Strength Data]\n", __func__);
		break;
	case TYPE_BASELINE_DATA:
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: [Baseline Data]\n", __func__);
		break;
	}

	stm_ts_print_frame(ts, min, max);

	if (!ts->info_work_done) {
		if (type == TYPE_RAW_DATA) {
			for (j = 0; j < ts->tx_count; j++) {
				for (i = 0; i < ts->rx_count; i++) {
					if (ts->rawcap_max < ts->pFrame[j * ts->rx_count + i]) {
						ts->rawcap_max = ts->pFrame[j * ts->rx_count + i];
						ts->rawcap_max_tx = j;
						ts->rawcap_max_rx = i;
					}
					if (ts->rawcap_min > ts->pFrame[j * ts->rx_count + i]) {
						ts->rawcap_min = ts->pFrame[j * ts->rx_count + i];
						ts->rawcap_min_tx = j;
						ts->rawcap_min_rx = i;
					}
				}
			}
		}
	}
ERROREXIT:
	kfree(pRead);
	return ret;
}

int stm_ts_read_nonsync_frame(struct stm_ts_data *ts, short *min, short *max)
{
	struct stm_ts_syncframeheader *psyncframeheader;
	u8 reg[8] = { 0 };
	unsigned int totalbytes = 0;
	u8 *pRead;
	int ret = 0;
	int i = 0;
	int retry = 10;

	input_info(true, ts->dev, "%s\n", __func__);

	pRead = kzalloc(ts->tx_count * ts->rx_count * 3 + 1, GFP_KERNEL);
	if (!pRead)
		return -ENOMEM;

	/* Request System Information */
	reg[0] = 0xA4;
	reg[1] = 0x06;
	reg[2] = 0x01;
	ts->stm_ts_write(ts, &reg[0], 3, NULL, 0);
	sec_delay(50);

	do {
		reg[0] = STM_TS_CMD_FRM_BUFF_R;
		reg[1] = 0x00;
		reg[2] = 0x00;
		ret = ts->stm_ts_read(ts, &reg[0], 3, &pRead[0], STM_TS_COMP_DATA_HEADER_SIZE);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: failed to read stm_ts_comp_data_header_size\n", __func__);
			goto ERROREXIT;
		}

		psyncframeheader = (struct stm_ts_syncframeheader *) &pRead[0];

		if ((psyncframeheader->header == 0xA5) && (psyncframeheader->host_data_mem_id == 0x01))
			break;

		sec_delay(100);
	} while (retry--);

	if (retry == 0) {
		input_err(true, ts->dev,
				"%s: didn't match header or id. header = %02X, id = %02X\n",
				__func__, psyncframeheader->header, psyncframeheader->host_data_mem_id);
		ret = -STM_TS_ERROR_INVALID_CHIP_VERSION_ID;
		goto ERROREXIT;
	}

	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = 0x00;
	reg[2] = 0x88;   // ms screen rawdata
	ret = ts->stm_ts_read(ts, &reg[0], 3, &pRead[0], 2);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to read ms screen rawdata(0x88)\n", __func__);
		goto ERROREXIT;
	}

	totalbytes = (ts->tx_count * ts->rx_count  * 2);

	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = (u8)pRead[1];
	reg[2] = (u8)pRead[0];
	ret = ts->stm_ts_read(ts, &reg[0], 3, &pRead[0], totalbytes);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to read totalbytes\n", __func__);
		goto ERROREXIT;
	}

	for (i = 0; i < totalbytes / 2; i++)
		ts->pFrame[i] = (short)(pRead[i * 2] + (pRead[i * 2 + 1] << 8));

	stm_ts_print_frame(ts, min, max);

ERROREXIT:
	kfree(pRead);
	return ret;
}

#define JITTER_TEST_RETRY	10
int stm_ts_get_jitter_result(struct stm_ts_data *ts, u8 *reg, u8 count, s16 *result, u8 type)
{
	int ret = 0;
	u8 address;
	u8 data[STM_TS_EVENT_BUFF_SIZE];
	int retry = 0;
	int retry_time = JITTER_TEST_RETRY;

	if (type == STM_TS_EVENT_JITTER_DELTA_TEST)
		retry_time = JITTER_TEST_RETRY * 5;

	stm_ts_release_all_finger(ts);

	mutex_lock(&ts->fn_mutex);
	disable_irq(ts->irq);

	ret = stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_TRUE);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to set active mode\n", __func__);
		goto ERROR;
	}

	ret = ts->stm_ts_write(ts, reg, count, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to write command\n", __func__);
		goto ERROR;
	}

	sec_delay(5);

	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);

	address = STM_TS_READ_ONE_EVENT;
	ret = -1;
	while (ts->stm_ts_read(ts, &address, 1, data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		if (data[0] != 0x00)
			input_info(true, ts->dev,
					"%s: event %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X\n",
					__func__, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

		if ((data[0] == STM_TS_EVENT_JITTER_RESULT) && (data[1] == 0x03)) {
			if ((type == STM_TS_EVENT_JITTER_MUTUAL_TEST) || (type == STM_TS_EVENT_JITTER_SELF_TEST)) {
				if (data[2] == STM_TS_EVENT_JITTER_MUTUAL_MAX) {
					result[1] = (s16)((data[8] << 8) + data[9]);
					input_info(true, ts->dev, "%s: Mutual max jitter Strength : %d, RX:%d, TX:%d\n",
							__func__, result[1], data[5], data[6]);
				} else if (data[2] == STM_TS_EVENT_JITTER_MUTUAL_MIN) {
					result[0] = (s16)((data[3] << 8) + data[4]);
					input_info(true, ts->dev, "%s: Mutual min jitter Strength : %d, RX:%d, TX:%d\n",
							__func__, result[0], data[5], data[6]);
					ret = 0;
					break;
				} else if (data[2] == STM_TS_EVENT_JITTER_SELF_TX_P2P) {
					result[0] = (s16)((data[3] << 8) + data[4]);
					input_info(true, ts->dev, "%s: Self TX P2P jitter Strength : %d, TX:%d\n",
							__func__, result[0], data[6]);
				} else if (data[2] == STM_TS_EVENT_JITTER_SELF_RX_P2P) {
					result[1] = (s16)((data[3] << 8) + data[4]);
					input_info(true, ts->dev, "%s: Self RX P2P jitter Strength : %d, RX:%d\n",
							__func__, result[1], data[5]);
					ret = 0;
					break;
				}
			} else if (type == STM_TS_EVENT_JITTER_DELTA_TEST) {
				if (data[2] == STM_TS_EVENT_JITTER_MUTUAL_MIN) {
					result[0] = data[3] << 8 | data[4];
					result[1] = data[8] << 8 | data[9];
					input_info(true, ts->dev, "%s: MIN: min:%d, max:%d\n", __func__, result[0], result[1]);
				} else if (data[2] == STM_TS_EVENT_JITTER_MUTUAL_MAX) {
					result[2] = data[3] << 8 | data[4];
					result[3] = data[8] << 8 | data[9];
					input_info(true, ts->dev, "%s: MAX: min:%d, max:%d\n", __func__, result[2], result[3]);
				} else if (data[2] == STM_TS_EVENT_JITTER_MUTUAL_AVG) {
					result[4] = data[3] << 8 | data[4];
					result[5] = data[8] << 8 | data[9];
					input_info(true, ts->dev, "%s: AVG: min:%d, max:%d\n", __func__, result[4], result[5]);
					ret = 0;
					break;
				}
			} else {
				ret = -1;
				break;
			}
		} else if (data[0] == STM_TS_EVENT_ERROR_REPORT) {
			input_info(true, ts->dev, "%s: Error detected %02X,%02X,%02X,%02X,%02X,%02X\n",
				__func__, data[0], data[1], data[2], data[3], data[4], data[5]);
			break;
		}

		if (retry++ > STM_TS_RETRY_COUNT * retry_time) {
			ret = -1;
			input_err(true, ts->dev, "%s: Time Over (%02X,%02X,%02X,%02X,%02X,%02X)\n",
				__func__, data[0], data[1], data[2], data[3], data[4], data[5]);
			break;
		}
		sec_delay(20);
	}

ERROR:
	enable_irq(ts->irq);
	mutex_unlock(&ts->fn_mutex);

	ts->stm_ts_systemreset(ts, 0);
	stm_ts_set_scanmode(ts, ts->scan_mode);

	return ret;
}

void stm_ts_checking_miscal(struct stm_ts_data *ts)
{
	u8 reg[3] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;

	ts->stm_ts_systemreset(ts, 0);
	stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true);

	stm_ts_release_all_finger(ts);

	/* get the raw data after C7 02 : mis cal test */
	reg[0] = 0xC7;
	reg[1] = 0x02;

	ts->stm_ts_write(ts, &reg[0], 2, NULL, 0);
	sec_delay(300);
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: [miscal diff data]\n", __func__);
	stm_ts_read_nonsync_frame(ts, &min, &max);

	stm_ts_set_scanmode(ts, ts->scan_mode);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: mis cal min/max :%d/%d\n", __func__, min, max);
}

int stm_ts_panel_ito_test(struct stm_ts_data *ts, int testmode)
{
	u8 cmd = STM_TS_READ_ONE_EVENT;
	u8 reg[4] = { 0 };
	u8 data[STM_TS_EVENT_BUFF_SIZE];
	int i;
	bool matched = false;
	int retry = 0;
	int result = 0;

	result = ts->stm_ts_systemreset(ts, 0);
	if (result < 0) {
		input_info(true, ts->dev, "%s: stm_ts_systemreset fail (%d)\n", __func__, result);
		return result;
	}

	disable_irq(ts->irq);
	stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true);

	stm_ts_release_all_finger(ts);

	reg[0] = 0xA4;
	reg[1] = 0x04;
	switch (testmode) {
	case OPEN_TEST:
		reg[2] = 0x00;
		reg[3] = 0x30;
		break;

	case OPEN_SHORT_CRACK_TEST:
	case SAVE_MISCAL_REF_RAW:
	default:
		reg[2] = 0xFF;
		reg[3] = 0x01;
		break;
	}

	ts->stm_ts_write(ts, &reg[0], 4, NULL, 0); // ITO test command
	sec_delay(100);

	memset(ts->plat_data->hw_param.ito_test, 0x0, 4);
	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);

	while (ts->stm_ts_read(ts, &cmd, 1, (u8 *)data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		if ((data[0] == STM_TS_EVENT_STATUS_REPORT) && (data[1] == 0x01)) {  // Check command ECHO - finished
			for (i = 0; i < 4; i++) {
				if (data[i + 2] != reg[i]) {
					matched = false;
					break;
				}
				matched = true;
			}

			if (matched == true)
				break;
		} else if (data[0] == STM_TS_EVENT_ERROR_REPORT) {
			ts->plat_data->hw_param.ito_test[0] = data[0];
			ts->plat_data->hw_param.ito_test[1] = data[1];
			ts->plat_data->hw_param.ito_test[2] = data[2];
			ts->plat_data->hw_param.ito_test[3] = 0x00;
			result = -ITO_FAIL;

			switch (data[1]) {
			case ITO_FORCE_SHRT_GND:
				input_info(true, ts->dev, "%s: Force channel [%d] short to GND\n",
						__func__, data[2]);
				result = -ITO_FAIL_SHORT;
				break;

			case ITO_SENSE_SHRT_GND:
				input_info(true, ts->dev, "%s: Sense channel [%d] short to GND\n",
						__func__, data[2]);
				result = ITO_FAIL_SHORT;
				break;

			case ITO_FORCE_SHRT_VDD:
				input_info(true, ts->dev, "%s: Force channel [%d] short to VDD\n",
						__func__, data[2]);
				result = -ITO_FAIL_SHORT;
				break;

			case ITO_SENSE_SHRT_VDD:
				input_info(true, ts->dev, "%s: Sense channel [%d] short to VDD\n",
						__func__, data[2]);
				result = -ITO_FAIL_SHORT;
				break;

			case ITO_FORCE_SHRT_FORCE:
				input_info(true, ts->dev, "%s: Force channel [%d] short to force\n",
						__func__, data[2]);
				result = -ITO_FAIL_SHORT;
				break;

			case ITO_SENSE_SHRT_SENSE:
				input_info(true, ts->dev, "%s: Sennse channel [%d] short to sense\n",
						__func__, data[2]);
				result = -ITO_FAIL_SHORT;
				break;

			case ITO_FORCE_OPEN:
				input_info(true, ts->dev, "%s: Force channel [%d] open\n",
						__func__, data[2]);
				result = -ITO_FAIL_OPEN;
				break;

			case ITO_SENSE_OPEN:
				input_info(true, ts->dev, "%s: Sense channel [%d] open\n",
						__func__, data[2]);
				result = -ITO_FAIL_OPEN;
				break;

			case ITO_KEY_OPEN:
				input_info(true, ts->dev, "%s: Key channel [%d] open\n",
						__func__, data[2]);
				result = -ITO_FAIL_OPEN;
				break;

			default:
				input_info(true, ts->dev, "%s: unknown event %02x %02x %02x %02x %02x %02x %02x %02x\n",
						__func__, data[0], data[1], data[2], data[3],
						data[4], data[5], data[6], data[7]);
				break;
			}
		}

		if (retry++ > 50) {
			result = -ITO_FAIL;
			input_err(true, ts->dev, "%s: Time over - wait for result of ITO test\n", __func__);
			break;
		}
		sec_delay(20);
	}

	ts->stm_ts_systemreset(ts, 0);

	ts->plat_data->touch_functions = (ts->plat_data->touch_functions & (~STM_TS_TOUCHTYPE_BIT_COVER));
	if (ts->glove_enabled)
		ts->plat_data->touch_functions = ts->plat_data->touch_functions | STM_TS_TOUCHTYPE_BIT_GLOVE;
	else
		ts->plat_data->touch_functions = ts->plat_data->touch_functions & (~STM_TS_TOUCHTYPE_BIT_GLOVE);

	stm_ts_set_touch_function(ts);
	sec_delay(10);

	ts->plat_data->touch_count = 0;

	stm_ts_set_scanmode(ts, ts->scan_mode);

	enable_irq(ts->irq);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: mode:%d [%s] %02X %02X %02X %02X\n",
			__func__, testmode, result < 0 ? "FAIL" : "PASS",
			ts->plat_data->hw_param.ito_test[0], ts->plat_data->hw_param.ito_test[1],
			ts->plat_data->hw_param.ito_test[2], ts->plat_data->hw_param.ito_test[3]);

	return result;
}

int stm_ts_panel_test_result(struct stm_ts_data *ts, int type)
{
	u8 data[STM_TS_EVENT_BUFF_SIZE];
	u8 cmd = STM_TS_READ_ONE_EVENT;
	uint8_t reg[4] = { 0 };
	bool matched = false;
	int retry = 0;
	int i = 0;
	int result = 0;
	short temp_min = 32767, temp_max = -32768;

	bool cheked_short_to_gnd = false;
	bool cheked_short_to_vdd = false;
	bool cheked_short = false;
	bool cheked_open = false;
	char tempv[25] = {0};
	char temph[30] = {0};
	struct sec_cmd_data *sec = &ts->sec;

	char buff[SEC_CMD_STR_LEN] = {0};
	u8 *result_buff = NULL;
	int size = 4095;

	result_buff = kzalloc(size, GFP_KERNEL);
	if (!result_buff) {
		input_err(true, ts->dev, "%s: result_buff kzalloc fail!\n", __func__);
		goto alloc_fail;
	}


	disable_irq(ts->irq);

	reg[0] = 0xA4;
	reg[1] = 0x04;
	reg[2] = 0xFC;
	reg[3] = 0x09;
	ts->stm_ts_write(ts, &reg[0], 4, NULL, 0);
	sec_delay(100);

	memset(ts->plat_data->hw_param.ito_test, 0x0, 4);

	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);
	while (ts->stm_ts_read(ts, &cmd, 1, (u8 *)data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		memset(tempv, 0x00, 25);
		memset(temph, 0x00, 30);
		if ((data[0] == STM_TS_EVENT_STATUS_REPORT) && (data[1] == 0x01)) {
			for (i = 0; i < 4; i++) {
				if (data[i + 2] != reg[i]) {
					matched = false;
					break;
				}
				matched = true;
			}
			if (matched == true)
				break;

		} else if (data[0] == STM_TS_EVENT_ERROR_REPORT) {
			ts->plat_data->hw_param.ito_test[0] = data[0];
			ts->plat_data->hw_param.ito_test[1] = data[1];
			ts->plat_data->hw_param.ito_test[2] = data[2];
			ts->plat_data->hw_param.ito_test[3] = 0x00;

			switch (data[1]) {
			case ITO_FORCE_SHRT_GND:
			case ITO_SENSE_SHRT_GND:
				input_info(true, ts->dev, "%s: TX/RX_SHORT_TO_GND:%cX[%d]\n",
						__func__, data[1] == ITO_FORCE_SHRT_VDD ? 'T' : 'R', data[2]);
				if (type != SHORT_TEST)
					break;
				if (!cheked_short_to_gnd) {
					snprintf(temph, 30, "TX/RX_SHORT_TO_GND:");
					strlcat(result_buff, temph, size);
					cheked_short_to_gnd = true;
				}
				snprintf(tempv, sizeof(tempv), "%c%d,", data[1] == ITO_FORCE_SHRT_GND ? 'T' : 'R', data[2]);
				strlcat(result_buff, tempv, size);
				result = -ITO_FAIL_SHORT;
				break;
			case ITO_FORCE_SHRT_VDD:
			case ITO_SENSE_SHRT_VDD:
				input_info(true, ts->dev, "%s: TX/RX_SHORT_TO_VDD:%cX[%d]\n",
						__func__, data[1] == ITO_FORCE_SHRT_VDD ? 'T' : 'R', data[2]);
				if (type != SHORT_TEST)
					break;
				if (!cheked_short_to_vdd) {
					snprintf(temph, 30, "TX/RX_SHORT_TO_VDD:");
					strlcat(result_buff, temph, size);
					cheked_short_to_vdd = true;
				}
				snprintf(tempv, sizeof(tempv), "%c%d,", data[1] == ITO_FORCE_SHRT_VDD ? 'T' : 'R', data[2]);
				strlcat(result_buff, tempv, size);
				result = -ITO_FAIL_SHORT;
				break;
			case ITO_FORCE_SHRT_FORCE:
			case ITO_SENSE_SHRT_SENSE:
				input_info(true, ts->dev, "%s: TX/RX_SHORT:%cX[%d]\n",
						__func__, data[1] == ITO_FORCE_SHRT_FORCE ? 'T' : 'R', data[2]);
				if (type != SHORT_TEST)
					break;
				if (!cheked_short) {
					snprintf(temph, 30, "TX/RX_SHORT:");
					strlcat(result_buff, temph, size);
					cheked_short = true;
				}
				snprintf(tempv, sizeof(tempv), "%c%d,", data[1] == ITO_FORCE_SHRT_FORCE ? 'T' : 'R', data[2]);
				strlcat(result_buff, tempv, size);
				result = -ITO_FAIL_SHORT;
				break;
			case ITO_FORCE_OPEN:
			case ITO_SENSE_OPEN:
				input_info(true, ts->dev, "%s: TX/RX_OPEN:%cX[%d]\n",
						__func__, data[1] == ITO_FORCE_OPEN ? 'T' : 'R', data[2]);
				if (type != OPEN_TEST)
					break;
				if (!cheked_open) {
					snprintf(temph, 30, "TX/RX_OPEN:");
					strlcat(result_buff, temph, size);
					cheked_open = true;
				}
				snprintf(tempv, sizeof(tempv), "%c%d,", data[1] == ITO_FORCE_OPEN ? 'T' : 'R', data[2]);
				strlcat(result_buff, tempv, size);
				result = -ITO_FAIL_OPEN;
				break;
			default:
				input_info(true, ts->dev, "%s: unknown event %02x %02x %02x %02x %02x %02x %02x %02x\n",
						__func__, data[0], data[1], data[2], data[3],
						data[4], data[5], data[6], data[7]);
				break;
			}
		}

		if (retry++ > 50) {
			input_err(true, ts->dev, "%s: Time over - wait for result of ITO test\n", __func__);
			goto test_fail;
		}
		sec_delay(20);
	}

	/* read rawdata */
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);
	stm_ts_read_nonsync_frame(ts, &temp_min, &temp_max);

	if (type == OPEN_TEST && result == -ITO_FAIL_OPEN) {
		snprintf(result_buff, sizeof(result_buff), "NG");
		sec_cmd_set_cmd_result(sec, result_buff, strnlen(result_buff, sizeof(result_buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	} else if (type == SHORT_TEST && result == -ITO_FAIL_SHORT) {
		snprintf(result_buff, sizeof(result_buff), "NG");
		sec_cmd_set_cmd_result(sec, result_buff, strnlen(result_buff, sizeof(result_buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	} else {
		snprintf(result_buff, sizeof(result_buff), "OK");
		sec_cmd_set_cmd_result(sec, result_buff, strnlen(result_buff, sizeof(result_buff)));
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, result_buff);
	enable_irq(ts->irq);
	kfree(result_buff);

	return result;

test_fail:
	enable_irq(ts->irq);
	kfree(result_buff);
alloc_fail:
	snprintf(buff, 30, "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;

	return -ITO_FAIL;
}

static void fw_update(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int retval = 0;

#if IS_ENABLED(CONFIG_INPUT_SEC_SECURE_TOUCH)
#if IS_ENABLED(CONFIG_INPUT_SEC_TRUSTED_TOUCH)
	if (atomic_read(&ts->plat_data->pvm->trusted_touch_enabled)) {
		input_info(true, ts->dev, "%s trusted touch is enabled. skip\n", __func__);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}
#endif
#endif

	mutex_lock(&ts->plat_data->enable_mutex);
	retval = stm_ts_fw_update_on_hidden_menu(ts, sec->cmd_param[0]);
	if (retval < 0) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_err(true, ts->dev, "%s: failed [%d]\n", __func__, retval);
	} else {
		sec->cmd_state = SEC_CMD_STATUS_OK;
		input_info(true, ts->dev, "%s: success [%d]\n", __func__, retval);
	}
	mutex_unlock(&ts->plat_data->enable_mutex);
}

static void get_fw_ver_bin(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };

	snprintf(buff, sizeof(buff), "ST%02X%02X%02X%02X",
			ts->ic_name_of_bin,
			ts->project_id_of_bin,
			ts->module_version_of_bin,
			ts->fw_main_version_of_bin & 0xFF);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "FW_VER_BIN");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_fw_ver_ic(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };
	char model_ver[7] = { 0 };

	stm_ts_get_version_info(ts);

	snprintf(buff, sizeof(buff), "ST%02X%02X%02X%02X",
			ts->plat_data->img_version_of_ic[0], ts->plat_data->img_version_of_ic[1],
			ts->plat_data->img_version_of_ic[2], ts->plat_data->img_version_of_ic[3]);
	snprintf(model_ver, sizeof(model_ver), "ST%02X%02X",
			ts->plat_data->img_version_of_ic[0], ts->plat_data->img_version_of_ic[1]);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "FW_VER_IC");
		sec_cmd_set_cmd_result_all(sec, model_ver, strnlen(model_ver, sizeof(model_ver)), "FW_MODEL");
	}
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_config_ver(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[20] = { 0 };

	snprintf(buff, sizeof(buff), "ST_%04X", ts->config_version_of_ic);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void module_off_master(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = stm_ts_stop_device(ts);
	if (ret == 0)
		sec->cmd_state = SEC_CMD_STATUS_OK;
	else
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void module_on_master(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = stm_ts_start_device(ts);
	if (ret == 0)
		sec->cmd_state = SEC_CMD_STATUS_OK;
	else
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void get_chip_vendor(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };

	snprintf(buff, sizeof(buff), "STM");

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "IC_VENDOR");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_chip_name(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };

	if (ts->plat_data->firmware_name)
		memcpy(buff, ts->plat_data->firmware_name + 8, 9);
	else
		snprintf(buff, 10, "FTS");

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "IC_NAME");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_jitter_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0 };
	int ret;
	s16 result[2] = { 0 };

	ts->stm_ts_systemreset(ts, 0);

	// Mutual jitter.
	reg[0] = 0xC7;
	reg[1] = 0x08;
	reg[2] = 0x64;	//100 frame
	reg[3] = 0x00;

	ret = stm_ts_get_jitter_result(ts, reg, 4, result, STM_TS_EVENT_JITTER_MUTUAL_TEST);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: failed to read Mutual jitter\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_info(true, ts->dev, "%s: Fail %s\n", __func__, buff);
	} else {
		snprintf(buff, sizeof(buff), "%d", result[1]);
		sec->cmd_state = SEC_CMD_STATUS_OK;
		input_info(true, ts->dev, "%s: Mutual max jitter %s\n", __func__, buff);
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MUTUAL_JITTER");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	return;
}

static void run_mutual_jitter(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0 };
	int ret;
	s16 result[2] = { 0 };

	ts->stm_ts_systemreset(ts, 0);

	// Mutual jitter.
	reg[0] = 0xC7;
	reg[1] = 0x08;
	reg[2] = 0x64;	//100 frame
	reg[3] = 0x00;

	ret = stm_ts_get_jitter_result(ts, reg, 4, result, STM_TS_EVENT_JITTER_MUTUAL_TEST);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: failed to read Mutual jitter\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: Fail %s\n", __func__, buff);
	} else {
		snprintf(buff, sizeof(buff), "%d,%d", result[0], result[1]);
		sec->cmd_state = SEC_CMD_STATUS_OK;
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: %s\n", __func__, buff);
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MUTUAL_JITTER");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	return;
}

static void run_self_jitter(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0 };
	int ret;
	s16 result[2] = { 0 };

	ts->stm_ts_systemreset(ts, 300);

	/* Self jitter */
	reg[0] = 0xC7;
	reg[1] = 0x0A;
	reg[2] = 0x64;	/* 100 frame */
	reg[3] = 0x00;

	ret = stm_ts_get_jitter_result(ts, reg, 4, result, STM_TS_EVENT_JITTER_SELF_TEST);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: failed to read Self jitter\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: Fail %s\n", __func__, buff);
	} else {
		snprintf(buff, sizeof(buff), "%d,%d", result[0], result[1]);
		sec->cmd_state = SEC_CMD_STATUS_OK;
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: %s\n", __func__, buff);
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "SELF_JITTER");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	return;
}

static void run_jitter_delta_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0 };
	int ret = -1;
	s16 result[6] = { 0 };

	ts->stm_ts_systemreset(ts, 0);

	/* jitter delta + 1000 frame*/
	reg[0] = 0xC7;
	reg[1] = 0x08;
	reg[2] = 0xE8;
	reg[3] = 0x03;

	ret = stm_ts_get_jitter_result(ts, reg, 4, result, STM_TS_EVENT_JITTER_DELTA_TEST);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: failed to read jitter delta\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		input_info(true, ts->dev, "%s: Fail %s\n", __func__, buff);
	} else {
		snprintf(buff, sizeof(buff), "%d,%d,%d,%d,%d,%d",
			result[0], result[1], result[2], result[3], result[4], result[5]);
		sec->cmd_state = SEC_CMD_STATUS_OK;
		input_info(true, ts->dev, "%s: %s\n", __func__, buff);
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		char buffer[SEC_CMD_STR_LEN] = { 0 };

		snprintf(buffer, sizeof(buffer), "%d,%d", result[0], result[1]);
		sec_cmd_set_cmd_result_all(sec, buffer, strnlen(buffer, sizeof(buffer)), "JITTER_DELTA_MIN");

		memset(buffer, 0x00, sizeof(buffer));
		snprintf(buffer, sizeof(buffer), "%d,%d", result[2], result[3]);
		sec_cmd_set_cmd_result_all(sec, buffer, strnlen(buffer, sizeof(buffer)), "JITTER_DELTA_MAX");

		memset(buffer, 0x00, sizeof(buffer));
		snprintf(buffer, sizeof(buffer), "%d,%d", result[4], result[5]);
		sec_cmd_set_cmd_result_all(sec, buffer, strnlen(buffer, sizeof(buffer)), "JITTER_DELTA_AVG");
	}
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
}

static void run_lcdoff_mutual_jitter(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0 };
	int ret;
	s16 mutual_min = 0, mutual_max = 0;
	u8 data[STM_TS_EVENT_BUFF_SIZE] = { 0 };
	u8 result = 0;
	int retry = 0;

	ts->stm_ts_systemreset(ts, 0);
	stm_ts_release_all_finger(ts);

	ret = stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_TRUE);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to set active mode\n", __func__);
		goto ERROR;
	}

	disable_irq(ts->irq);
	mutex_lock(&ts->fn_mutex);

	// lcd off Mutual jitter.
	reg[0] = 0xC7;
	reg[1] = 0x0D;
	reg[2] = 0x64;	//100 frame
	reg[3] = 0x00;

	ret = ts->stm_ts_write(ts, &reg[0], 4, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to write command\n", __func__);
		mutex_unlock(&ts->fn_mutex);
		enable_irq(ts->irq);
		goto ERROR;
	}

	sec_delay(5);

	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);

	reg[0] = STM_TS_READ_ONE_EVENT;
	while (ts->stm_ts_read(ts, &reg[0], 1, data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		if ((data[0] == STM_TS_EVENT_ERROR_REPORT) || (data[0] == STM_TS_EVENT_PASS_REPORT)) {
			mutual_max = data[3] << 8 | data[2];
			mutual_min = data[5] << 8 | data[4];

			if (data[0] == STM_TS_EVENT_PASS_REPORT) {
				sec->cmd_state = SEC_CMD_STATUS_OK;
				result = 0;
			} else {
				sec->cmd_state = SEC_CMD_STATUS_FAIL;
				result = 1;
			}
			break;
		}

		/* waiting 10 seconds */
		if (retry++ > STM_TS_RETRY_COUNT * 50) {
			input_err(true, ts->dev, "%s: Time Over (%02X,%02X,%02X,%02X,%02X,%02X)\n",
				__func__, data[0], data[1], data[2], data[3], data[4], data[5]);
			break;
		}
		sec_delay(20);
	}

	mutex_unlock(&ts->fn_mutex);
	enable_irq(ts->irq);

	ts->stm_ts_systemreset(ts, 0);
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "%d,%d,%d", result, mutual_min, mutual_max);
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "LCDOFF_MUTUAL_JITTER");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return;

ERROR:
	ts->stm_ts_systemreset(ts, 0);
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "LCDOFF_MUTUAL_JITTER");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void get_wet_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[3] = { 0 };
	u8 data[2] = { 0 };
	int ret;

	reg[0] = 0xC7;
	reg[1] = 0x03;
	ret = ts->stm_ts_read(ts, &reg[0], 2, &data[0], 1);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: [ERROR] failed to read\n", __func__);
		snprintf(buff, sizeof(buff), "%s", "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
			sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "WET_MODE");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	snprintf(buff, sizeof(buff), "%d", data[0]);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "WET_MODE");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_x_num(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };

	snprintf(buff, sizeof(buff), "%d", ts->tx_count);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_y_num(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };

	snprintf(buff, sizeof(buff), "%d", ts->rx_count);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_checksum_data(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[16] = { 0 };
	int ret;
	u32 checksum_data;

	ts->stm_ts_systemreset(ts, 0);

	ret = stm_ts_get_sysinfo_data(ts, STM_TS_SI_CONFIG_CHECKSUM, 4, (u8 *)&checksum_data);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: Get checksum data Read Fail!! [Data : %08X]\n",
				__func__, checksum_data);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}
	stm_ts_reinit(ts);

	snprintf(buff, sizeof(buff), "%08X", checksum_data);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void check_fw_corruption(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	if (ts->fw_corruption) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		ret = stm_ts_fw_corruption_check(ts);
		if (ret == -STM_TS_ERROR_FW_CORRUPTION || ret == -STM_TS_ERROR_BROKEN_FW) {
			sec->cmd_state = SEC_CMD_STATUS_FAIL;
		} else {
			sec->cmd_state = SEC_CMD_STATUS_OK;
			stm_ts_reinit(ts);
		}
	}
	ts->fw_corruption = false;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void run_reference_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;

	stm_ts_read_frame(ts, TYPE_BASELINE_DATA, &min, &max);
	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_reference(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short val = 0;
	int node = 0;

	node = stm_ts_check_index(ts);
	if (node < 0)
		return;

	val = ts->pFrame[node];
	snprintf(buff, sizeof(buff), "%d", val);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_rawcap_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;

	stm_ts_read_frame(ts, TYPE_RAW_DATA, &min, &max);
	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "RAW_DATA");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_rawcap_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	int i, j;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	enter_factory_mode(ts, true);
	stm_ts_read_frame(ts, TYPE_RAW_DATA, &min, &max);

	for (j = 0; j < ts->tx_count; j++) {
		for (i = 0; i < ts->rx_count; i++) {
			snprintf(buff, sizeof(buff), "%d,", ts->pFrame[j * ts->rx_count + i]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}
	enter_factory_mode(ts, false);

	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
}

static void run_nonsync_rawcap_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	int i, j;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);
	stm_ts_read_nonsync_frame(ts, &min, &max);

	for (j = 0; j < ts->tx_count; j++) {
		for (i = 0; i < ts->rx_count; i++) {
			snprintf(buff, sizeof(buff), "%d,", ts->pFrame[j * ts->rx_count + i]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}
	enter_factory_mode(ts, false);

	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
}

static void get_rawcap(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short val = 0;
	int node = 0;

	node = stm_ts_check_index(ts);
	if (node < 0)
		return;

	val = ts->pFrame[node];
	snprintf(buff, sizeof(buff), "%d", val);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_lp_single_ended_rawcap_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 regr[4] = { 0xA4, 0x0A, 0x01, 0x00 };
	int ret;
	short min = 0x7FFF;
	short max = 0x8000;

	ts->stm_ts_systemreset(ts, 0);

	/* Request to Prepare single ended raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, regr, 4, 0);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);
	stm_ts_read_nonsync_frame(ts, &min, &max);

	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MUTUAL_RAW");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MUTUAL_RAW");
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
	input_info(true, ts->dev, "%s: fail : %s\n", __func__, buff);

	return;
}

static void run_lp_single_ended_rawcap_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 regr[4] = { 0xA4, 0x0A, 0x01, 0x00 };
	int ret;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	enter_factory_mode(ts, true);

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	sec_delay(30);

	/* Request to Prepare single ended raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, regr, 4, 0);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	run_nonsync_rawcap_read_all(sec);

	stm_ts_set_scanmode(ts, ts->scan_mode);

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void run_low_frequency_rawcap_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0xA4, 0x04, 0x00, 0xC0 };
	int ret;
	short min = 0x7FFF;
	short max = 0x8000;

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	sec_delay(30);

	/* Request to Prepare Hight Frequency(ITO) raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, reg, 4, 30);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	stm_ts_read_nonsync_frame(ts, &min, &max);

	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		char rawcap_buff[SEC_CMD_STR_LEN];

		snprintf(rawcap_buff, SEC_CMD_STR_LEN, "%d,%d", min, max);
		sec_cmd_set_cmd_result_all(sec, rawcap_buff, SEC_CMD_STR_LEN, "LF_RAW_DATA");
	}

	stm_ts_set_scanmode(ts, ts->scan_mode);

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void run_low_frequency_rawcap_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0xA4, 0x04, 0x00, 0xC0 };
	int ret;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	enter_factory_mode(ts, true);

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	sec_delay(30);

	/* Request to Prepare Hight Frequency(ITO) raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, reg, 4, 30);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	run_nonsync_rawcap_read_all(sec);

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void run_high_frequency_rawcap_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short rawcap[2] = {SHRT_MAX, SHRT_MIN}; /* min, max */
	short rawcap_edge[2] = {SHRT_MAX, SHRT_MIN}; /* min, max */
	u8 reg[4] = { 0xA4, 0x04, 0xFF, 0x01 };
	int ret;
	int i, j;
	short min = 0x7FFF;
	short max = 0x8000;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	sec_delay(30);

	/* Request to Prepare Hight Frequency(ITO) raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, reg, 4, 100);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	stm_ts_read_nonsync_frame(ts, &min, &max);

	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	stm_ts_set_scanmode(ts, ts->scan_mode);

	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++) {
			short *rawcap_ptr;

			if (i == 0 || i == ts->tx_count - 1 || j == 0 || j == ts->rx_count - 1)
				rawcap_ptr = rawcap_edge;
			else
				rawcap_ptr = rawcap;

			if (ts->pFrame[(i * ts->rx_count) + j] < rawcap_ptr[0])
				rawcap_ptr[0] = ts->pFrame[(i * ts->rx_count) + j];
			if (ts->pFrame[(i * ts->rx_count) + j] > rawcap_ptr[1])
				rawcap_ptr[1] = ts->pFrame[(i * ts->rx_count) + j];
		}
	}

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev,
			"%s: rawcap:%d,%d rawcap_edge:%d,%d\n",
			__func__, rawcap[0], rawcap[1], rawcap_edge[0], rawcap_edge[1]);

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		char rawcap_buff[SEC_CMD_STR_LEN];

		snprintf(rawcap_buff, SEC_CMD_STR_LEN, "%d,%d", min, max);
		sec_cmd_set_cmd_result_all(sec, rawcap_buff, SEC_CMD_STR_LEN, "HF_RAW_DATA");
		snprintf(rawcap_buff, SEC_CMD_STR_LEN, "%d,%d", rawcap[0], rawcap[1]);
		sec_cmd_set_cmd_result_all(sec, rawcap_buff, SEC_CMD_STR_LEN, "TSP_RAWCAP");
		snprintf(rawcap_buff, SEC_CMD_STR_LEN, "%d,%d", rawcap_edge[0], rawcap_edge[1]);
		sec_cmd_set_cmd_result_all(sec, rawcap_buff, SEC_CMD_STR_LEN, "TSP_RAWCAP_EDGE");
	}

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void run_high_frequency_rawcap_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[4] = { 0xA4, 0x04, 0xFF, 0x01 };
	int ret;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);

	enter_factory_mode(ts, true);

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	sec_delay(30);

	/* Request to Prepare Hight Frequency(ITO) raw data from flash */

	ret = stm_ts_wait_for_echo_event(ts, reg, 4, 100);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: timeout, ret: %d\n", __func__, ret);
		goto out;
	}

	run_nonsync_rawcap_read_all(sec);
	stm_ts_set_scanmode(ts, ts->scan_mode);

	return;

out:
	stm_ts_set_scanmode(ts, ts->scan_mode);

	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void run_delta_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;

	stm_ts_read_frame(ts, TYPE_STRENGTH_DATA, &min, &max);
	snprintf(buff, sizeof(buff), "%d,%d", min, max);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_prox_intensity_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;
	u8 reg[2];
	u8 thd_data[4];
	u8 sum_data[4];

	memset(thd_data, 0x00, 4);
	memset(sum_data, 0x00, 4);

	/* Threshold */
	reg[0] = 0xC7;
	reg[1] = 0x0C;
	ret = ts->stm_ts_read(ts, &reg[0], 2, &thd_data[0], 4);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to read thd_data\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	/* Sum */
	reg[0] = 0xC7;
	reg[1] = 0x0D;
	ret = ts->stm_ts_read(ts, &reg[0], 2, &sum_data[0], 4);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to read sum_data\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	snprintf(buff, sizeof(buff), "SUM_X:%d SUM_Y:%d THD_X:%d THD_Y:%d",
			(sum_data[0] << 8) + sum_data[1], (sum_data[2] << 8) + sum_data[3],
			(thd_data[0] << 8) + thd_data[1], (thd_data[2] << 8) + thd_data[3]);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);

}

static void run_cs_raw_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	short *rdata;
	int i, j, k;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	rdata = (short *)kzalloc(ts->tx_count * ts->rx_count * 2, GFP_KERNEL);
	if (!rdata) {
		input_err(true, ts->dev, "%s: rdata alloc failed\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		kfree(all_strbuff);
		return;
	}

	enter_factory_mode(ts, true);
	stm_ts_read_frame(ts, TYPE_RAW_DATA, &min, &max);

	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++) {
			rdata[(ts->rx_count - j - 1) * ts->tx_count + i] = ts->pFrame[i * ts->rx_count + j];
		}
	}

	k = 0;
	for (j = 0; j < ts->rx_count; j++) {
		for (i = 0; i < ts->tx_count; i++) {
			snprintf(buff, sizeof(buff), "%d,", rdata[k++]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}

	k = 0;
	for (j = 0; j < ts->rx_count; j++) {
		pr_cont("[sec_input]: ");
		for (i = 0; i < ts->tx_count; i++) {
			pr_cont(" %d", rdata[k++]);
		}
		pr_cont("\n");
	}

	enter_factory_mode(ts, false);

	stm_ts_reinit(ts);

	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
	kfree(rdata);
}

static void run_cs_delta_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	short *rdata;
	int i, j, k;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		input_err(true, ts->dev, "%s: alloc failed\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	rdata = (short *)kzalloc(ts->tx_count * ts->rx_count * 2, GFP_KERNEL);
	if (!rdata) {
		input_err(true, ts->dev, "%s: rdata alloc failed\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		kfree(all_strbuff);
		return;
	}

	stm_ts_read_frame(ts, TYPE_STRENGTH_DATA, &min, &max);

	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++) {
			rdata[(ts->rx_count - j - 1) * ts->tx_count + i] = ts->pFrame[i * ts->rx_count + j];
		}
	}

	k = 0;
	for (j = 0; j < ts->rx_count; j++) {
		for (i = 0; i < ts->tx_count; i++) {
			snprintf(buff, sizeof(buff), "%d,", rdata[k++]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}

	k = 0;
	for (j = 0; j < ts->rx_count; j++) {
		pr_cont("[sec_input]: ");
		for (i = 0; i < ts->tx_count; i++) {
			pr_cont(" %d", rdata[k++]);
		}
		pr_cont("\n");
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;

	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
	kfree(rdata);
}

static void get_strength_all_data(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	int i, j;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		input_err(true, ts->dev, "%s: alloc failed\n", __func__);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	stm_ts_read_frame(ts, TYPE_STRENGTH_DATA, &min, &max);

	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++) {
			snprintf(buff, sizeof(buff), "%d,", ts->pFrame[(i * ts->rx_count) + j]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;

	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
}

static void get_delta(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short val = 0;
	int node = 0;

	node = stm_ts_check_index(ts);
	if (node < 0)
		return;

	val = ts->pFrame[node];
	snprintf(buff, sizeof(buff), "%d", val);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void stm_ts_read_self_raw_frame(struct stm_ts_data *ts, bool allnode)
{
	struct sec_cmd_data *sec = &ts->sec;
	char buff[SEC_CMD_STR_LEN] = { 0 };
	struct stm_ts_syncframeheader *psyncframeheader;
	u8 reg[STM_TS_EVENT_BUFF_SIZE] = {0};
	u8 *data;
	s16 self_force_raw_data[100];
	s16 self_sense_raw_data[100];
	int Offset = 0;
	u8 count = 0;
	int i;
	int ret;
	int totalbytes;
	int retry = 10;
	s16 min_tx_self_raw_data = S16_MAX;
	s16 max_tx_self_raw_data = S16_MIN;
	s16 min_rx_self_raw_data = S16_MAX;
	s16 max_rx_self_raw_data = S16_MIN;

	data = kzalloc((ts->tx_count + ts->rx_count) * 2 + 1, GFP_KERNEL);
	if (!data)
		return;

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: [ERROR] Touch is stopped\n",
				__func__);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	// Request Data Type
	reg[0] = 0xA4;
	reg[1] = 0x06;
	reg[2] = TYPE_RAW_DATA;
	ts->stm_ts_write(ts, &reg[0], 3, NULL, 0);

	do {
		reg[0] = STM_TS_CMD_FRM_BUFF_R;
		reg[1] = 0x00;
		reg[2] = 0x00;
		ret = ts->stm_ts_read(ts, &reg[0], 3, &data[0], STM_TS_COMP_DATA_HEADER_SIZE);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: read failed ret = %d\n", __func__, ret);
			snprintf(buff, sizeof(buff), "NG");
			sec->cmd_state = SEC_CMD_STATUS_FAIL;
			goto out;
		}

		psyncframeheader = (struct stm_ts_syncframeheader *) &data[0];

		if ((psyncframeheader->header == 0xA5) && (psyncframeheader->host_data_mem_id == TYPE_RAW_DATA))
			break;

		sec_delay(100);
	} while (retry--);

	if (retry == 0) {
		input_err(true, ts->dev, "%s: didn't match header or id. header = %02X, id = %02X\n",
				__func__, psyncframeheader->header, psyncframeheader->host_data_mem_id);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	Offset = STM_TS_COMP_DATA_HEADER_SIZE + psyncframeheader->dbg_frm_len +
			(psyncframeheader->ms_force_len * psyncframeheader->ms_sense_len * 2);

	totalbytes = (psyncframeheader->ss_force_len + psyncframeheader->ss_sense_len) * 2;

	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = (u8)(Offset >> 8);
	reg[2] = (u8)(Offset & 0xFF);
	ret = ts->stm_ts_read(ts, &reg[0], 3, &data[0], totalbytes);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: read failed ret = %d\n", __func__, ret);
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	Offset = 0;
	for (count = 0; count < (ts->tx_count); count++) {
		self_force_raw_data[count] = (s16)(data[count * 2 + Offset] + (data[count * 2 + 1 + Offset] << 8));

		/* Only for YOCTA */
		if ((count == 0) && STM_TS_IS_EXCEPTIONAL_CHIP(ts->chip_id))
			continue;

		if (max_tx_self_raw_data < self_force_raw_data[count])
			max_tx_self_raw_data = self_force_raw_data[count];
		if (min_tx_self_raw_data > self_force_raw_data[count])
			min_tx_self_raw_data = self_force_raw_data[count];
	}

	Offset = (ts->tx_count * 2);
	for (count = 0; count < ts->rx_count; count++) {
		self_sense_raw_data[count] = (s16)(data[count * 2 + Offset] + (data[count * 2 + 1 + Offset] << 8));

		/* Only for YOCTA */
		if ((count == 0) && STM_TS_IS_EXCEPTIONAL_CHIP(ts->chip_id))
			continue;

		if (max_rx_self_raw_data < self_sense_raw_data[count])
			max_rx_self_raw_data = self_sense_raw_data[count];
		if (min_rx_self_raw_data > self_sense_raw_data[count])
			min_rx_self_raw_data = self_sense_raw_data[count];
	}

	stm_ts_print_channel(ts, self_force_raw_data, self_sense_raw_data);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: MIN_TX_SELF_RAW: %d MAX_TX_SELF_RAW : %d\n",
			__func__, (s16)min_tx_self_raw_data, (s16)max_tx_self_raw_data);
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: MIN_RX_SELF_RAW : %d MIN_RX_SELF_RAW : %d\n",
			__func__, (s16)min_rx_self_raw_data, (s16)max_rx_self_raw_data);

	if (allnode == true) {
		char *mbuff;
		char temp[10] = { 0 };

		mbuff = kzalloc((ts->tx_count + ts->rx_count + 2) * 10, GFP_KERNEL);
		if (!mbuff)
			goto out;

		for (i = 0; i < (ts->tx_count); i++) {
			snprintf(temp, sizeof(temp), "%d,", (s16)self_force_raw_data[i]);
			strlcat(mbuff, temp, sizeof(mbuff));
		}
		for (i = 0; i < (ts->rx_count); i++) {
			snprintf(temp, sizeof(temp), "%d,", (s16)self_sense_raw_data[i]);
			strlcat(mbuff, temp, sizeof(mbuff));
		}

		sec_cmd_set_cmd_result(sec, mbuff, sizeof(mbuff));
		sec->cmd_state = SEC_CMD_STATUS_OK;
		kfree(mbuff);
		return;
	}

	snprintf(buff, sizeof(buff), "%d,%d,%d,%d",
			(s16)min_tx_self_raw_data, (s16)max_tx_self_raw_data,
			(s16)min_rx_self_raw_data, (s16)max_rx_self_raw_data);
	sec->cmd_state = SEC_CMD_STATUS_OK;
out:
	kfree(data);
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		char ret_buff[SEC_CMD_STR_LEN] = { 0 };

		snprintf(ret_buff, sizeof(ret_buff), "%d,%d", (s16)min_rx_self_raw_data, (s16)max_rx_self_raw_data);
		sec_cmd_set_cmd_result_all(sec, ret_buff, strnlen(ret_buff, sizeof(ret_buff)), "SELF_RAW_RX");
		snprintf(ret_buff, sizeof(ret_buff), "%d,%d", (s16)min_tx_self_raw_data, (s16)max_tx_self_raw_data);
		sec_cmd_set_cmd_result_all(sec, ret_buff, strnlen(ret_buff, sizeof(ret_buff)), "SELF_RAW_TX");
	}
	sec_cmd_set_cmd_result(sec, &buff[0], strnlen(buff, sizeof(buff)));
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_self_raw_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);
	stm_ts_read_self_raw_frame(ts, false);
}

static void get_cx_data(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	short val = 0;
	int node = 0;

	node = stm_ts_check_index(ts);
	if (node < 0)
		return;

	if (ts->cx_data)
		val = ts->cx_data[node];
	snprintf(buff, sizeof(buff), "%d", val);
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);

}

static int read_ms_cx_data(struct stm_ts_data *ts, u8 active, s8 *cx_min, s8 *cx_max)
{
	s8 *rdata = NULL;
	u8 cdata[STM_TS_COMP_DATA_HEADER_SIZE];
	u8 reg[STM_TS_EVENT_BUFF_SIZE] = { 0 };
	u8 dataID = 0;
	u16 comp_start_addr;
	int i, j, ret = 0;
	u8 *pStr = NULL;
	u8 pTmp[16] = { 0 };

	ts->stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true); // Clear FIFO
	stm_ts_release_all_finger(ts);

	sec_delay(20);

	// Request compensation data type
	if (active == NORMAL_CX2)
		dataID = 0x11;  // MS - LP
	else if (active == ACTIVE_CX2)
		dataID = 0x10;	// MS - ACTIVE

	reg[0] = 0xA4;
	reg[1] = 0x06;
	reg[2] = dataID;

	ret = stm_ts_wait_for_echo_event(ts, &reg[0], 3, 0);
	if (ret < 0)
		return ret;

	// Read Header
	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = 0x00;
	reg[2] = 0x00;
	ret = ts->stm_ts_read(ts, &reg[0], 3, &cdata[0], STM_TS_COMP_DATA_HEADER_SIZE);
	if (ret < 0)
		return ret;

	if ((cdata[0] != 0xA5) && (cdata[1] != dataID)) {
		input_info(true, ts->dev, "%s: failed to read signature data of header.\n", __func__);
		ret = -EIO;
		return ret;
	}

	rdata = kzalloc(ts->rx_count * ts->tx_count + 1, GFP_KERNEL);
	if (!rdata)
		return -ENOMEM;

	comp_start_addr = (u16)STM_TS_COMP_DATA_HEADER_SIZE;
	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = (u8)(comp_start_addr >> 8);
	reg[2] = (u8)(comp_start_addr & 0xFF);
	ret = ts->stm_ts_read(ts, &reg[0], 3, &rdata[0], ts->tx_count * ts->rx_count);
	if (ret < 0)
		goto out;

	pStr = kzalloc(7 * (ts->rx_count + 1), GFP_KERNEL);
	if (!pStr) {
		ret = -ENOMEM;
		goto out;
	}

	*cx_min = *cx_max = rdata[0];
	for (i = 0; i < ts->tx_count; i++) {
		memset(pStr, 0x0, 7 * (ts->rx_count + 1));
		snprintf(pTmp, sizeof(pTmp), "Tx%02d | ", i);
		strlcat(pStr, pTmp, 7 * (ts->rx_count + 1));

		for (j = 0; j < ts->rx_count; j++) {
			snprintf(pTmp, sizeof(pTmp), "%4d", rdata[i * ts->rx_count + j]);
			strlcat(pStr, pTmp, 7 * (ts->rx_count + 1));

			*cx_min = min(*cx_min, rdata[i * ts->rx_count + j]);
			*cx_max = max(*cx_max, rdata[i * ts->rx_count + j]);
		}
		input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", pStr);
	}
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "cx min:%d, cx max:%d\n", *cx_min, *cx_max);

	/* ts->cx_data length: Force * Sense */
	if (ts->cx_data && active == NORMAL_CX2)
		memcpy(&ts->cx_data[0], &rdata[0], ts->tx_count * ts->rx_count);

	/* for get_gap_data_all */
	for (i = 0; i < ts->tx_count; i++) {
		for (j = 0; j < ts->rx_count; j++) {
			ts->pFrame[i * ts->rx_count + j] = rdata[i * ts->rx_count + j];
		}
	}

	kfree(pStr);
out:
	kfree(rdata);
	return ret;
}

static void run_active_cx_data_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	char buff_minmax[SEC_CMD_STR_LEN] = { 0 };
	int ret;
	s8 cx_min, cx_max;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: start\n", __func__);

	ret = read_ms_cx_data(ts, ACTIVE_CX2, &cx_min, &cx_max);
	if (ret < 0) {
		snprintf(buff, sizeof(buff), "NG");
		snprintf(buff_minmax, sizeof(buff_minmax), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff_minmax, sizeof(buff_minmax), "%d,%d", cx_min, cx_max);
		snprintf(buff, sizeof(buff), "OK");
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff_minmax, strnlen(buff_minmax, sizeof(buff_minmax)), "ACTIVE_CX2_DATA");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_cx_gap_data(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int rx_max = 0, tx_max = 0, ii;

	for (ii = 0; ii < (ts->rx_count * ts->tx_count); ii++) {
		/* rx(x) gap max */
		if ((ii + 1) % (ts->rx_count) != 0)
			rx_max = max(rx_max, (int)abs(ts->cx_data[ii + 1] - ts->cx_data[ii]));

		/* tx(y) gap max */
		if (ii < (ts->tx_count - 1) * ts->rx_count)
			tx_max = max(tx_max, (int)abs(ts->cx_data[ii + ts->rx_count] - ts->cx_data[ii]));
	}

	input_raw_info(true, ts->dev, "%s: rx max:%d, tx max:%d\n", __func__, rx_max, tx_max);

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		snprintf(buff, sizeof(buff), "%d,%d", 0, rx_max);
		sec_cmd_set_cmd_result_all(sec, buff, SEC_CMD_STR_LEN, "CX2_GAP_RX");
		snprintf(buff, sizeof(buff), "%d,%d", 0, tx_max);
		sec_cmd_set_cmd_result_all(sec, buff, SEC_CMD_STR_LEN, "CX2_GAP_TX");
	}
}

static void run_cx_gap_data_x_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char *buff = NULL;
	int ii;
	char temp[5] = { 0 };

	buff = kzalloc(ts->tx_count * ts->rx_count * 5, GFP_KERNEL);
	if (!buff) {
		snprintf(temp, sizeof(temp), "NG");
		sec_cmd_set_cmd_result(sec, temp, strnlen(temp, sizeof(temp)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	for (ii = 0; ii < (ts->rx_count * ts->tx_count); ii++) {
		if ((ii + 1) % (ts->rx_count) != 0) {
			snprintf(temp, sizeof(temp), "%d,", (int)abs(ts->cx_data[ii + 1] - ts->cx_data[ii]));
			strlcat(buff, temp, ts->tx_count * ts->rx_count * 5);
			memset(temp, 0x00, 5);
		}
	}

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, ts->tx_count * ts->rx_count * 5));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	kfree(buff);
}

static void run_cx_gap_data_y_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char *buff = NULL;
	int ii;
	char temp[5] = { 0 };

	buff = kzalloc(ts->tx_count * ts->rx_count * 5, GFP_KERNEL);
	if (!buff) {
		snprintf(temp, sizeof(temp), "NG");
		sec_cmd_set_cmd_result(sec, temp, strnlen(temp, sizeof(temp)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	for (ii = 0; ii < (ts->rx_count * ts->tx_count); ii++) {
		if (ii < (ts->tx_count - 1) * ts->rx_count) {
			snprintf(temp, sizeof(temp), "%d,",
					(int)abs(ts->cx_data[ii + ts->rx_count] - ts->cx_data[ii]));
			strlcat(buff, temp, ts->tx_count * ts->rx_count * 5);
			memset(temp, 0x00, 5);
		}
	}

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, ts->tx_count * ts->rx_count * 5));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	kfree(buff);
}

#define GAP_MULTIPLE_VAL	100
static void get_gap_data_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char *buff = NULL;
	int ii;
	char temp[6] = { 0 };
	int node_gap_tx = 0;
	int node_gap_rx = 0;
	int node_gap_max = 0;

	buff = kzalloc(ts->tx_count * ts->rx_count * 6, GFP_KERNEL);
	if (!buff) {
		snprintf(temp, sizeof(temp), "NG");
		sec_cmd_set_cmd_result(sec, temp, strnlen(temp, sizeof(temp)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	for (ii = 0; ii < (ts->rx_count * ts->tx_count); ii++) {
		node_gap_tx = node_gap_rx = node_gap_max = 0;

		/* rx(x) gap max */
		if ((ii + 1) % (ts->rx_count) != 0)
			node_gap_tx = 1 * GAP_MULTIPLE_VAL - (min(ts->pFrame[ii], ts->pFrame[ii + 1]) * GAP_MULTIPLE_VAL) / (max(ts->pFrame[ii], ts->pFrame[ii + 1]));

		/* tx(y) gap max */
		if (ii < (ts->tx_count - 1) * ts->rx_count)
			node_gap_rx = 1 * GAP_MULTIPLE_VAL - (min(ts->pFrame[ii], ts->pFrame[ii + ts->rx_count]) * GAP_MULTIPLE_VAL) / (max(ts->pFrame[ii], ts->pFrame[ii + ts->rx_count]));

		node_gap_max = max(node_gap_tx, node_gap_rx);

		snprintf(temp, sizeof(temp), "%d,", node_gap_max);
		strlcat(buff, temp, ts->tx_count * ts->rx_count * 6);
		memset(temp, 0x00, 6);
	}

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, ts->tx_count * ts->rx_count * 5));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	kfree(buff);
}

static void run_cx_data_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	char buff_minmax[SEC_CMD_STR_LEN] = { 0 };
	int ret;
	s8 cx_min, cx_max;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: start\n", __func__);

	ret = read_ms_cx_data(ts, NORMAL_CX2, &cx_min, &cx_max);
	if (ret < 0) {
		snprintf(buff, sizeof(buff), "NG");
		snprintf(buff_minmax, sizeof(buff_minmax), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff_minmax, sizeof(buff_minmax), "%d,%d", cx_min, cx_max);
		snprintf(buff, sizeof(buff), "OK");
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff_minmax, strnlen(buff_minmax, sizeof(buff_minmax)), "CX2_DATA");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_cx_data_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret, i, j;
	s8 cx_min, cx_max;
	char *all_strbuff;

	input_info(true, ts->dev, "%s: start\n", __func__);

	ret = read_ms_cx_data(ts, NORMAL_CX2, &cx_min, &cx_max);

	enter_factory_mode(ts, false);

	if (ret < 0) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 4 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	/* Read compensation data */
	if (ts->cx_data) {
		for (j = 0; j < ts->tx_count; j++) {
			for (i = 0; i < ts->rx_count; i++) {
				snprintf(buff, sizeof(buff), "%d,", ts->cx_data[j * ts->rx_count + i]);
				strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 4 + 1);
			}
		}
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
}

static void stm_ts_read_ix_data(struct stm_ts_data *ts, bool allnode)
{
	struct sec_cmd_data *sec = &ts->sec;
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;
	u16 max_tx_ix_sum = 0;
	u16 min_tx_ix_sum = 0xFFFF;
	u16 max_rx_ix_sum = 0;
	u16 min_rx_ix_sum = 0xFFFF;
	u8 *data;
	u8 reg[STM_TS_EVENT_BUFF_SIZE];
	u8 dataID;
	u16 force_ix_data[100];
	u16 sense_ix_data[100];
	int buff_size, j;
	char *mbuff = NULL;
	int num, n, a, fzero;
	char cnum;
	int i = 0;
	u16 comp_start_tx_addr, comp_start_rx_addr;
	unsigned int rx_num, tx_num;

	data = kzalloc((ts->tx_count + ts->rx_count) * 2 + 1, GFP_KERNEL);
	if (!data)
		return;

	ts->stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true); // Clear FIFO

	stm_ts_release_all_finger(ts);

	// Request compensation data type
	dataID = 0x52;
	reg[0] = 0xA4;
	reg[1] = 0x06;
	reg[2] = dataID; // SS - CX total

	ret = stm_ts_wait_for_echo_event(ts, &reg[0], 3, 0);
	if (ret < 0) {
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	// Read Header
	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = 0x00;
	reg[2] = 0x00;
	ts->stm_ts_read(ts, &reg[0], 3, &data[0], STM_TS_COMP_DATA_HEADER_SIZE);

	if ((data[0] != 0xA5) && (data[1] != dataID)) {
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	tx_num = data[4];
	rx_num = data[5];

	/* Read TX IX data */
	comp_start_tx_addr = (u16)STM_TS_COMP_DATA_HEADER_SIZE;
	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = (u8)(comp_start_tx_addr >> 8);
	reg[2] = (u8)(comp_start_tx_addr & 0xFF);
	ts->stm_ts_read(ts, &reg[0], 3, &data[0], tx_num * 2);

	for (i = 0; i < tx_num; i++) {
		force_ix_data[i] = data[2 * i] | data[2 * i + 1] << 8;

		if (max_tx_ix_sum < force_ix_data[i])
			max_tx_ix_sum = force_ix_data[i];
		if (min_tx_ix_sum > force_ix_data[i])
			min_tx_ix_sum = force_ix_data[i];

	}

	/* Read RX IX data */
	comp_start_rx_addr = (u16)(STM_TS_COMP_DATA_HEADER_SIZE + (tx_num * 2));
	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = (u8)(comp_start_rx_addr >> 8);
	reg[2] = (u8)(comp_start_rx_addr & 0xFF);
	ts->stm_ts_read(ts, &reg[0], 3, &data[0], rx_num * 2);

	for (i = 0; i < rx_num; i++) {
		sense_ix_data[i] = data[2 * i] | data[2 * i + 1] << 8;

		if (max_rx_ix_sum < sense_ix_data[i])
			max_rx_ix_sum = sense_ix_data[i];
		if (min_rx_ix_sum > sense_ix_data[i])
			min_rx_ix_sum = sense_ix_data[i];
	}

	stm_ts_print_channel(ts, force_ix_data, sense_ix_data);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: MIN_TX_IX_SUM : %d MAX_TX_IX_SUM : %d\n",
			__func__, min_tx_ix_sum, max_tx_ix_sum);
	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: MIN_RX_IX_SUM : %d MAX_RX_IX_SUM : %d\n",
			__func__, min_rx_ix_sum, max_rx_ix_sum);

	if (allnode == true) {
		buff_size = (ts->tx_count + ts->rx_count + 2) * 5;
		mbuff = kzalloc(buff_size, GFP_KERNEL);
	}
	if (mbuff != NULL) {
		char *pBuf = mbuff;

		for (i = 0; i < ts->tx_count; i++) {
			num =  force_ix_data[i];
			n = 100000;
			fzero = 0;
			for (j = 5; j > 0; j--) {
				n = n / 10;
				a = num / n;
				if (a)
					fzero = 1;
				cnum = a + '0';
				num  = num - a*n;
				if (fzero)
					*pBuf++ = cnum;
			}
			if (!fzero)
				*pBuf++ = '0';
			*pBuf++ = ',';
		}
		for (i = 0; i < ts->rx_count; i++) {
			num =  sense_ix_data[i];
			n = 100000;
			fzero = 0;
			for (j = 5; j > 0; j--) {
				n = n / 10;
				a = num / n;
				if (a)
					fzero = 1;
				cnum = a + '0';
				num  = num - a * n;
				if (fzero)
					*pBuf++ = cnum;
			}
			if (!fzero)
				*pBuf++ = '0';
			if (i < (ts->rx_count - 1))
				*pBuf++ = ',';
		}

		sec_cmd_set_cmd_result(sec, mbuff, buff_size);
		sec->cmd_state = SEC_CMD_STATUS_OK;
		kfree(mbuff);
		return;
	}

	if (allnode == true) {
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff, sizeof(buff), "%d,%d,%d,%d",
				min_tx_ix_sum, max_tx_ix_sum, min_rx_ix_sum, max_rx_ix_sum);
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

out:
	kfree(data);

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		char ret_buff[SEC_CMD_STR_LEN] = { 0 };

		snprintf(ret_buff, sizeof(ret_buff), "%d,%d", min_rx_ix_sum, max_rx_ix_sum);
		sec_cmd_set_cmd_result_all(sec, ret_buff, strnlen(ret_buff, sizeof(ret_buff)), "IX_DATA_RX");
		snprintf(ret_buff, sizeof(ret_buff), "%d,%d", min_tx_ix_sum, max_tx_ix_sum);
		sec_cmd_set_cmd_result_all(sec, ret_buff, strnlen(ret_buff, sizeof(ret_buff)), "IX_DATA_TX");
	}
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_ix_data_read(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s\n", __func__);
	stm_ts_read_ix_data(ts, false);
}

static void run_ix_data_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	enter_factory_mode(ts, true);
	stm_ts_read_ix_data(ts, true);
	enter_factory_mode(ts, false);
}

static void run_self_raw_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	enter_factory_mode(ts, true);
	stm_ts_read_self_raw_frame(ts, true);
	enter_factory_mode(ts, false);
}

static void run_rawdata_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };

	input_raw_data_clear();

	ts->tsp_dump_lock = true;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev,
			"%s: start (noise:%d, wet:%d, tc:%d)##\n",
			__func__, atomic_read(&ts->plat_data->touch_noise_status), ts->plat_data->wet_mode,
			ts->plat_data->touch_count);

	run_high_frequency_rawcap_read(sec);
#if 0 // this function is no longer support in Samsung
	run_low_frequency_rawcap_read(sec);
#endif
	run_rawcap_read(sec);
	run_self_raw_read(sec);
	stm_ts_checking_miscal(ts);
	run_cx_data_read(sec);
	run_ix_data_read(sec);
	stm_ts_panel_ito_test(ts, OPEN_SHORT_CRACK_TEST);
	run_mutual_jitter(sec);

	ts->tsp_dump_lock = false;

	sec->cmd_state = SEC_CMD_STATUS_OK;

	input_raw_info_d(GET_DEV_COUNT(ts->multi_dev), ts->dev, "%s: %s\n", __func__, buff);
}

void stm_ts_run_rawdata_all(struct stm_ts_data *ts)
{
	struct sec_cmd_data *sec = &ts->sec;

	run_rawdata_read_all(sec);
}

static void run_trx_short_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int result = 0;
	int type = 0;
	char test[32];

	if (sec->cmd_param[0] == 1 && sec->cmd_param[1] == 0) {
		input_err(true, ts->dev,
				"%s: %s: seperate cm1 test open / short test result\n", __func__, buff);

		snprintf(buff, sizeof(buff), "%s", "CONT");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_OK;
		return;
	}

	if (sec->cmd_param[0] == 1 && sec->cmd_param[1] == 1) {
		type = OPEN_TEST;
	} else if (sec->cmd_param[0] == 1 && sec->cmd_param[1] == 2) {
		type = SHORT_TEST;
	} else {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		input_info(true, ts->dev, "%s : not supported test case\n", __func__);
		return;
	}

	input_info(true, ts->dev, "%s : CM%d factory_position[%d]\n",
					__func__, sec->cmd_param[0], ts->factory_position);

	/* Prevent F3 12 Error */
	stm_ts_systemreset(ts, 0);
	stm_ts_set_hsync_scanmode(ts, STM_TS_CMD_LPM_ASYNC_SCAN);

	ts->stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true); // Clear FIFO
	stm_ts_release_all_finger(ts);

	result = stm_ts_panel_test_result(ts, type);

	/* reinit */
	stm_ts_reinit(ts);

	ts->plat_data->touch_count = 0;

	if (sec->cmd_param[1])
		snprintf(test, sizeof(test), "TEST=%d,%d", sec->cmd_param[0], sec->cmd_param[1]);
	else
		snprintf(test, sizeof(test), "TEST=%d", sec->cmd_param[0]);

	if (result == 0)
		sec_cmd_send_event_to_user(sec, test, "RESULT=PASS");
	else
		sec_cmd_send_event_to_user(sec, test, "RESULT=FAIL");

	input_info(true, ts->dev, "%s : test done\n", __func__);
}

#ifdef TCLM_CONCEPT
static void get_pat_information(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[50] = { 0 };

#ifdef CONFIG_SEC_FACTORY
	if (ts->factory_position == 1) {
		sec_tclm_initialize(ts->tdata);
		stm_tclm_data_read(stm_ts_get_client_dev(ts), SEC_TCLM_NVM_ALL_DATA);
	}
#endif
	/* fixed tune version will be saved at excute autotune */
	snprintf(buff, sizeof(buff), "C%02XT%04X.%4s%s%c%d%c%d%c%d",
		ts->tdata->nvdata.cal_count, ts->tdata->nvdata.tune_fix_ver,
		ts->tdata->tclm_string[ts->tdata->nvdata.cal_position].f_name,
		(ts->tdata->tclm_level == TCLM_LEVEL_LOCKDOWN) ? ".L " : " ",
		ts->tdata->cal_pos_hist_last3[0], ts->tdata->cal_pos_hist_last3[1],
		ts->tdata->cal_pos_hist_last3[2], ts->tdata->cal_pos_hist_last3[3],
		ts->tdata->cal_pos_hist_last3[4], ts->tdata->cal_pos_hist_last3[5]);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void set_external_factory(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	ts->tdata->external_factory = true;
	sec->cmd_state = SEC_CMD_STATUS_OK;
}

static void tclm_test_cmd(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	struct sec_tclm_data *data = ts->tdata;
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret = 0;

	if (!ts->tdata->support_tclm_test)
		goto not_support;

	ret = tclm_test_command(data, sec->cmd_param[0], sec->cmd_param[1], sec->cmd_param[2], buff);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	else
		sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	return;

not_support:
	snprintf(buff, sizeof(buff), "%s", "NA");
	sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
}

static void get_calibration(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };

	if (!ts->tdata->support_tclm_test)
		goto not_support;

	snprintf(buff, sizeof(buff), "%d", ts->is_cal_done);

	ts->is_cal_done = false;
	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	return;

not_support:
	snprintf(buff, sizeof(buff), "%s", "NA");
	sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
}
#endif

static void run_factory_miscalibration(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN];
	char data[STM_TS_EVENT_BUFF_SIZE];
	char echo;
	int ret;
	int retry = 200;
	short min = SHRT_MIN, max = SHRT_MAX;

	disable_irq(ts->irq);

	memset(data, 0x00, sizeof(data));
	memset(buff, 0x00, sizeof(buff));

	data[0] = 0xC7;
	data[1] = 0x02;
	ret = ts->stm_ts_write(ts, data, 2, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: write failed: %d\n", __func__, ret);
		goto error;
	}

	sec_delay(200);

	/* maximum timeout 2sec ? */
	while (retry-- >= 0) {
		memset(data, 0x00, sizeof(data));
		echo = STM_TS_READ_ONE_EVENT;
		ret = ts->stm_ts_read(ts, &echo, 1, data, STM_TS_EVENT_BUFF_SIZE);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: read failed: %d\n", __func__, ret);
			goto error;
		}

		input_info(true, ts->dev, "%s: %02X %02X %02X %02X %02X %02X %02X %02X\n",
				__func__, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7]);
		sec_delay(10);

		if (data[0] == 0x03 || data[0] == 0xF3) {
			max = data[3] << 8 | data[2];
			min = data[5] << 8 | data[4];

			break;
		}
		if (retry == 0)
			goto error;
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING) {
		snprintf(buff, sizeof(buff), "%d,%d", min, max);
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MIS_CAL");
	} else {
		if (data[0] == 0x03) {
			snprintf(buff, sizeof(buff), "OK,%d,%d", min, max);
		} else {
			snprintf(buff, sizeof(buff), "NG,%d,%d", min, max);
		}
	}
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;
	stm_ts_reinit(ts);
	enable_irq(ts->irq);
	return;

error:
	snprintf(buff, sizeof(buff), "NG");
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "MIS_CAL");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
	stm_ts_reinit(ts);
	enable_irq(ts->irq);

}

static void run_factory_miscalibration_read_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	u8 reg[3] = { 0 };
	short min = 0x7FFF;
	short max = 0x8000;
	char *all_strbuff;
	int i, j;

	all_strbuff = kzalloc(ts->tx_count * ts->rx_count * 7 + 1, GFP_KERNEL);
	if (!all_strbuff) {
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	ts->stm_ts_systemreset(ts, 0);
	stm_ts_command(ts, STM_TS_CMD_CLEAR_ALL_EVENT, true);

	stm_ts_release_all_finger(ts);

	/* get the raw data after C7 02 : mis cal test */
	reg[0] = 0xC7;
	reg[1] = 0x02;

	ts->stm_ts_write(ts, &reg[0], 2, NULL, 0);
	sec_delay(300);
	stm_ts_read_nonsync_frame(ts, &min, &max);

	stm_ts_set_scanmode(ts, ts->scan_mode);

	for (j = 0; j < ts->tx_count; j++) {
		for (i = 0; i < ts->rx_count; i++) {
			snprintf(buff, sizeof(buff), "%d,", ts->pFrame[j * ts->rx_count + i]);
			strlcat(all_strbuff, buff, ts->tx_count * ts->rx_count * 7);
		}
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, all_strbuff, strlen(all_strbuff));
	input_info(true, ts->dev, "%s: %ld\n", __func__, strlen(all_strbuff));
	kfree(all_strbuff);
}

static void run_miscalibration(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN];
	char data[STM_TS_EVENT_BUFF_SIZE];
	char echo;
	int ret;
	int retry = 200;
	short min = SHRT_MIN, max = SHRT_MAX;

	disable_irq(ts->irq);
	memset(data, 0x00, sizeof(data));
	memset(buff, 0x00, sizeof(buff));

	data[0] = 0xA4;
	data[1] = 0x0B;
	data[2] = 0x00;
	data[3] = 0xC0;

	ret = ts->stm_ts_write(ts, data, 4, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: write failed: %d\n", __func__, ret);
		goto error;
	}

	sec_delay(5);

	/* maximum timeout 2sec ? */
	while (retry-- >= 0) {
		memset(data, 0x00, sizeof(data));
		echo = STM_TS_READ_ONE_EVENT;
		ret = ts->stm_ts_read(ts, &echo, 1, data, STM_TS_EVENT_BUFF_SIZE);
		if (ret < 0) {
			input_err(true, ts->dev, "%s: read failed: %d\n", __func__, ret);
			goto error;
		}

		input_info(true, ts->dev, "%s: %02X %02X %02X %02X %02X %02X %02X %02X\n",
				__func__, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7]);
		sec_delay(10);

		if (data[0] == 0x03 || data[0] == 0xF3) {
			max = data[3] << 8 | data[2];
			min = data[5] << 8 | data[4];

			break;
		}
		if (retry == 0)
			goto error;
	}

	if (data[0] == 0x03) {
		snprintf(buff, sizeof(buff), "OK,%d,%d", min, max);
	} else {
		snprintf(buff, sizeof(buff), "NG,%d,%d", min, max);
	}
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;

	stm_ts_reinit(ts);
	enable_irq(ts->irq);
	return;
error:
	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;
	stm_ts_reinit(ts);
	enable_irq(ts->irq);
}

static void check_connection(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = stm_ts_panel_ito_test(ts, OPEN_TEST);
	if (ret == 0)
		sec->cmd_state = SEC_CMD_STATUS_OK;
	else
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

int stm_ts_get_tsp_test_result(struct stm_ts_data *ts)
{
	u8 data;
	int ret;

	ret = get_nvm_data(ts, STM_TS_NVM_OFFSET_FAC_RESULT, &data);
	if (ret < 0)
		goto err_read;

	if (data == 0xFF)
		data = 0;

	ts->test_result.data[0] = data;

err_read:
	return ret;
}
EXPORT_SYMBOL(stm_ts_get_tsp_test_result);

static void get_tsp_test_result(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;

	ret = stm_ts_get_tsp_test_result(ts);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: get failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff, sizeof(buff), "M:%s, M:%d, A:%s, A:%d",
				ts->test_result.module_result == 0 ? "NONE" :
				ts->test_result.module_result == 1 ? "FAIL" :
				ts->test_result.module_result == 2 ? "PASS" : "A",
				ts->test_result.module_count,
				ts->test_result.assy_result == 0 ? "NONE" :
				ts->test_result.assy_result == 1 ? "FAIL" :
				ts->test_result.assy_result == 2 ? "PASS" : "A",
				ts->test_result.assy_count);

		sec_cmd_set_cmd_result(sec, buff, strlen(buff));
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}
}

/* FACTORY TEST RESULT SAVING FUNCTION
 * bit 3 ~ 0 : OCTA Assy
 * bit 7 ~ 4 : OCTA module
 * param[0] : OCTA module(1) / OCTA Assy(2)
 * param[1] : TEST NONE(0) / TEST FAIL(1) / TEST PASS(2) : 2 bit
 */
static void set_tsp_test_result(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = stm_ts_get_tsp_test_result(ts);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: get failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}
	sec->cmd_state = SEC_CMD_STATUS_RUNNING;

	if (sec->cmd_param[0] == TEST_OCTA_ASSAY) {
		ts->test_result.assy_result = sec->cmd_param[1];
		if (ts->test_result.assy_count < 3)
			ts->test_result.assy_count++;

	} else if (sec->cmd_param[0] == TEST_OCTA_MODULE) {
		ts->test_result.module_result = sec->cmd_param[1];
		if (ts->test_result.module_count < 3)
			ts->test_result.module_count++;
	}

	input_info(true, ts->dev, "%s: [0x%X] M:%s, M:%d, A:%s, A:%d\n",
			__func__, ts->test_result.data[0],
			ts->test_result.module_result == 0 ? "NONE" :
			ts->test_result.module_result == 1 ? "FAIL" :
			ts->test_result.module_result == 2 ? "PASS" : "A",
			ts->test_result.module_count,
			ts->test_result.assy_result == 0 ? "NONE" :
			ts->test_result.assy_result == 1 ? "FAIL" :
			ts->test_result.assy_result == 2 ? "PASS" : "A",
			ts->test_result.assy_count);

	ret = set_nvm_data(ts, STM_TS_NVM_OFFSET_FAC_RESULT, ts->test_result.data);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: set failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

int stm_ts_get_disassemble_count(struct stm_ts_data *ts)
{
	u8 data;
	int ret;

	ret = get_nvm_data(ts, STM_TS_NVM_OFFSET_DISASSEMBLE_COUNT, &data);
	if (ret < 0)
		goto err_read;

	if (data == 0xFF)
		data = 0;

	ts->disassemble_count = data;

err_read:
	return ret;
}

static void increase_disassemble_count(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = stm_ts_get_disassemble_count(ts);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: get failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}
	sec->cmd_state = SEC_CMD_STATUS_RUNNING;

	if (ts->disassemble_count < 0xFE)
		ts->disassemble_count++;

	ret = set_nvm_data(ts, STM_TS_NVM_OFFSET_DISASSEMBLE_COUNT, &ts->disassemble_count);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: set failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void get_disassemble_count(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;

	ret = stm_ts_get_disassemble_count(ts);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: get failed. ret: %d\n", __func__, ret);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff, sizeof(buff), "%d", ts->disassemble_count);

		sec_cmd_set_cmd_result(sec, buff, strlen(buff));
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}
}

static void get_osc_trim_error(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;

	ret = ts->stm_ts_systemreset(ts, 0);
	if (ret == -STM_TS_ERROR_BROKEN_OSC_TRIM) {
		snprintf(buff, sizeof(buff), "1");
	} else {
		snprintf(buff, sizeof(buff), "0");
	}
	stm_ts_set_scanmode(ts, ts->scan_mode);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "OSC_TRIM_ERR");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void get_osc_trim_info(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret;
	unsigned char data[4];
	unsigned char reg[3];

	ret = stm_ts_get_sysinfo_data(ts, STM_TS_SI_OSC_TRIM_INFO, 2, data);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: system info read failed. ret: %d\n", __func__, ret);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	reg[0] = STM_TS_CMD_FRM_BUFF_R;
	reg[1] = data[1];
	reg[2] = data[0];

	memset(data, 0x00, 4);
	ret = ts->stm_ts_read(ts, reg, 3, data, 4);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: osc trim info read failed. ret: %d\n", __func__, ret);
		snprintf(buff, sizeof(buff), "NG");
		sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	snprintf(buff, sizeof(buff), "%02X%02X%02X%02X", data[0], data[1], data[2], data[3]);

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "OSC_TRIM_INFO");
	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_elvss_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;
	u8 data[STM_TS_EVENT_BUFF_SIZE + 1];
	int retry = 10;

	stm_ts_systemreset(ts, 0);
	disable_irq(ts->irq);

	memset(data, 0x00, 8);

	data[0] = 0xA4;
	data[1] = 0x04;
	data[2] = 0x00;
	data[3] = 0x04;

	ret = ts->stm_ts_write(ts, &data[0], 4, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: write failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		stm_ts_reinit(ts);
		enable_irq(ts->irq);
		return;
	}

	sec_delay(5);

	memset(data, 0x00, STM_TS_EVENT_BUFF_SIZE);
	data[0] = STM_TS_READ_ONE_EVENT;

	while (ts->stm_ts_read(ts, &data[0], 1, &data[1], STM_TS_EVENT_BUFF_SIZE) >= 0) {
		input_info(true, ts->dev,
			"%s: %02X: %02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X\n",
			__func__, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
			data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);

		if (data[1] == STM_TS_EVENT_ERROR_REPORT) {
			sec->cmd_state = SEC_CMD_STATUS_FAIL;
			break;
		} else if (data[1] == 0x03) {
			sec->cmd_state = SEC_CMD_STATUS_OK;
			break;
		} else if (retry < 0) {
			sec->cmd_state = SEC_CMD_STATUS_FAIL;
			break;
		}
		retry--;
		sec_delay(50);
	}

	stm_ts_reinit(ts);
	enable_irq(ts->irq);

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void run_snr_non_touched(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	u8 address[5] = { 0 };
	u16 status;
	int ret = 0;
	int wait_time = 0;
	int retry_cnt = 0;

	if (sec->cmd_param[0] < 1 || sec->cmd_param[0] > 1000) {
		input_err(true, ts->dev, "%s: strange value frame:%d\n",
				__func__, sec->cmd_param[0]);
		goto ERROR_INIT;
	}

	ret = stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_TRUE);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to set active mode\n", __func__);
		goto ERROR_INIT;
	}

	/* start Non-touched Peak Noise */
	address[0] = 0xC7;
	address[1] = 0x09;
	address[2] = 0x01;
	address[3] = (u8)(sec->cmd_param[0] & 0xff);
	address[4] = (u8)(sec->cmd_param[0] >> 8);
	ret = ts->stm_ts_write(ts, &address[0], 5, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: i2c_write failed\n", __func__);
		goto ERROR;
	}

	/* enter SNR mode */
	address[0] = 0x70;
	address[1] = 0x25;
	ret = ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: i2c_write failed\n", __func__);
		goto ERROR;
	}

	wait_time = (sec->cmd_param[0] * 1000) / 120 + 200;	/* frame count * 1000 / frame rate + 200 msec margin*/

	sec_delay(wait_time);

	retry_cnt = 50;
	address[0] = STM_TS_CMD_SNR_R;
	while ((ts->stm_ts_read(ts, &address[0], 1, (u8 *)&status, STM_TS_CMD_SNR_R_SIZE) >= 0) && (retry_cnt-- > 0)) {
		if (status == 1)
			break;
		sec_delay(20);
	}

	if (status == 0) {
		input_err(true, ts->dev, "%s: failed non-touched status:%d\n", __func__, status);
		goto ERROR;
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;

	/* EXIT SNR mode */
	address[0] = 0x70;
	address[1] = 0x00;
	ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_FALSE_SNR);
	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");

	return;

ERROR:
	address[0] = 0x70;
	address[1] = 0x00;
	ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_FALSE_SNR);

ERROR_INIT:
	sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
}

static void run_snr_touched(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	struct stm_ts_snr_result_cmd snr_cmd_result;
	struct stm_ts_snr_result snr_result;
	char buff[SEC_CMD_STR_LEN] = { 0 };
	char tbuff[SEC_CMD_STR_LEN] = { 0 };
	u8 address[5] = { 0 };
	int ret = 0;
	int wait_time = 0;
	int retry_cnt = 0;
	int i = 0;

	memset(&snr_result, 0, sizeof(struct stm_ts_snr_result));
	memset(&snr_cmd_result, 0, sizeof(struct stm_ts_snr_result_cmd));

	if (sec->cmd_param[0] < 1 || sec->cmd_param[0] > 1000) {
		input_err(true, ts->dev, "%s: strange value frame:%d\n",
				__func__, sec->cmd_param[0]);
		goto ERROR_INIT;
	}

	ret = stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_TRUE);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to set active mode\n", __func__);
		goto ERROR_INIT;
	}

	/* start touched Peak Noise */
	address[0] = 0xC7;
	address[1] = 0x09;
	address[2] = 0x02;
	address[3] = (u8)(sec->cmd_param[0] & 0xff);
	address[4] = (u8)(sec->cmd_param[0] >> 8);
	ret = ts->stm_ts_write(ts, &address[0], 5, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: i2c_write failed\n", __func__);
		goto ERROR;
	}

	/* enter SNR mode */
	address[0] = 0x70;
	address[1] = 0x25;
	ret = ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: i2c_write failed\n", __func__);
		goto ERROR;
	}

	wait_time = (sec->cmd_param[0] * 1000) / 120 + 200;	/* frame count * 1000 / frame rate + 200 msec margin*/
	sec_delay(wait_time);

	retry_cnt = 50;
	memset(address, 0x00, 5);
	address[0] = STM_TS_CMD_SNR_R;
	while ((ts->stm_ts_read(ts, &address[0], 1, (u8 *)&snr_cmd_result, 6) >= 0) && (retry_cnt-- > 0)) {
		if (snr_cmd_result.status == 1)
			break;
		sec_delay(20);
	}

	if (snr_cmd_result.status == 0) {
		input_err(true, ts->dev, "%s: failed non-touched status:%d\n", __func__, snr_cmd_result.status);
		goto ERROR;
	} else {
		input_info(true, ts->dev, "%s: status:%d, point:%d, average:%d\n", __func__,
			snr_cmd_result.status, snr_cmd_result.point, snr_cmd_result.average);
	}

	memset(address, 0x00, 5);
	address[0] = STM_TS_CMD_SNR_R;
	ret = ts->stm_ts_read(ts, &address[0], 1, (u8 *)&snr_result, sizeof(struct stm_ts_snr_result));
	if (ret < 0) {
		input_err(true, ts->dev, "%s: i2c_write failed size:%ld\n", __func__, sizeof(struct stm_ts_snr_result));
		goto ERROR;
	}

	for (i = 0; i < 9; i++) {
		input_info(true, ts->dev, "%s: average:%d, snr1:%d, snr2:%d\n", __func__,
			snr_result.result[i].average, snr_result.result[i].snr1, snr_result.result[i].snr2);
		snprintf(tbuff, sizeof(tbuff), "%d,%d,%d,",
			snr_result.result[i].average,
			snr_result.result[i].snr1,
			snr_result.result[i].snr2);
		strlcat(buff, tbuff, sizeof(buff));
	}

	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_OK;

	/* EXIT SNR mode */
	address[0] = 0x70;
	address[1] = 0x00;
	ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_FALSE_SNR);
	input_info(true, ts->dev, "%s: %s\n", __func__, buff);

	return;

ERROR:
	address[0] = 0x70;
	address[1] = 0x00;
	ts->stm_ts_write(ts, &address[0], 2, NULL, 0);
	stm_ts_fix_active_mode(ts, STM_TS_ACTIVE_FALSE_SNR);
ERROR_INIT:
	snprintf(buff, sizeof(buff), "NG");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
	sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void run_sram_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN];
	u8 reg;
	u8 data[STM_TS_EVENT_BUFF_SIZE];
	int ret, retry = 0;

	ts->stm_ts_systemreset(ts, 0);

	mutex_lock(&ts->fn_mutex);
	disable_irq(ts->irq);

	reg = STM_TS_CMD_RUN_SRAM_TEST;
	ret = ts->stm_ts_write(ts, &reg, 1, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to write cmd\n", __func__);
		goto error;
	}

	sec_delay(300);

	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);
	ret = -EIO;
	reg = STM_TS_READ_ONE_EVENT;
	while (ts->stm_ts_read(ts, &reg, 1, data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		if (data[0] != 0x00)
			input_info(true, ts->dev,
					"%s: event %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X\n",
					__func__, data[0], data[1], data[2], data[3],
					data[4], data[5], data[6], data[7]);

		if (data[0] == STM_TS_EVENT_PASS_REPORT && data[1] == STM_TS_EVENT_SRAM_TEST_RESULT) {
			ret = 0; /* PASS */
			break;
		} else if (data[0] == STM_TS_EVENT_ERROR_REPORT && data[1] == STM_TS_EVENT_SRAM_TEST_RESULT) {
			ret = 1; /* FAIL */
			break;
		}

		if (retry++ > STM_TS_RETRY_COUNT * 25) {
			input_err(true, ts->dev,
					"%s: Time Over (%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X)\n",
					__func__, data[0], data[1], data[2], data[3],
					data[4], data[5], data[6], data[7]);
			break;
		}
		sec_delay(20);
	}

error:
	mutex_unlock(&ts->fn_mutex);

	if (ret < 0) {
		snprintf(buff, sizeof(buff), "NG");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		snprintf(buff, sizeof(buff), "%d", ret);
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "SRAM");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	stm_ts_reinit(ts);
	enable_irq(ts->irq);
}

static void run_polarity_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN];
	u8 reg;
	u8 data[STM_TS_EVENT_BUFF_SIZE];
	int ret, retry = 0;

	ts->stm_ts_systemreset(ts, 0);

	mutex_lock(&ts->fn_mutex);
	disable_irq(ts->irq);

	reg = STM_TS_CMD_RUN_POLARITY_TEST;
	ret = ts->stm_ts_write(ts, &reg, 1, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed to write cmd\n", __func__);
		goto error;
	}

	sec_delay(300);

	memset(data, 0x0, STM_TS_EVENT_BUFF_SIZE);
	ret = -EIO;
	reg = STM_TS_READ_ONE_EVENT;
	while (ts->stm_ts_read(ts, &reg, 1, data, STM_TS_EVENT_BUFF_SIZE) >= 0) {
		input_info(true, ts->dev,
				"%s: event %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X\n",
				__func__, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7]);

		if (data[0] == STM_TS_EVENT_PASS_REPORT) {
			ret = 0; /* PASS */
			break;
		} else if (data[0] == STM_TS_EVENT_ERROR_REPORT) {
			ret = 1; /* FAIL */
			break;
		}

		if (retry++ > STM_TS_RETRY_COUNT * 25) {
			input_err(true, ts->dev,
					"%s: Time Over (%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X)\n",
					__func__, data[0], data[1], data[2], data[3],
					data[4], data[5], data[6], data[7]);
			break;
		}
		sec_delay(20);
	}

error:
	mutex_unlock(&ts->fn_mutex);

	if (ret == 0) {
		snprintf(buff, sizeof(buff), "0");
		sec->cmd_state = SEC_CMD_STATUS_OK;
	} else {
		snprintf(buff, sizeof(buff), "1");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	}
	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "POLARITY");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	stm_ts_reinit(ts);
	enable_irq(ts->irq);
}

static int run_force_calibration_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
#ifdef TCLM_CONCEPT
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	ts->tdata->external_factory = false;
#endif
	sec->cmd_state = SEC_CMD_STATUS_FAIL;

	return SEC_SUCCESS;
}

static void run_force_calibration(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	bool touch_on = false;

	if (ts->tsp_dump_lock == 1) {
		input_err(true, ts->dev, "%s: ramdump mode is running, %d\n",
				__func__, ts->tsp_dump_lock);
		goto autotune_fail;
	}

	if (ts->plat_data->touch_count > 0) {
		touch_on = true;
		input_err(true, ts->dev, "%s: finger on touch(%d)\n", __func__, ts->plat_data->touch_count);
	}

	ts->stm_ts_systemreset(ts, 0);

	stm_ts_release_all_finger(ts);

	if (touch_on) {
		input_err(true, ts->dev, "%s: finger! do not run autotune\n", __func__);
	} else {
		input_info(true, ts->dev, "%s: run autotune\n", __func__);

		input_err(true, ts->dev, "%s: RUN OFFSET CALIBRATION\n", __func__);
		if (stm_ts_execute_autotune(ts, true) < 0) {
			stm_ts_set_scanmode(ts, ts->scan_mode);
			goto autotune_fail;
		}
#ifdef TCLM_CONCEPT
		/* devide tclm case */
		sec_tclm_case(ts->tdata, sec->cmd_param[0]);

		input_info(true, ts->dev, "%s: param, %d, %c, %d\n", __func__,
			sec->cmd_param[0], sec->cmd_param[0], ts->tdata->root_of_calibration);

		if (sec_execute_tclm_package(ts->tdata, 1) < 0)
			input_err(true, ts->dev,
						"%s: sec_execute_tclm_package\n", __func__);

		sec_tclm_root_of_cal(ts->tdata, CALPOSITION_NONE);
#endif
	}

	stm_ts_set_scanmode(ts, ts->scan_mode);

	if (touch_on)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	else
		sec->cmd_state = SEC_CMD_STATUS_OK;

#ifdef TCLM_CONCEPT
	ts->tdata->external_factory = false;
#endif
	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
	return;

autotune_fail:
#ifdef TCLM_CONCEPT
	ts->tdata->external_factory = false;
#endif
	sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void run_interrupt_gpio_test(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN];
	u8 drv_data[3] = { 0xA4, 0x01, 0x01 };
	u8 irq_data[3] = { 0xA4, 0x01, 0x00 };
	int drv_value = -1;
	int irq_value = -1;

	disable_irq(ts->irq);

	ts->stm_ts_write(ts, drv_data, 3, NULL, 0);

	sec_delay(50);

	drv_value = gpio_get_value(ts->plat_data->irq_gpio);
	ts->stm_ts_write(ts, irq_data, 3, NULL, 0);

	sec_delay(50);

	irq_value = gpio_get_value(ts->plat_data->irq_gpio);
	input_info(true, ts->dev, "%s: drv_value:%d, irq_value:%d\n", __func__, drv_value, irq_value);

	if (drv_value == 0 && irq_value == 1) {
		snprintf(buff, sizeof(buff), "0");
		sec->cmd_state = SEC_CMD_STATUS_OK;
	} else {
		if (drv_value != 0)
			snprintf(buff, sizeof(buff), "1:HIGH");
		else if (irq_value != 1)
			snprintf(buff, sizeof(buff), "1:LOW");
		else
			snprintf(buff, sizeof(buff), "1:FAIL");
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	}

	if (sec->cmd_all_factory_state == SEC_CMD_STATUS_RUNNING)
		sec_cmd_set_cmd_result_all(sec, buff, strnlen(buff, sizeof(buff)), "INT_GPIO");
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	stm_ts_reinit(ts);
	enable_irq(ts->irq);
}

static void set_factory_level(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < OFFSET_FAC_SUB || sec->cmd_param[0] > OFFSET_FAC_MAIN) {
		input_err(true, ts->dev,
				"%s: cmd data is abnormal, %d\n", __func__, sec->cmd_param[0]);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	ts->factory_position = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %d\n", __func__, ts->factory_position);

	sec->cmd_state = SEC_CMD_STATUS_OK;
}

static void factory_cmd_result_all(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	sec->item_count = 0;
	memset(sec->cmd_result_all, 0x00, SEC_CMD_RESULT_STR_LEN);

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: [ERROR] Touch is stopped\n",
				__func__);
		sec->cmd_all_factory_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	sec->cmd_all_factory_state = SEC_CMD_STATUS_RUNNING;

	get_chip_vendor(sec);
	get_chip_name(sec);
	get_fw_ver_bin(sec);
	get_fw_ver_ic(sec);

	enter_factory_mode(ts, true);
	if (ts->support_mutual_raw)
		run_lp_single_ended_rawcap_read(sec);	/* Mutual raw */
	else
		run_rawcap_read(sec);
	run_self_raw_read(sec);

	stm_ts_set_scanmode(ts, STM_TS_SCAN_MODE_SCAN_OFF);
	stm_ts_release_all_finger(ts);

	run_active_cx_data_read(sec);
	run_cx_data_read(sec);
	get_cx_gap_data(sec);
	run_ix_data_read(sec);

	enter_factory_mode(ts, false);

	get_wet_mode(sec);

	run_mutual_jitter(sec);
	run_self_jitter(sec);
	run_factory_miscalibration(sec);
	run_sram_test(sec);
	run_polarity_test(sec);

	run_high_frequency_rawcap_read(sec);
	run_interrupt_gpio_test(sec);

	sec->cmd_all_factory_state = SEC_CMD_STATUS_OK;

out:
	input_info(true, ts->dev, "%s: %d%s\n", __func__, sec->item_count, sec->cmd_result_all);
}

static void factory_cmd_result_all_imagetest(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	sec->item_count = 0;
	memset(sec->cmd_result_all, 0x00, SEC_CMD_RESULT_STR_LEN);

	if (sec_input_cmp_ic_status(ts->dev, CHECK_POWEROFF)) {
		input_err(true, ts->dev, "%s: [ERROR] Touch is stopped\n",
				__func__);
		sec->cmd_all_factory_state = SEC_CMD_STATUS_FAIL;
		goto out;
	}

	sec->cmd_all_factory_state = SEC_CMD_STATUS_RUNNING;

	run_jitter_delta_test(sec);

	sec->cmd_all_factory_state = SEC_CMD_STATUS_OK;

out:
	input_info(true, ts->dev, "%s: %d%s\n", __func__, sec->item_count, sec->cmd_result_all);
}

static int glove_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->glove_enabled = sec->cmd_param[0];
	if (ts->glove_enabled)
		ts->plat_data->touch_functions = ts->plat_data->touch_functions | STM_TS_TOUCHTYPE_BIT_GLOVE;
	else
		ts->plat_data->touch_functions = (ts->plat_data->touch_functions & (~STM_TS_TOUCHTYPE_BIT_GLOVE));

	sec->cmd_state = SEC_CMD_STATUS_OK;
	return SEC_SUCCESS;
}

static void glove_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = glove_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		stm_ts_set_touch_function(ts);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");
}

static int clear_cover_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 3) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0] > 1) {
		ts->plat_data->cover_type = sec->cmd_param[1];
		ts->plat_data->touch_functions |= STM_TS_TOUCHTYPE_BIT_COVER;
	} else {
		ts->plat_data->touch_functions &= ~STM_TS_TOUCHTYPE_BIT_COVER;
	}

	sec->cmd_state = SEC_CMD_STATUS_OK;
	return SEC_SUCCESS;
};

static void clear_cover_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = clear_cover_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		stm_ts_set_cover_type(ts, ts->plat_data->touch_functions & STM_TS_TOUCHTYPE_BIT_COVER);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");
};

static int set_wirelesscharger_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = sec_input_check_wirelesscharger_mode(ts->dev, sec->cmd_param[0], sec->cmd_param[1]);
	if (ret == SEC_ERROR)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	else
		sec->cmd_state = SEC_CMD_STATUS_OK;

	return ret;
};

static void set_wirelesscharger_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
#if IS_ENABLED(CONFIG_INPUT_SEC_NOTIFIER)
	u8 reg[3];
#endif
	int ret = 0;

	ret = set_wirelesscharger_mode_save(device_data);
	if (ret != SEC_SUCCESS) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

#if IS_ENABLED(CONFIG_INPUT_SEC_NOTIFIER)
	reg[0] = STM_TS_CMD_SET_FUNCTION_ONOFF;
	reg[1] = STM_TS_CMD_FUNCTION_SET_TSP_BLOCK;
	reg[2] = 0;
	ret = ts->stm_ts_write(ts, reg, 3, NULL, 0);
	input_info(true, ts->dev, "%s: force tsp unblock, ret=%d\n", __func__, ret);
	sec_input_gesture_report(ts->dev, SPONGE_EVENT_TYPE_TSP_SCAN_UNBLOCK, 0, 0);
#endif

	ret = stm_ts_set_wirelesscharger_mode(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
};

/*
 * index
 *	0 :  set edge handler
 *	1 :  portrait (normal) mode
 *	2 :  landscape mode
 * data
 *	0, X (direction), X (y start), X (y end)
 *	direction : 0 (off), 1 (left), 2 (right)
 *	ex) echo set_grip_data,0,2,600,900 > cmd
 *
 *
 *	1, X (edge zone), X (dead zone up x), X (dead zone down x), X (dead zone y)
 *	ex) echo set_grip_data,1,200,10,50,1500 > cmd
 *
 *	2, 1 (landscape mode), X (edge zone), X (dead zone), X (dead zone top y), X (dead zone bottom y)
 *	ex) echo set_grip_data,2,1,200,100,120,0 > cmd
 *
 *	2, 0 (portrait mode)
 *	ex) echo set_grip_data,2,0  > cmd
 */
static int set_grip_data_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	int mode = G_NONE;

	mode = sec_input_store_grip_data(sec->dev, sec->cmd_param);
	if (mode < 0) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return mode;
}

static void set_grip_data(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int mode = G_NONE;

	mode = set_grip_data_save(device_data);
	if (mode < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	mutex_lock(&ts->plat_data->enable_mutex);
	stm_set_grip_data_to_ic(ts->dev, mode);
	mutex_unlock(&ts->plat_data->enable_mutex);
}

static int dead_zone_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->dead_zone = sec->cmd_param[0];
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void dead_zone_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = dead_zone_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	ret = stm_ts_dead_zone_enable(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int spay_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0])
		ts->plat_data->lowpower_mode |= SEC_TS_MODE_SPONGE_SWIPE;
	else
		ts->plat_data->lowpower_mode &= ~SEC_TS_MODE_SPONGE_SWIPE;

	input_info(true, ts->dev, "%s: %s, %02X\n",
			__func__, sec->cmd_param[0] ? "on" : "off", ts->plat_data->lowpower_mode);

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void spay_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = spay_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	stm_ts_set_custom_library(ts);

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int aot_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0])
		ts->plat_data->lowpower_mode |= SEC_TS_MODE_SPONGE_DOUBLETAP_TO_WAKEUP;
	else
		ts->plat_data->lowpower_mode &= ~SEC_TS_MODE_SPONGE_DOUBLETAP_TO_WAKEUP;

	input_info(true, ts->dev, "%s: %s, %02X\n",
			__func__, sec->cmd_param[0] ? "on" : "off", ts->plat_data->lowpower_mode);

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void aot_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = aot_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		stm_ts_set_custom_library(ts);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	input_info(true, ts->dev, "%s: %d\n", __func__, sec->cmd_param[0]);
}

static int singletap_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0])
		ts->plat_data->lowpower_mode |= SEC_TS_MODE_SPONGE_SINGLE_TAP;
	else
		ts->plat_data->lowpower_mode &= ~SEC_TS_MODE_SPONGE_SINGLE_TAP;

	input_info(true, ts->dev, "%s: %s, %02X\n",
			__func__, sec->cmd_param[0] ? "on" : "off", ts->plat_data->lowpower_mode);

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void singletap_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = singletap_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		stm_ts_set_custom_library(ts);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	input_info(true, ts->dev, "%s: %d\n", __func__, sec->cmd_param[0]);
}

static int aod_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0]) {
		ts->plat_data->lowpower_mode |= SEC_TS_MODE_SPONGE_AOD;
		ts->plat_data->sponge_mode |= SEC_TS_MODE_SPONGE_AOD_NOTI_RECT_AOT;
	} else {
		ts->plat_data->lowpower_mode &= ~SEC_TS_MODE_SPONGE_AOD;
		ts->plat_data->sponge_mode &= ~SEC_TS_MODE_SPONGE_AOD_NOTI_RECT_AOT;
	}

	input_info(true, ts->dev, "%s: %s, %02X\n",
			__func__, sec->cmd_param[0] ? "on" : "off", ts->plat_data->lowpower_mode);

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void aod_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = aod_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		stm_ts_set_custom_library(ts);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	input_info(true, ts->dev, "%s: %d\n", __func__, sec->cmd_param[0]);
}

static int set_aod_rect_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int i;

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	input_info(true, ts->dev, "%s: w:%d, h:%d, x:%d, y:%d\n",
			__func__, sec->cmd_param[0], sec->cmd_param[1],
			sec->cmd_param[2], sec->cmd_param[3]);
#endif

	for (i = 0; i < 4; i++)
		ts->plat_data->aod_data.rect_data[i] = sec->cmd_param[i];

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_aod_rect(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	set_aod_rect_save(device_data);

	ret = stm_ts_set_aod_rect(ts);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	}
}

static int set_aod_noti_rect_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int i;

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	input_info(true, ts->dev, "%s: w:%d, h:%d, x:%d, y:%d\n",
			__func__, sec->cmd_param[0], sec->cmd_param[1],
			sec->cmd_param[2], sec->cmd_param[3]);
#endif

	for (i = 0; i < 4; i++)
		ts->plat_data->aod_noti_data.rect_data[i] = sec->cmd_param[i];

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_aod_noti_rect(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	set_aod_noti_rect_save(device_data);

	ret = stm_ts_set_aod_noti_rect(ts);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	}
}

static void get_aod_rect(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	u8 data[8] = {0, };
	u16 rect_data[4] = {0, };
	int i, ret = -1;

	data[0] = STM_TS_CMD_SPONGE_OFFSET_AOD_RECT;

	ret = ts->stm_ts_read_sponge(ts, data, sizeof(data));
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	for (i = 0; i < 4; i++)
		rect_data[i] = (data[i * 2 + 1] & 0xFF) << 8 | (data[i * 2] & 0xFF);

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	input_info(true, ts->dev, "%s: w:%d, h:%d, x:%d, y:%d\n",
			__func__, rect_data[0], rect_data[1], rect_data[2], rect_data[3]);
#endif

	sec->cmd_state = SEC_CMD_STATUS_OK;
	return;
}

static int fod_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (!ts->plat_data->support_fod) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0])
		ts->plat_data->lowpower_mode |= SEC_TS_MODE_SPONGE_PRESS;
	else
		ts->plat_data->lowpower_mode &= ~SEC_TS_MODE_SPONGE_PRESS;

	ts->plat_data->fod_data.press_prop = (sec->cmd_param[1] & 0x01) | ((sec->cmd_param[2] & 0x01) << 1);

	input_info(true, ts->dev, "%s: %s, fast:%s, strict:%s, %02X\n",
			__func__, sec->cmd_param[0] ? "on" : "off",
			ts->plat_data->fod_data.press_prop & 1 ? "on" : "off",
			ts->plat_data->fod_data.press_prop & 2 ? "on" : "off",
			ts->plat_data->lowpower_mode);
	sec->cmd_state = SEC_CMD_STATUS_OK;

#if IS_ENABLED(CONFIG_INPUT_SEC_SECURE_TOUCH)
#if IS_ENABLED(CONFIG_INPUT_SEC_TRUSTED_TOUCH)
	if (atomic_read(&ts->plat_data->pvm->trusted_touch_enabled)) {
		input_info(true, ts->dev, "%s trusted touch is enabled. skip\n", __func__);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
#endif
#endif

	return SEC_SUCCESS;
}

static void fod_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = fod_enable_save(sec);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	mutex_lock(&ts->plat_data->enable_mutex);

	if (!atomic_read(&ts->plat_data->enabled) && sec_input_need_ic_off(ts->plat_data)) {
		if (atomic_read(&ts->plat_data->power_state) == SEC_INPUT_STATE_LPM)
			disable_irq_wake(ts->irq);
		ts->plat_data->stop_device(ts);
	} else {
		stm_ts_set_custom_library(ts);
		stm_ts_set_press_property(ts);
		stm_ts_set_fod_finger_merge(ts);
	}

	mutex_unlock(&ts->plat_data->enable_mutex);

	sec->cmd_state = SEC_CMD_STATUS_OK;
}

static void fod_lp_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	} else if (!ts->plat_data->support_fod_lp_mode) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return;
	}

	ts->plat_data->fod_lp_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %d\n", __func__, ts->plat_data->fod_lp_mode);

	sec->cmd_state = SEC_CMD_STATUS_OK;
}

static int set_fod_rect_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	input_info(true, ts->dev, "%s: l:%d, t:%d, r:%d, b:%d\n",
			__func__, sec->cmd_param[0], sec->cmd_param[1],
			sec->cmd_param[2], sec->cmd_param[3]);

	if (!ts->plat_data->support_fod) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return SEC_ERROR;
	}

	if (!sec_input_set_fod_rect(ts->dev, sec->cmd_param)) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_fod_rect(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = set_fod_rect_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	ret = stm_ts_set_fod_rect(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static void fp_int_control(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;
	u8 reg[2] = {STM_TS_CMD_SET_FOD_INT_CONTROL, 0x00};
	u8 enable;

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		input_err(true, ts->dev, "%s: invalid param %d\n", __func__, sec->cmd_param[0]);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	} else if (!ts->plat_data->support_fod) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return;
	}

	enable = sec->cmd_param[0];
	if (enable)
		reg[1] = 0x01;
	else
		reg[1] = 0x00;

	ret = ts->stm_ts_write(ts, reg, 2, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev, "%s: failed. ret: %d\n", __func__, ret);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return;
	}

	input_info(true, ts->dev, "%s: fod int %d\n", __func__, enable);

	sec->cmd_state = SEC_CMD_STATUS_OK;
}

/*
 * Enable or disable specific external_noise_mode (sec_cmd)
 *
 * This cmd has 2 params.
 * param 0 : the mode that you want to change.
 * param 1 : enable or disable the mode.
 *
 * For example,
 * enable EXT_NOISE_MODE_MONITOR mode,
 * write external_noise_mode,1,1
 * disable EXT_NOISE_MODE_MONITOR mode,
 * write external_noise_mode,1,0
 */
static int external_noise_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] <= EXT_NOISE_MODE_NONE || sec->cmd_param[0] >= EXT_NOISE_MODE_MAX ||
			sec->cmd_param[1] < 0 || sec->cmd_param[1] > 1) {
		input_err(true, ts->dev, "%s: not support param\n", __func__);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	if (sec->cmd_param[1] == 1)
		ts->plat_data->external_noise_mode |= 1 << sec->cmd_param[0];
	else
		ts->plat_data->external_noise_mode &= ~(1 << sec->cmd_param[0]);

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void external_noise_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = external_noise_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	ret = stm_ts_set_external_noise_mode(ts, ts->plat_data->external_noise_mode);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
}

static int brush_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->brush_mode = sec->cmd_param[0];

	input_info(true, ts->dev,
			"%s: set brush mode %s\n", __func__, ts->brush_mode ? "enable" : "disable");

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void brush_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	u8 reg[3] = {STM_TS_CMD_SET_FUNCTION_ONOFF, STM_TS_FUNCTION_ENABLE_BRUSH_MODE, 0x00};
	int ret = 0;

	ret = brush_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	if (ts->brush_mode == 0)
		reg[2] = 0x00;	/* 0: Disable Artcanvas min phi mode */
	else
		reg[2] = 0x01;	/* 1: Enable Artcanvas min phi mode  */

	ret = ts->stm_ts_write(ts, &reg[0], 3, NULL, 0);
	if (ret < 0) {
		input_err(true, ts->dev,
				"%s: failed to set brush mode\n", __func__);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int set_touchable_area_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->plat_data->touchable_area = sec->cmd_param[0];
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_touchable_area(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = set_touchable_area_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	ret = stm_ts_set_touchable_area(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

}

static void debug(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	ts->debug_flag = sec->cmd_param[0];

	input_info(true, ts->dev, "%s: command is %d\n", __func__, ts->debug_flag);
	sec->cmd_state = SEC_CMD_STATUS_WAITING;
}

#ifdef ENABLE_RAWDATA_SERVICE
static int rawdata_init_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (!ts->plat_data->support_rawdata) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return SEC_ERROR;
	}

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->raw_mode = sec->cmd_param[0]; //param : 1 strength , 2 raw
	input_info(true, ts->dev, "%s: %d\n", __func__, ts->raw_mode);
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void rawdata_init(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char buff[SEC_CMD_STR_LEN] = { 0 };
	int ret = 0;

	ret = rawdata_init_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	snprintf(buff, sizeof(buff), "OK:%d", ts->plat_data->support_rawdata_map_num);
	sec->cmd_state = SEC_CMD_STATUS_OK;
	sec_cmd_set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));

	input_info(true, ts->dev, "%s: %s\n", __func__, buff);
}

static void blocking_palm(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	ts->plat_data->blocking_palm = sec->cmd_param[0];

	sec->cmd_state = SEC_CMD_STATUS_OK;
	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");
}
#endif

static int fix_active_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	ts->fix_active_mode = !!sec->cmd_param[0];
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void fix_active_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = fix_active_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	stm_ts_fix_active_mode(ts, ts->fix_active_mode);

	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");
}

static int touch_aging_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->touch_aging_mode = sec->cmd_param[0];
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void touch_aging_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	char reg[3];
	int ret = 0;

	ret = touch_aging_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->touch_aging_mode) {
		reg[0] = 0xA0;
		reg[1] = 0x03;
		reg[2] = 0x20;

		ts->stm_ts_write(ts, &reg[0], 3, NULL, 0);
	} else {
		stm_ts_reinit(ts);
	}

	input_info(true, ts->dev, "%s: %s\n", __func__, "OK");
}

static int ear_detect_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (!ts->plat_data->support_ear_detect) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return SEC_ERROR;
	} else if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 3) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	ts->plat_data->ed_enable = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n",
			__func__, ts->plat_data->ed_enable ? "on" : "off");
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void ear_detect_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = ear_detect_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	if (ts->probe_done)
		ret = stm_ts_ear_detect_enable(ts, ts->plat_data->ed_enable);
	else
		input_info(true, ts->dev, "%s: probe is not done\n", __func__);

	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int pocket_mode_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (!ts->plat_data->support_ear_detect) {
		sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;
		return SEC_ERROR;
	} else if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->plat_data->pocket_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n",
			__func__, ts->plat_data->pocket_mode ? "enable" : "disable");
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void pocket_mode_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret = 0;

	ret = pocket_mode_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	ret = stm_ts_pocket_mode_enable(ts, ts->plat_data->pocket_mode);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int low_sensitivity_mode_enable_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 3) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->plat_data->low_sensitivity_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n", __func__,
			ts->plat_data->low_sensitivity_mode ? "enable" : "disable");
	sec->cmd_state = SEC_CMD_STATUS_OK;

#if IS_ENABLED(CONFIG_INPUT_SEC_SECURE_TOUCH)
#if IS_ENABLED(CONFIG_INPUT_SEC_TRUSTED_TOUCH)
	if (atomic_read(&ts->plat_data->pvm->trusted_touch_enabled)) {
		input_info(true, ts->dev, "%s trusted touch is enabled. skip\n", __func__);
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
#endif
#endif

	return SEC_SUCCESS;
}

static void low_sensitivity_mode_enable(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;
	u8 reg[3] = { 0 };

	ret = low_sensitivity_mode_enable_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: NG\n", __func__);
		return;
	}

	mutex_lock(&ts->plat_data->enable_mutex);
	reg[0] = STM_TS_CMD_FUNCTION_SET_LOW_SENSITIVITY_MODE;
	reg[1] = sec->cmd_param[0];
	ret = ts->stm_ts_write(ts, &reg[0], 1, &reg[1], 1);
	if (ret < 0) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
	} else {
		sec->cmd_state = SEC_CMD_STATUS_OK;
	}
	mutex_unlock(&ts->plat_data->enable_mutex);

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int set_sip_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	ts->sip_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n", __func__, ts->sip_mode ? "enable" : "disable");

	sec->cmd_state = SEC_CMD_STATUS_OK;
	return SEC_SUCCESS;
}

static void set_sip_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = set_sip_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	ret = stm_ts_sip_mode_enable(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int set_game_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}

	ts->game_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n", __func__, ts->game_mode ? "enable" : "disable");

	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_game_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = set_game_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	ret = stm_ts_game_mode_enable(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static int set_note_mode_save(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	if (sec->cmd_param[0] < 0 || sec->cmd_param[0] > 1) {
		sec->cmd_state = SEC_CMD_STATUS_FAIL;
		return SEC_ERROR;
	}
	ts->note_mode = sec->cmd_param[0];
	input_info(true, ts->dev, "%s: %s\n", __func__, ts->note_mode ? "enable" : "disable");
	sec->cmd_state = SEC_CMD_STATUS_OK;

	return SEC_SUCCESS;
}

static void set_note_mode(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);
	int ret;

	ret = set_note_mode_save(device_data);
	if (ret < 0) {
		input_info(true, ts->dev, "%s: %s\n", __func__, "NG");
		return;
	}

	ret = stm_ts_note_mode_enable(ts);
	if (ret < 0)
		sec->cmd_state = SEC_CMD_STATUS_FAIL;

	input_info(true, ts->dev, "%s: %s\n", __func__, sec->cmd_state == SEC_CMD_STATUS_OK ? "OK" : "NG");
}

static void not_support_cmd(void *device_data)
{
	struct sec_cmd_data *sec = (struct sec_cmd_data *)device_data;
	struct stm_ts_data *ts = container_of(sec, struct stm_ts_data, sec);

	sec->cmd_state = SEC_CMD_STATUS_NOT_APPLICABLE;

	input_info(true, ts->dev, "%s: %s\n", __func__, "NA");
}

struct sec_cmd sec_cmds[] = {
	{SEC_CMD_V2("fw_update", fw_update, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_fw_ver_bin", get_fw_ver_bin, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_fw_ver_ic", get_fw_ver_ic, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_config_ver", get_config_ver, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("module_off_master", module_off_master, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("module_on_master", module_on_master, NULL, CHECK_POWEROFF, WAIT_RESULT),},
	{SEC_CMD_V2("get_chip_vendor", get_chip_vendor, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_chip_name", get_chip_name, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("run_jitter_test", run_jitter_test, NULL, CHECK_POWERON, WAIT_RESULT),},
	{SEC_CMD_V2("run_mutual_jitter", run_mutual_jitter, NULL, CHECK_POWERON, WAIT_RESULT),},
	{SEC_CMD_V2("run_self_jitter", run_self_jitter, NULL, CHECK_POWERON, WAIT_RESULT),},
	{SEC_CMD_V2("run_jitter_delta_test", run_jitter_delta_test, NULL, CHECK_POWERON, WAIT_RESULT),},
	{SEC_CMD_V2("run_lcdoff_mutual_jitter", run_lcdoff_mutual_jitter, NULL, CHECK_POWERON, WAIT_RESULT),},
	{SEC_CMD_V2("get_wet_mode", get_wet_mode, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_x_num", get_x_num, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_y_num", get_y_num, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_checksum_data", get_checksum_data, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_crc_check", check_fw_corruption, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_reference_read", run_reference_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_reference", get_reference, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_rawcap_read", run_rawcap_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_rawcap_read_all", run_rawcap_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_rawcap", get_rawcap, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_lp_single_ended_rawcap_read", run_lp_single_ended_rawcap_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_lp_single_ended_rawcap_read_all", run_lp_single_ended_rawcap_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_low_frequency_rawcap_read", run_low_frequency_rawcap_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_low_frequency_rawcap_read_all", run_low_frequency_rawcap_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_high_frequency_rawcap_read", run_high_frequency_rawcap_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_high_frequency_rawcap_read_all", run_high_frequency_rawcap_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_delta_read", run_delta_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_delta", get_delta, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_prox_intensity_read_all", run_prox_intensity_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_cs_raw_read_all", run_cs_raw_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_cs_delta_read_all", run_cs_delta_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_rawdata_read_all_for_ghost", run_rawdata_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_ix_data_read", run_ix_data_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_ix_data_read_all", run_ix_data_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_self_raw_read", run_self_raw_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_self_raw_read_all", run_self_raw_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_trx_short_test", run_trx_short_test, NULL, CHECK_ON_LP, WAIT_RESULT),},
#ifdef TCLM_CONCEPT
	{SEC_CMD_V2("get_pat_information", get_pat_information, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("set_external_factory", set_external_factory, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("tclm_test_cmd", tclm_test_cmd, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_calibration", get_calibration, NULL, CHECK_ALL, WAIT_RESULT),},
#endif
	{SEC_CMD_V2("run_factory_miscalibration", run_factory_miscalibration, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_factory_miscalibration_read_all", run_factory_miscalibration_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_miscalibration", run_miscalibration, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("check_connection", check_connection, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_cx_data", get_cx_data, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_active_cx_data_read", run_active_cx_data_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_cx_data_read", run_cx_data_read, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_cx_data_read_all", run_cx_data_read_all, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_cx_gap_data_rx_all", run_cx_gap_data_x_all, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("run_cx_gap_data_tx_all", run_cx_gap_data_y_all, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_gap_data_all", get_gap_data_all, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2("get_strength_all_data", get_strength_all_data, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("set_tsp_test_result", set_tsp_test_result, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_tsp_test_result", get_tsp_test_result, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("increase_disassemble_count", increase_disassemble_count, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_disassemble_count", get_disassemble_count, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_osc_trim_error", get_osc_trim_error, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("get_osc_trim_info", get_osc_trim_info, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_elvss_test", run_elvss_test, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_snr_non_touched", run_snr_non_touched, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_snr_touched", run_snr_touched, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_sram_test", run_sram_test, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_polarity_test", run_polarity_test, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("run_force_calibration", run_force_calibration, run_force_calibration_save, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("set_factory_level", set_factory_level, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("factory_cmd_result_all", factory_cmd_result_all, NULL, CHECK_ALL,  WAIT_RESULT),},
	{SEC_CMD_V2("factory_cmd_result_all_imagetest", factory_cmd_result_all_imagetest, NULL, CHECK_ALL, WAIT_RESULT),},
	{SEC_CMD_V2_H("glove_mode", glove_mode, glove_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("clear_cover_mode", clear_cover_mode, clear_cover_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_wirelesscharger_mode", set_wirelesscharger_mode, set_wirelesscharger_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_grip_data", set_grip_data, set_grip_data_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("dead_zone_enable", dead_zone_enable, dead_zone_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("spay_enable", spay_enable, spay_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("singletap_enable", singletap_enable, singletap_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("aot_enable", aot_enable, aot_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("aod_enable", aod_enable, aod_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_aod_rect", set_aod_rect, set_aod_rect_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_aod_noti_rect", set_aod_noti_rect, set_aod_noti_rect_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("get_aod_rect", get_aod_rect, NULL, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("fod_enable", fod_enable, fod_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("fod_lp_mode", fod_lp_mode, NULL, CHECK_ALL, EXIT_RESULT),},
	{SEC_CMD_V2("set_fod_rect", set_fod_rect, set_fod_rect_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("fp_int_control", fp_int_control, NULL, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("external_noise_mode", external_noise_mode, external_noise_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("brush_enable", brush_enable, brush_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("set_touchable_area", set_touchable_area, set_touchable_area_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("debug", debug, NULL, CHECK_ALL, EXIT_RESULT),},
#ifdef ENABLE_RAWDATA_SERVICE
	{SEC_CMD_V2("rawdata_init", rawdata_init, rawdata_init_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("blocking_palm", blocking_palm, NULL, CHECK_ALL, EXIT_RESULT),},
#endif
	{SEC_CMD_V2_H("fix_active_mode", fix_active_mode, fix_active_mode_save, CHECK_POWERON, EXIT_RESULT),},
	{SEC_CMD_V2("touch_aging_mode", touch_aging_mode, touch_aging_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("ear_detect_enable", ear_detect_enable, ear_detect_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2_H("pocket_mode_enable", pocket_mode_enable, pocket_mode_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("low_sensitivity_mode_enable", low_sensitivity_mode_enable, low_sensitivity_mode_enable_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_sip_mode", set_sip_mode, set_sip_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_game_mode", set_game_mode, set_game_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("set_note_mode", set_note_mode, set_note_mode_save, CHECK_ON_LP, EXIT_RESULT),},
	{SEC_CMD_V2("run_interrupt_gpio_test", run_interrupt_gpio_test, NULL, CHECK_ON_LP, WAIT_RESULT),},
	{SEC_CMD_V2("not_support_cmd", not_support_cmd, NULL, CHECK_ALL, EXIT_RESULT),},
};

int stm_ts_fn_init(struct stm_ts_data *ts)
{
	int retval = 0;

	retval = sec_cmd_init(&ts->sec, ts->dev, sec_cmds,
			ARRAY_SIZE(sec_cmds), SEC_CLASS_DEVT_TSP, &cmd_attr_group);
	if (retval < 0) {
		input_err(true, ts->dev,
				"%s: Failed to sec_cmd_init\n", __func__);
		goto exit;
	}

	retval = sysfs_create_link(&ts->sec.fac_dev->kobj,
			&ts->plat_data->input_dev->dev.kobj, "input");
	if (retval < 0) {
		input_err(true, ts->dev,
				"%s: Failed to create input symbolic link\n",
				__func__);
		sec_cmd_exit(&ts->sec, SEC_CLASS_DEVT_TSP);
		goto exit;
	}

	return 0;
exit:
	return retval;
}

void stm_ts_fn_remove(struct stm_ts_data *ts)
{
	input_err(true, ts->dev, "%s\n", __func__);

	sysfs_remove_link(&ts->sec.fac_dev->kobj, "input");

	sec_cmd_exit(&ts->sec, SEC_CLASS_DEVT_TSP);
}

MODULE_LICENSE("GPL");
