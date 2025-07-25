/*
* @file sgpu_governor.c
* @copyright 2020 Samsung Electronics
*/

#include <linux/devfreq.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#include "amdgpu.h"
#include "amdgpu_trace.h"
#include "sgpu_governor.h"
#include "sgpu_utilization.h"

#ifdef CONFIG_DRM_SGPU_EXYNOS
#if IS_ENABLED(CONFIG_CAL_IF)
#include <soc/samsung/cal-if.h>
#include <soc/samsung/fvmap.h>
#endif /* CONFIG_CAL_IF */
#include <linux/notifier.h>
#include "exynos_gpu_interface.h"
#include "sgpu_profiler.h"
#endif /* CONFIG_DRM_SGPU_EXYNOS */
#if IS_ENABLED(CONFIG_EXYNOS_ESCA_DVFS_MANAGER)
#include <soc/samsung/exynos-dm.h>
extern int sgpu_dm_freq_scaler(int dm_type, void *devdata, u32 target_freq, unsigned int relation);
#endif /* CONFIG_EXYNOS_ESCA_DVFS_MANAGER */

/* get frequency and delay time data from string */
unsigned int *sgpu_get_array_data(struct devfreq_dev_profile *dp, const char *buf)
{
	const char *cp;
	int i, j;
	int ntokens = 1;
	unsigned int *tokenized_data, *array_data;
	int err = -EINVAL;

	cp = buf;
	while ((cp = strpbrk(cp + 1, " :")))
		ntokens++;

	if (!(ntokens & 0x1))
		goto err;

	tokenized_data = kmalloc(ntokens * sizeof(unsigned int), GFP_KERNEL);
	if (!tokenized_data) {
		err = -ENOMEM;
		goto err;
	}

	cp = buf;
	i = 0;
	while (i < ntokens) {
		if (sscanf(cp, "%u", &tokenized_data[i++]) != 1)
			goto err_kfree;

		cp = strpbrk(cp, " :");
		if (!cp)
			break;
		cp++;
	}

	if (i != ntokens)
		goto err_kfree;

	array_data = kmalloc(dp->max_state * sizeof(unsigned int), GFP_KERNEL);
	if (!array_data) {
		err = -ENOMEM;
		goto err_kfree;
	}

	for (i = dp->max_state - 1, j = 0; i >= 0; i--) {
		while(j < ntokens - 1 && dp->freq_table[i] >= tokenized_data[j + 1])
			j += 2;
		array_data[i] = tokenized_data[j];
	}
	kfree(tokenized_data);

	return array_data;

err_kfree:
	kfree(tokenized_data);
err:
	return ERR_PTR(err);
}

static uint64_t calc_utilization(struct devfreq *df)
{
	struct devfreq_dev_status *stat = &df->last_status;
	struct sgpu_governor_data *gdata = df->data;
	struct utilization_data *udata = stat->private_data;
	struct utilization_timeinfo *sw_info = &udata->timeinfo[SGPU_TIMEINFO_SW];
	unsigned long cu_busy_time = sw_info->cu_busy_time;

	udata->last_util = div64_u64(cu_busy_time *
				      (gdata->compute_weight - 100) +
				      sw_info->busy_time * 100LL,
				     sw_info->total_time);

	if (udata->last_util > 100)
		udata->last_util = 100;

	udata->last_cu_util = div64_u64(cu_busy_time * 100LL, sw_info->total_time);

	if (udata->last_util && udata->last_util == udata->last_cu_util)
		gdata->cl_boost_status = true;
	else
		gdata->cl_boost_status = false;

	return udata->last_util;
}

#define NORMALIZE_SHIFT (10)
#define NORMALIZE_FACT  (1<<(NORMALIZE_SHIFT))
#define NORMALIZE_FACT3 (1<<((NORMALIZE_SHIFT)*3))
#define ITERATION_MAX	(10)

static uint64_t cube_root(uint64_t value)
{
	uint32_t index, iter;
	uint64_t cube, cur, prev = 0;

	if (value == 0)
		return 0;

	index = fls64(value);
	index = (index - 1)/3 + 1;

	/* Implementation of Newton-Raphson method for approximating
	   the cube root */
	iter = ITERATION_MAX;

	cur = (1 << index);
	cube = cur*cur*cur;

	while (iter) {
		if ((cube-value == 0) || (prev == cur))
			return cur;
		prev = cur;
		cur = (value + 2*cube) / (3*cur*cur);
		cube = cur*cur*cur;
		iter--;
	}

	return prev;
}

static int sgpu_conservative_get_threshold(struct devfreq *df,
					   uint32_t *max, uint32_t *min)
{
	struct sgpu_governor_data *gdata = df->data;
	struct devfreq_dev_status *stat = &df->last_status;
	struct utilization_data *udata = stat->private_data;
	struct utilization_timeinfo *sw_info = &udata->timeinfo[SGPU_TIMEINFO_SW];

	uint64_t coefficient, ratio;
	uint32_t power_ratio;
	unsigned long sw_busy_time;
	uint32_t max_threshold, min_threshold;


	sw_busy_time = sw_info->busy_time;
	power_ratio  = gdata->power_ratio;
	max_threshold = *max;
	min_threshold = *min;

	if (sw_busy_time == 0)
		coefficient = 1;
	else
		coefficient = div64_u64(sw_busy_time * 100 * NORMALIZE_FACT3,
					sw_busy_time * 100);

	if (coefficient == 1)
		ratio = NORMALIZE_FACT;
	else
		ratio = cube_root(coefficient);

	if(ratio == 0)
		ratio = NORMALIZE_FACT;

	*max = div64_u64(max_threshold * NORMALIZE_FACT, ratio);
	*min = div64_u64(min_threshold * NORMALIZE_FACT, ratio);

	trace_sgpu_utilization_sw_source_data(sw_info, power_ratio, ratio,
							NORMALIZE_FACT);
	trace_sgpu_governor_conservative_threshold(*max, *min, max_threshold,
						   min_threshold);

	return 0;

}

static int sgpu_dvfs_governor_conservative_get_target(struct devfreq *df, uint32_t *level)
{
	struct sgpu_governor_data *data = df->data;
	struct devfreq_dev_status *stat = &df->last_status;
	struct utilization_data *udata = stat->private_data;
	uint32_t max_threshold = data->max_thresholds[*level];
	uint32_t min_threshold = data->min_thresholds[*level];
	uint64_t utilization = calc_utilization(df);

	if (df->previous_freq < data->highspeed_freq &&
	    utilization > data->highspeed_load) {
		if (time_after(jiffies, data->expire_highspeed_delay)) {
			*level = data->highspeed_level;
			return 0;
		}
	} else {
		data->expire_highspeed_delay = jiffies +
			msecs_to_jiffies(data->highspeed_delay);
	}

	if (udata->utilization_src->hw_source_valid) {
		sgpu_conservative_get_threshold(df, &max_threshold,
						&min_threshold);
	}

	if (utilization > max_threshold &&
	    *level > 0) {
		(*level)--;
	} else if (utilization < min_threshold) {
		if (time_after(jiffies, data->expire_jiffies) &&
		    *level < df->profile->max_state - 1 ) {
			(*level)++;
		}
	} else {
		data->expire_jiffies = jiffies +
			msecs_to_jiffies(data->downstay_times[*level]);
	}

	return 0;
}

static int sgpu_dvfs_governor_conservative_clear(struct devfreq *df, uint32_t level)
{
	struct sgpu_governor_data *data = df->data;

	data->expire_jiffies = jiffies +
		msecs_to_jiffies(data->downstay_times[level]);
	if (data->current_level == level ||
	    (data->current_level >= data->highspeed_level && level < data->highspeed_level))
		data->expire_highspeed_delay = jiffies +
			msecs_to_jiffies(data->highspeed_delay);

	return 0;
}


unsigned long sgpu_interactive_target_freq(struct devfreq *df,
					   uint64_t utilization,
					   uint32_t target_load)
{
	struct sgpu_governor_data *gdata = df->data;
	struct devfreq_dev_status *stat = &df->last_status;
	struct utilization_data *udata = stat->private_data;
	struct utilization_timeinfo *sw_info = &udata->timeinfo[SGPU_TIMEINFO_SW];

	unsigned long target_freq = 0;
	uint64_t coefficient, freq_ratio;
	uint32_t power_ratio, new_target_load;
	unsigned long sw_busy_time;


	sw_busy_time = sw_info->busy_time;

	power_ratio  = gdata->power_ratio;

	if (sw_busy_time == 0)
		coefficient = NORMALIZE_FACT3;
	else
		coefficient = div64_u64(sw_busy_time * 100 * NORMALIZE_FACT3,
					sw_busy_time * 100);

	freq_ratio = cube_root(coefficient);

	if(freq_ratio == 0)
		freq_ratio = NORMALIZE_FACT;

	target_freq = div64_u64(freq_ratio * utilization * df->previous_freq,
				target_load * NORMALIZE_FACT);

	new_target_load = div64_u64(target_load * NORMALIZE_FACT, freq_ratio);

	trace_sgpu_utilization_sw_source_data(sw_info, power_ratio,
					      freq_ratio, NORMALIZE_FACT);
	trace_sgpu_governor_interactive_freq(df, utilization, target_load,
					     target_freq, new_target_load);

	return target_freq;
}

static int sgpu_dvfs_governor_interactive_get_target(struct devfreq *df, uint32_t *level)
{
	struct sgpu_governor_data *data = df->data;
	struct devfreq_dev_status *stat = &df->last_status;
	struct utilization_data *udata = stat->private_data;
	unsigned long target_freq;
	uint32_t target_load;
	uint64_t utilization = calc_utilization(df);

	if (df->previous_freq < data->highspeed_freq &&
	    utilization > data->highspeed_load) {
		if (time_after(jiffies, data->expire_highspeed_delay)) {
			*level = data->highspeed_level;
			return 0;
		}
	} else {
		data->expire_highspeed_delay = jiffies +
			msecs_to_jiffies(data->highspeed_delay);
	}
	target_load = data->max_thresholds[*level];

	if (udata->utilization_src->hw_source_valid)
		target_freq = sgpu_interactive_target_freq(df, utilization,
							   target_load);
	else
		target_freq = div64_u64(utilization * df->previous_freq,
					target_load);

	if (target_freq > df->previous_freq) {
		while (df->profile->freq_table[*level] < target_freq && *level > 0)
			(*level)--;

		data->expire_jiffies = jiffies +
			msecs_to_jiffies(data->downstay_times[*level]);
	} else {
		while (df->profile->freq_table[*level] > target_freq &&
		       *level < df->profile->max_state - 1)
			(*level)++;
		if (df->profile->freq_table[*level] < target_freq)
			(*level)--;

		if (*level > data->current_level + 1) {
			target_load = data->max_thresholds[*level];
			if (div64_u64(utilization *
				      df->profile->freq_table[data->current_level],
				      df->profile->freq_table[*level]) > target_load) {
				(*level)--;
			}
		}

		if (*level == data->current_level) {
			data->expire_jiffies = jiffies +
				msecs_to_jiffies(data->downstay_times[*level]);
		} else if (time_before(jiffies, data->expire_jiffies)) {
			*level = data->current_level;
			return 0;
		}
	}


	return 0;
}

static int sgpu_dvfs_governor_interactive_clear(struct devfreq *df, uint32_t level)
{
	struct sgpu_governor_data *data = df->data;
	int target_load;
	uint64_t downstay_jiffies;

	target_load = data->max_thresholds[level];
	downstay_jiffies = msecs_to_jiffies(data->downstay_times[level]);

	if (level > data->current_level && df->profile->freq_table[level] != data->max_freq)
		data->expire_jiffies = jiffies +
			msecs_to_jiffies(data->valid_time);
	else
		data->expire_jiffies = jiffies + downstay_jiffies;
	if (data->current_level == level ||
	    (data->current_level >= data->highspeed_level && level < data->highspeed_level))
		data->expire_highspeed_delay = jiffies +
			msecs_to_jiffies(data->highspeed_delay);

	return 0;
}

static int sgpu_dvfs_governor_static_get_target(struct devfreq *df, uint32_t *level)
{
	static uint32_t updown = 0;
	struct sgpu_governor_data *data = df->data;

	if (!(updown & 0x1)) {
		if (df->profile->freq_table[*level] < data->max_freq && *level > 0)
			(*level)--;
	} else {
		if (df->profile->freq_table[*level] > data->min_freq &&
		    *level < df->profile->max_state - 1)
			(*level)++;
	}
	if (data->current_level == *level) {
		/* change up and down direction */
		if ((updown & 0x1)) {
			if (df->profile->freq_table[*level] < data->max_freq && *level > 0)
				(*level)--;
		} else {
			if (df->profile->freq_table[*level] > data->min_freq &&
			    *level < df->profile->max_state - 1)
				(*level)++;
		}
		if (data->current_level != *level) {
			/* increase direction change count */
			updown++;
		}
	}

	return 0;
}
#if IS_ENABLED(CONFIG_EXYNOS_GPU_PROFILER)
static uint32_t weight_table[WEIGHT_TABLE_MAX_SIZE][WINDOW_MAX_SIZE + 1] = {
	{  48,  44,  40,  36,  32,  28,  24,  20,  16,  12,   8,   4,  312},
	{ 100,  10,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,  111},
	{ 200,  40,   8,   2,   1,   0,   0,   0,   0,   0,   0,   0,  251},
	{ 300,  90,  27,   8,   2,   1,   0,   0,   0,   0,   0,   0,  428},
	{ 400, 160,  64,  26,  10,   4,   2,   1,   0,   0,   0,   0,  667},
	{ 500, 250, 125,  63,  31,  16,   8,   4,   2,   1,   0,   0, 1000},
	{ 600, 360, 216, 130,  78,  47,  28,  17,  10,   6,   4,   2, 1498},
	{ 700, 490, 343, 240, 168, 118,  82,  58,  40,  28,  20,  14, 2301},
	{ 800, 640, 512, 410, 328, 262, 210, 168, 134, 107,  86,  69, 3726},
	{ 900, 810, 729, 656, 590, 531, 478, 430, 387, 349, 314, 282, 6456},
	{  48,  44,  40,  36,  32,  28,  24,  20,  16,  12,   8,   4,  312}
};

uint64_t sgpu_weight_prediction_utilization(struct devfreq *df, uint64_t utilization)
{
	struct sgpu_governor_data *data = df->data;
	unsigned long cur_freq = df->profile->freq_table[data->current_level];
	unsigned long max_freq = df->profile->freq_table[0];
	uint64_t weight_util[WEIGHT_TABLE_IDX_NUM];
	uint64_t normalized_util, util_conv;
	uint32_t window_idx, table_row, table_col;
	uint32_t i, j;

	normalized_util = ((utilization * cur_freq) << NORMALIZE_SHIFT) / max_freq;

	window_idx = data->window_idx;
	data->window_idx = (window_idx + 1) % WINDOW_MAX_SIZE;
	data->window[window_idx] = normalized_util;

	for (i = 0; i < WEIGHT_TABLE_IDX_NUM; i++) {
		weight_util[i] = 0;
		table_row = data->weight_table_idx[i];
		table_col = WINDOW_MAX_SIZE - 1;

		for(j = window_idx+1; j <= window_idx + WINDOW_MAX_SIZE; j++){
			weight_util[i] += data->window[j%WINDOW_MAX_SIZE] *
					weight_table[table_row][table_col--];
		}
		weight_util[i] /= weight_table[table_row][WINDOW_MAX_SIZE];
	}

	for (i = 1; i < WEIGHT_TABLE_IDX_NUM; i++)
		weight_util[0] = max(weight_util[0], weight_util[i]);
	util_conv = weight_util[0] * max_freq / cur_freq;

	return util_conv;
}

static int sgpu_dvfs_governor_profiler_get_target(struct devfreq *df, uint32_t *level)
{
	unsigned long cur_freq = df->profile->freq_table[*level];
	unsigned long target_freq;
	uint64_t utilization = calc_utilization(df);
	uint64_t weight_util = sgpu_weight_prediction_utilization(df, utilization);
	uint64_t utilT = ((weight_util) * cur_freq / 100 ) >> NORMALIZE_SHIFT;
	long target_freq_signed;
#if (PROFILER_VERSION < 2)
	struct sgpu_governor_data *data = df->data;

	target_freq_signed = (long)utilT + ((long)utilT * (long)data->freq_margin / 1000);
#elif (PROFILER_VERSION == 2)
	target_freq_signed = profiler_pb_get_gpu_target(cur_freq, utilization, utilT);
#endif

	if (target_freq_signed < 0)
		target_freq = 0;
	else
		target_freq = target_freq_signed;

	if (target_freq > cur_freq) {
		while (df->profile->freq_table[*level] < target_freq && *level > 0)
			(*level)--;
	} else {
		while (df->profile->freq_table[*level] > target_freq &&
		      *level < df->profile->max_state - 1)
			(*level)++;
		if (df->profile->freq_table[*level] < target_freq)
			(*level)--;
	}
	profiler_pb_set_cur_freq(PROFILER_GPU, df->profile->freq_table[*level]);
	return 0;
}
#endif /* CONFIG_EXYNOS_GPU_PROFILER */

static struct sgpu_governor_info governor_info[SGPU_MAX_GOVERNOR_NUM] = {
	{
		SGPU_DVFS_GOVERNOR_STATIC,
		"static",
		sgpu_dvfs_governor_static_get_target,
		NULL,
	},
	{
		SGPU_DVFS_GOVERNOR_CONSERVATIVE,
		"conservative",
		sgpu_dvfs_governor_conservative_get_target,
		sgpu_dvfs_governor_conservative_clear,
	},
	{
		SGPU_DVFS_GOVERNOR_INTERACTIVE,
		"interactive",
		sgpu_dvfs_governor_interactive_get_target,
		sgpu_dvfs_governor_interactive_clear,
	},
#if IS_ENABLED(CONFIG_EXYNOS_GPU_PROFILER)
	{
		SGPU_DVFS_GOVERNOR_PROFILER,
		"profiler",
		sgpu_dvfs_governor_profiler_get_target,
		NULL,
	},
#endif /* CONFIG_EXYNOS_GPU_PROFILER */
};

static int devfreq_sgpu_func(struct devfreq *df, unsigned long *freq)
{
	int err = 0;
	struct sgpu_governor_data *data = df->data;
	struct utilization_data *udata = df->last_status.private_data;
	struct utilization_timeinfo *sw_info = &udata->timeinfo[SGPU_TIMEINFO_SW];
	struct device *dev= df->dev.parent;
	uint32_t level = data->current_level;
	struct dev_pm_opp *target_opp;
	int32_t qos_min_freq, qos_max_freq;

	qos_max_freq = dev_pm_qos_read_value(dev, DEV_PM_QOS_MAX_FREQUENCY);
	qos_min_freq = dev_pm_qos_read_value(dev, DEV_PM_QOS_MIN_FREQUENCY);

	data->max_freq = min(df->scaling_max_freq,
			     (unsigned long)HZ_PER_KHZ * qos_max_freq);

	target_opp = devfreq_recommended_opp(dev, &data->max_freq,
					     DEVFREQ_FLAG_LEAST_UPPER_BOUND);
	if (IS_ERR(target_opp)) {
		dev_err(dev, "max_freq: not found valid OPP table\n");
		return PTR_ERR(target_opp);
	}
	dev_pm_opp_put(target_opp);

	data->min_freq = max(df->scaling_min_freq,
			      (unsigned long)HZ_PER_KHZ * qos_min_freq);
	data->min_freq = min(data->max_freq, data->min_freq);

	/* in suspend or power_off*/
	if (atomic_read(&df->suspend_count) > 0) {
		df->resume_freq = max(data->min_freq,
				min(data->max_freq, df->resume_freq));
		*freq = 0;
		df->suspend_freq = 0;
		return 0;
	}

#if IS_ENABLED(CONFIG_EXYNOS_ESCA_DVFS_MANAGER)
	policy_update_call_to_DM(data->dm_type, data->min_freq, data->max_freq);
#endif

	err = df->profile->get_dev_status(df->dev.parent, &df->last_status);
	if (err)
		return err;

	if (sw_info->prev_total_time) {
#ifdef CONFIG_DRM_SGPU_EXYNOS
		gpu_dvfs_notify_utilization();
#endif
		data->governor->get_target(df, &level);
	}

	if (!data->cl_boost_disable && !data->mm_min_clock &&
	    data->cl_boost_status) {
		level = data->cl_boost_level;
		data->expire_jiffies = jiffies +
			msecs_to_jiffies(data->downstay_times[level]);
	}

	while (df->profile->freq_table[level] < data->min_freq && level > 0)
		level--;
	while (df->profile->freq_table[level] > data->max_freq &&
	       level < df->profile->max_state - 1)
		level++;

	*freq = df->profile->freq_table[level];

	return err;
}

static int sgpu_governor_notifier_call(struct notifier_block *nb,
				       unsigned long event, void *ptr)
{
	struct sgpu_governor_data *data = container_of(nb, struct sgpu_governor_data,
						       nb_trans);
	struct devfreq *df = data->devfreq;
	struct drm_device *ddev = adev_to_drm(data->adev);
	struct devfreq_freqs *freqs = (struct devfreq_freqs *)ptr;
	struct devfreq_dev_status *stat = &df->last_status;
	struct utilization_data *udata = stat->private_data;
	struct utilization_timeinfo *sw_info = &udata->timeinfo[SGPU_TIMEINFO_SW];

	/* in suspend or power_off*/
	if (ddev->switch_power_state == DRM_SWITCH_POWER_OFF ||
	    ddev->switch_power_state == DRM_SWITCH_POWER_DYNAMIC_OFF)
		return NOTIFY_DONE;

	if (freqs->old == freqs->new && !sw_info->prev_total_time)
		return NOTIFY_DONE;

	switch (event) {
	case DEVFREQ_PRECHANGE:
		sgpu_utilization_trace_before(&df->last_status, freqs->new);
		break;
	case DEVFREQ_POSTCHANGE:
		sgpu_utilization_trace_after(&df->last_status, freqs->new);
		if (data->governor->clear && freqs->old != freqs->new)
			data->governor->clear(df, data->current_level);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int devfreq_sgpu_handler(struct devfreq *df, unsigned int event, void *data)
{
	struct sgpu_governor_data *governor_data = df->data;
	int ret = 0;

	mutex_lock(&governor_data->lock);

	switch (event) {
	case DEVFREQ_GOV_START:
		ret = sgpu_utilization_init(governor_data->adev, df);
		if (ret)
			goto out;

		governor_data->nb_trans.notifier_call = sgpu_governor_notifier_call;
		devm_devfreq_register_notifier(df->dev.parent, df, &governor_data->nb_trans,
					       DEVFREQ_TRANSITION_NOTIFIER);
		sgpu_utilization_trace_start(&df->last_status);
		if (governor_data->governor->clear)
			governor_data->governor->clear(df, governor_data->current_level);
#ifdef CONFIG_DRM_SGPU_EXYNOS
		gpu_dvfs_update_time_in_state(0);
#endif /* CONFIG_DRM_SGPU_EXYNOS */
		devfreq_monitor_start(df);
		break;
	case DEVFREQ_GOV_STOP:
		devfreq_monitor_stop(df);
		devm_devfreq_unregister_notifier(df->dev.parent, df, &governor_data->nb_trans,
						 DEVFREQ_TRANSITION_NOTIFIER);
		sgpu_utilization_deinit(df);
		break;
	case DEVFREQ_GOV_UPDATE_INTERVAL:
		devfreq_update_interval(df, (unsigned int*)data);
		break;
	case DEVFREQ_GOV_SUSPEND:
		devfreq_monitor_suspend(df);
		if (governor_data->wakeup_lock)
			df->resume_freq = df->previous_freq;
		else
			df->resume_freq = 0;
		sgpu_utilization_trace_stop(&df->last_status);
		governor_data->in_suspend = true;
		governor_data->cl_boost_status = false;
#ifdef CONFIG_DRM_SGPU_EXYNOS
		gpu_dvfs_update_time_in_state(df->previous_freq);
		df->previous_freq = 0;
#endif /* CONFIG_DRM_SGPU_EXYNOS */
		break;
	case DEVFREQ_GOV_RESUME:
		governor_data->in_suspend = false;
		if (df->suspend_freq == 0)
			df->suspend_freq = df->profile->initial_freq;
		sgpu_utilization_trace_start(&df->last_status);
		if (governor_data->governor->clear)
			governor_data->governor->clear(df, governor_data->current_level);
		devfreq_monitor_resume(df);
#ifdef CONFIG_DRM_SGPU_EXYNOS
		gpu_dvfs_update_time_in_state(0);
#endif /* CONFIG_DRM_SGPU_EXYNOS */
		break;
	default:
		break;
	}

out:
	mutex_unlock(&governor_data->lock);
	return ret;
}

static struct devfreq_governor devfreq_governor_sgpu = {
	.name = "sgpu_governor",
	.get_target_freq = devfreq_sgpu_func,
	.event_handler = devfreq_sgpu_handler,
	.flags = DEVFREQ_GOV_FLAG_IMMUTABLE,
};

ssize_t sgpu_governor_all_info_show(struct devfreq *df, char *buf)
{
	int i;
	ssize_t count = 0;
	if (!df->governor || !df->data)
		return -EINVAL;

	for (i = 0; i < SGPU_MAX_GOVERNOR_NUM; i++) {
		struct sgpu_governor_info *governor = &governor_info[i];
		count += scnprintf(&buf[count], (PAGE_SIZE - count - 2),
				   "%s ", governor->name);
	}
	/* Truncate the trailing space */
	if (count)
		count--;

	count += sprintf(&buf[count], "\n");

	return count;
}

ssize_t sgpu_governor_current_info_show(struct devfreq *df, char *buf,
					size_t size)
{
	struct sgpu_governor_data *data = df->data;

	return scnprintf(buf, size, "%s", data->governor->name);
}

int sgpu_governor_change(struct devfreq *df, char *str_governor)
{
	int i;
	struct sgpu_governor_data *data = df->data;

	for (i = 0; i < SGPU_MAX_GOVERNOR_NUM; i++) {
		if (!strncmp(governor_info[i].name, str_governor, DEVFREQ_NAME_LEN)) {
			mutex_lock(&data->lock);
			if (!data->in_suspend)
				devfreq_monitor_stop(df);
			data->governor = &governor_info[i];
			if (!data->in_suspend)
				devfreq_monitor_start(df);
			mutex_unlock(&data->lock);
			return 0;
		}
	}

	return -ENODEV;
}

#define DVFS_TABLE_ROW_MAX			1
#define DEFAULT_GOVERNOR			SGPU_DVFS_GOVERNOR_CONSERVATIVE
#define DEFAULT_INITIAL_FREQ			26000
#define DEFAULT_HIGHSPEED_FREQ			500000
#define DEFAULT_HIGHSPEED_LOAD			99
#define DEFAULT_HIGHSPEED_DELAY			0
#define DEFAULT_POWER_RATIO			50
#define DEFAULT_CL_BOOST_FREQ			999000
#define DEFAULT_COMPUTE_WEIGHT			100
#define DEFAULT_IFPO_DISABLE_FREQ		800000

static void sgpu_governor_dt_preparse(struct device *dev,
				      struct devfreq_dev_profile *dp,
				      struct sgpu_governor_data *data)
{
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);
	uint32_t value;

	if (!of_property_read_u32(dev->of_node, "highspeed_freq", &value))
		data->highspeed_freq = (unsigned long)value;
	else
		data->highspeed_freq = DEFAULT_HIGHSPEED_FREQ;

	if (!of_property_read_u32(dev->of_node, "ifpo_disable_freq", &value))
		adev->ifpo_disable_freq = (unsigned long)value;
	else
		adev->ifpo_disable_freq = DEFAULT_IFPO_DISABLE_FREQ;

	if (of_property_read_u32(dev->of_node, "highspeed_load",
				 &data->highspeed_load))
		data->highspeed_load = DEFAULT_HIGHSPEED_LOAD;

	if (of_property_read_u32(dev->of_node, "highspeed_delay",
				 &data->highspeed_delay))
		data->highspeed_delay = DEFAULT_HIGHSPEED_DELAY;

	if (!of_property_read_u32(dev->of_node, "cl_boost_freq", &value))
		data->cl_boost_freq = value;
	else
		data->cl_boost_freq = DEFAULT_CL_BOOST_FREQ;

	if (of_property_read_u32(dev->of_node, "compute_weight",
				   &data->compute_weight))
		data->compute_weight = DEFAULT_COMPUTE_WEIGHT;
}

/* These need to be parsed after dvfs table set */
static int sgpu_governor_dt_postparse(struct device *dev,
				      struct devfreq_dev_profile *dp,
				      struct sgpu_governor_data *data)
{
	const char *tmp_str;
	int ret = 0;

	if (of_property_read_string(dev->of_node, "min_threshold", &tmp_str))
		tmp_str = "60";
	data->min_thresholds = sgpu_get_array_data(dp, tmp_str);
	if (IS_ERR(data->min_thresholds)) {
		ret = PTR_ERR(data->min_thresholds);
		dev_err(dev, "fail minimum threshold tokenized %d\n", ret);
		goto err_min_threshold;
	}

	if (of_property_read_string(dev->of_node, "max_threshold", &tmp_str))
		tmp_str = "75";
	data->max_thresholds = sgpu_get_array_data(dp, tmp_str);
	if (IS_ERR(data->max_thresholds)) {
		ret = PTR_ERR(data->max_thresholds);
		dev_err(dev, "fail maximum threshold tokenized %d\n", ret);
		goto err_max_threshold;
	}

	if (of_property_read_string(dev->of_node, "downstay_time", &tmp_str))
		tmp_str = "32";
	data->downstay_times = sgpu_get_array_data(dp, tmp_str);
	if (IS_ERR(data->downstay_times)) {
		ret = PTR_ERR(data->downstay_times);
		dev_err(dev, "fail down stay time tokenized %d\n", ret);
		goto err_downstay_time;
	}

	return ret;

err_downstay_time:
	kfree(data->max_thresholds);
err_max_threshold:
	kfree(data->min_thresholds);
err_min_threshold:
	return ret;
}

int sgpu_governor_init(struct device *dev, struct devfreq_dev_profile *dp,
		       struct sgpu_governor_data **governor_data)
{
	struct sgpu_governor_data *data;
	int ret = 0, i, j;
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);
#ifdef CONFIG_DRM_SGPU_EXYNOS
	uint32_t dt_freq;
	unsigned long max_freq, min_freq;
	struct freq_volt *g3d_rate_volt = NULL;
	uint32_t *freq_table;
	int freq_table_size;
	unsigned long cal_maxfreq, cal_minfreq, boot_freq;
#endif /* CONFIG_DRM_SGPU_EXYNOS*/

	dp->initial_freq = DEFAULT_INITIAL_FREQ;
	dp->polling_ms = sgpu_devfreq_polling_ms;
	dp->max_state = DVFS_TABLE_ROW_MAX;
	data = kzalloc(sizeof(struct sgpu_governor_data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto err;
	}
	*governor_data = data;

	sgpu_governor_dt_preparse(dev, dp, data);
	data->governor = &governor_info[DEFAULT_GOVERNOR];
	data->wakeup_lock = true;
	data->valid_time = sgpu_devfreq_polling_ms;
	data->in_suspend = false;
	data->adev = adev;
	data->power_ratio = DEFAULT_POWER_RATIO;
#if IS_ENABLED(CONFIG_EXYNOS_GPU_PROFILER)
	data->freq_margin = 10;
	data->window_idx = 0;
	for (i = 0; i < WINDOW_MAX_SIZE; i++)
		data->window[i] = 0;
	for (i = 0; i < WEIGHT_TABLE_IDX_NUM; i++)
		data->weight_table_idx[i] = 0;
#endif /* CONFIG_EXYNOS_GPU_PROFILER */
	data->cl_boost_disable = false;
	data->cl_boost_status = false;
	data->cl_boost_level = 0;
	data->mm_min_clock = 0;

	mutex_init(&data->lock);

#ifdef CONFIG_DRM_SGPU_EXYNOS
	freq_table_size = of_property_count_u32_elems(dev->of_node,
						      "freq_table");
	if (freq_table_size < 0) {
		dev_err(dev, "Cannot find freq-table node in DT\n");
		ret = freq_table_size;
		goto err_kfree0;
	}

	freq_table = kcalloc(freq_table_size, sizeof(uint32_t), GFP_KERNEL);
	if (!freq_table) {
		ret = -ENOMEM;
		goto err_kfree0;
	}

	ret = of_property_read_u32_array(dev->of_node, "freq_table",
					 freq_table, freq_table_size);
	if (ret) {
		dev_err(dev, "Cannot read the freq-table node in DT\n");
		goto err_kfree1;
	}
	dp->max_state = freq_table_size;

	g3d_rate_volt = kcalloc(freq_table_size, sizeof(struct freq_volt),
				GFP_KERNEL);
	if (!g3d_rate_volt) {
		ret = -ENOMEM;
		goto err_kfree1;
	}

#if IS_ENABLED(CONFIG_CAL_IF)
	dp->initial_freq = cal_dfs_get_boot_freq(adev->cal_id);
	cal_maxfreq = cal_dfs_get_max_freq(adev->cal_id);
	cal_minfreq = cal_dfs_get_min_freq(adev->cal_id);
#else
	dp->initial_freq = cal_maxfreq = cal_minfreq = 303000;
#endif /* CONFIG_CAL_IF */
	boot_freq = dp->initial_freq;

	ret = of_property_read_u32(dev->of_node, "max_freq", &dt_freq);
	if (!ret) {
		max_freq = (unsigned long)dt_freq;
		max_freq = min(max_freq, cal_maxfreq);
	} else {
		max_freq = cal_maxfreq;
	}

	ret = of_property_read_u32(dev->of_node, "min_freq", &dt_freq);
	if (!ret) {
		min_freq = (unsigned long)dt_freq;
		min_freq = max(min_freq, cal_minfreq);
	} else {
		min_freq = cal_minfreq;
	}

	min_freq = min(max_freq, min_freq);

	for (i = freq_table_size - 1, j = 0; i >= 0; i--) {
		if (freq_table[i] > max_freq || freq_table[i] < min_freq)
			continue;

		g3d_rate_volt[j++].rate = freq_table[i];
	}
	dp->max_state = j;

#if IS_ENABLED(CONFIG_CAL_IF)
	cal_dfs_get_freq_volt_table(adev->cal_id, g3d_rate_volt,
				    dp->max_state);
#endif /* CONFIG_CAL_IF */

	adev->gpu_dss_freq_id = 0;
#if IS_ENABLED(CONFIG_DEBUG_SNAPSHOT)
	adev->gpu_dss_freq_id = dbg_snapshot_get_freq_idx("G3D");
#endif

#endif /* CONFIG_DRM_SGPU_EXYNOS */

	dp->freq_table = kcalloc(dp->max_state, sizeof(*(dp->freq_table)),
				 GFP_KERNEL);
	if (!dp->freq_table) {
		ret = -ENOMEM;
		goto err_kfree2;
	}

	for (i = 0; i < dp->max_state; i++) {
		uint32_t freq, volt;

#ifdef CONFIG_DRM_SGPU_EXYNOS
		freq =  g3d_rate_volt[i].rate;
		volt =  g3d_rate_volt[i].volt;
#else
		freq = dp->initial_freq;
		volt = 0;
#endif

		dp->freq_table[i] = freq;
		if (freq >= dp->initial_freq) {
			data->current_level = i;
		}

		if (freq >= data->highspeed_freq) {
			data->highspeed_level = i;
		}

		if (freq >= data->cl_boost_freq)
			data->cl_boost_level = i;

		ret = dev_pm_opp_add(dev, freq, volt);
		if (ret) {
			dev_err(dev, "failed to add opp entries\n");
			goto err_kfree3;
		}
	}
	dp->initial_freq = dp->freq_table[data->current_level];

#ifdef CONFIG_DRM_SGPU_EXYNOS
	gpu_dvfs_init_table(g3d_rate_volt, dp->freq_table, i);
	gpu_dvfs_init_utilization_notifier_list();

#if IS_ENABLED(CONFIG_EXYNOS_ESCA_DVFS_MANAGER)
	/* Initialize DVFS Manager */
	ret = of_property_read_u32(dev->of_node, "dm_type",
				   &data->dm_type);
	exynos_dm_data_init(data->dm_type, data,
			min_freq, max_freq, dp->initial_freq);

	register_exynos_dm_freq_scaler(data->dm_type,
			sgpu_dm_freq_scaler);
#endif /* CONFIG_EXYNOS_ESCA_DVFS_MANAGER */

#if IS_ENABLED(CONFIG_DEBUG_SNAPSHOT)
	if (adev->gpu_dss_freq_id)
		dbg_snapshot_freq(adev->gpu_dss_freq_id, boot_freq, dp->initial_freq, DSS_FLAG_IN);
#endif /* CONFIG_DEBUG_SNAPSHOT */
#if IS_ENABLED(CONFIG_EXYNOS_ESCA_DVFS_MANAGER)
	DM_CALL(data->dm_type, &dp->initial_freq);
	data->old_freq = dp->initial_freq;
#elif IS_ENABLED(CONFIG_CAL_IF)
	cal_dfs_set_rate(adev->cal_id, dp->initial_freq);
#endif
#if IS_ENABLED(CONFIG_DEBUG_SNAPSHOT)
	if (adev->gpu_dss_freq_id)
		dbg_snapshot_freq(adev->gpu_dss_freq_id, boot_freq, dp->initial_freq, DSS_FLAG_OUT);
#endif /* CONFIG_DEBUG_SNAPSHOT */

	/* BG3D_DVFS_CTL 0x058 enable */
	writel(0x1, adev->pm.pmu_mmio + 0x58);
#endif

	ret = sgpu_governor_dt_postparse(dev, dp, data);
	if (ret) {
		dev_err(dev, "failed to dt tokenized %d\n", ret);
		goto err_kfree3;
	}

	ret = devfreq_add_governor(&devfreq_governor_sgpu);
	if (ret) {
		dev_err(dev, "failed to add governor %d\n", ret);
		goto err_kfree3;
	}

#ifdef CONFIG_DRM_SGPU_EXYNOS
	kfree(freq_table);
	kfree(g3d_rate_volt);
#endif

	return ret;

err_kfree3:
	kfree(dp->freq_table);
err_kfree2:
#ifdef CONFIG_DRM_SGPU_EXYNOS
	kfree(g3d_rate_volt);
#endif
err_kfree1:
#ifdef CONFIG_DRM_SGPU_EXYNOS
	kfree(freq_table);
#endif
err_kfree0:
	kfree(data);
err:
	return ret;
}

void sgpu_governor_deinit(struct devfreq *df)
{
	int ret = 0;
	struct sgpu_governor_data *data = df->data;

	mutex_destroy(&data->lock);
	kfree(df->profile->freq_table);
	kfree(df->data);
	ret = devfreq_remove_governor(&devfreq_governor_sgpu);
	if (ret)
		pr_err("%s: failed remove governor %d\n", __func__, ret);
}
