// SPDX-License-Identifier: GPL-2.0-only
/* exynos_drm_connector.c
 *
 * Copyright (c) 2021 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>

#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_connector.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_property.h>
#include <drm/drm_print.h>

#include <exynos_drm_drv.h>
#include <exynos_drm_connector.h>

static const struct drm_prop_enum_list props[] = {
	{ __builtin_ffs(HDR_DOLBY_VISION) - 1,	"Dolby Vision"	},
	{ __builtin_ffs(HDR_HDR10) - 1,		"HDR10"		},
	{ __builtin_ffs(HDR_HLG) - 1,		"HLG"		},
	{ __builtin_ffs(HDR_HDR10_PLUS) - 1,	"HDR10_PLUS"	},
};

void exynos_drm_boost_bts_fps(struct exynos_drm_connector *exynos_connector,
		u32 fps, ktime_t expire_time)
{
	exynos_connector->boost_bts_fps = fps;
	exynos_connector->boost_expire_time = expire_time;
}
EXPORT_SYMBOL(exynos_drm_boost_bts_fps);

enum drm_connector_status
exynos_drm_connector_detect(struct drm_connector *connector, bool force)
{
	struct exynos_drm_connector *exynos_conn = to_exynos_connector(connector);
	const struct exynos_drm_connector_funcs *funcs = exynos_conn->funcs;

	if (funcs && funcs->detect)
		return funcs->detect(exynos_conn, force);

	return connector_status_connected;
}

static void exynos_drm_connector_destroy(struct drm_connector *connector)
{
	struct exynos_drm_connector *exynos_conn = to_exynos_connector(connector);
	const struct exynos_drm_connector_funcs *funcs = exynos_conn->funcs;

	if (funcs && funcs->destroy)
		funcs->destroy(exynos_conn);
}

static struct drm_connector_state *
exynos_drm_connector_duplicate_state(struct drm_connector *connector)
{
	struct exynos_drm_connector_state *exynos_connector_state, *copy;

	if (WARN_ON(!connector->state))
		return NULL;

	exynos_connector_state = to_exynos_connector_state(connector->state);
	copy = kzalloc(sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return NULL;

	memcpy(copy, exynos_connector_state, sizeof(*copy));
	copy->seamless_modeset = 0;
	copy->bypass_panel = false;

	__drm_atomic_helper_connector_duplicate_state(connector, &copy->base);

	return &copy->base;
}

static void exynos_drm_connector_destroy_state(struct drm_connector *connector,
		struct drm_connector_state *connector_state)
{
	struct exynos_drm_connector_state *exynos_connector_state;

	exynos_connector_state = to_exynos_connector_state(connector_state);
	/* if need, put ref of blob property */
	__drm_atomic_helper_connector_destroy_state(connector_state);
	kfree(exynos_connector_state);
}

static void exynos_drm_connector_reset(struct drm_connector *connector)
{
	struct exynos_drm_connector_state *exynos_connector_state;

	if (connector->state) {
		exynos_drm_connector_destroy_state(connector, connector->state);
		connector->state = NULL;
	}

	exynos_connector_state =
			kzalloc(sizeof(*exynos_connector_state), GFP_KERNEL);
	if (exynos_connector_state) {
		connector->state = &exynos_connector_state->base;
		connector->state->connector = connector;
		connector->state->self_refresh_aware = true;
	} else {
		pr_err("failed to allocate exynos connector state\n");
	}
}

static int exynos_drm_connector_get_property(struct drm_connector *connector,
		const struct drm_connector_state *conn_state,
		struct drm_property *property, uint64_t *val)
{
	struct exynos_drm_connector *exynos_conn =
		to_exynos_connector(conn_state->connector);
	const struct exynos_drm_connector_state *exynos_conn_state =
		to_exynos_connector_state(conn_state);
	const struct exynos_drm_connector_funcs *funcs = exynos_conn->funcs;

	if (funcs && funcs->atomic_get_property)
		return funcs->atomic_get_property(exynos_conn, exynos_conn_state,
				property, val);

	return -EINVAL;
}

static int exynos_drm_connector_set_property(struct drm_connector *connector,
		struct drm_connector_state *conn_state,
		struct drm_property *property, uint64_t val)
{
	struct exynos_drm_connector *exynos_conn =
		to_exynos_connector(conn_state->connector);
	struct exynos_drm_connector_state *exynos_conn_state =
		to_exynos_connector_state(conn_state);
	const struct exynos_drm_connector_funcs *funcs = exynos_conn->funcs;

	if (funcs && funcs->atomic_set_property)
		return funcs->atomic_set_property(exynos_conn, exynos_conn_state,
				property, val);

	return -EINVAL;
}

static void exynos_drm_connector_print_state(struct drm_printer *p,
		const struct drm_connector_state *state)
{
	struct exynos_drm_connector *exynos_conn =
		to_exynos_connector(state->connector);
	const struct exynos_drm_connector_state *exynos_conn_state =
		to_exynos_connector_state(state);
	const struct exynos_drm_connector_funcs *funcs = exynos_conn->funcs;

	drm_printf(p, "\tdisplay_info:\n");
	drm_printf(p, "\t\twidth_mm: %d\n", exynos_conn->base.display_info.width_mm);
	drm_printf(p, "\t\theight_mm: %d\n", exynos_conn->base.display_info.height_mm);
	drm_printf(p, "\t\tbpc: %d\n", exynos_conn->base.display_info.bpc);

	if (funcs && funcs->atomic_print_state)
		funcs->atomic_print_state(p, exynos_conn_state);
}

static const struct drm_connector_funcs exynos_connector_funcs = {
	.detect = exynos_drm_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.reset = exynos_drm_connector_reset,
	.destroy = exynos_drm_connector_destroy,
	.atomic_duplicate_state = exynos_drm_connector_duplicate_state,
	.atomic_destroy_state = exynos_drm_connector_destroy_state,
	.atomic_get_property = exynos_drm_connector_get_property,
	.atomic_set_property = exynos_drm_connector_set_property,
	.atomic_print_state = exynos_drm_connector_print_state,
};

bool is_exynos_drm_connector(const struct drm_connector *connector)
{
	return connector->funcs == &exynos_connector_funcs;
}

int exynos_drm_connector_init(struct drm_device *dev,
		struct exynos_drm_connector *exynos_connector,
		const struct exynos_drm_connector_funcs *funcs,
		int connector_type)
{
	exynos_connector->funcs = funcs;

	return drm_connector_init(dev, &exynos_connector->base,
			&exynos_connector_funcs,
			connector_type);
}
EXPORT_SYMBOL(exynos_drm_connector_init);

int exynos_drm_connector_create_properties(struct drm_device *dev)
{
	struct exynos_drm_properties *p;

	p = dev_get_exynos_props(dev);
	if (!p)
		return -EINVAL;

#if IS_ENABLED(CONFIG_USDM_PANEL_MASK_LAYER)
	p->fingerprint_mask = drm_property_create_range(dev, 0, "fingerprint_mask", 0, 1);
	if (!p->fingerprint_mask)
		return -ENOMEM;
#endif

	p->max_luminance = drm_property_create_range(dev, 0, "max_luminance",
			0, UINT_MAX);
	if (!p->max_luminance)
		return -ENOMEM;

	p->max_avg_luminance = drm_property_create_range(dev, 0, "max_avg_luminance",
			0, UINT_MAX);
	if (!p->max_avg_luminance)
		return -ENOMEM;

	p->min_luminance = drm_property_create_range(dev, 0, "min_luminance",
			0, UINT_MAX);
	if (!p->min_luminance)
		return -ENOMEM;

	p->hdr_formats = drm_property_create_bitmask(dev, 0, "hdr_formats",
			props, ARRAY_SIZE(props),
			HDR_DOLBY_VISION | HDR_HDR10 | HDR_HLG | HDR_HDR10_PLUS);
	if (!p->hdr_formats)
		return -ENOMEM;

	p->adjusted_fps = drm_property_create_range(dev, 0, "adjusted_fps", 0, UINT_MAX);
	if (!p->adjusted_fps)
		return -ENOMEM;

	p->lp_mode = drm_property_create(dev, DRM_MODE_PROP_IMMUTABLE |
			DRM_MODE_PROP_BLOB, "lp_mode", 0);
	if (!p->lp_mode)
		return -ENOMEM;

	p->hdr_sink_connected = drm_property_create_bool(dev, 0, "hdr_sink_connected");
	if (!p->hdr_sink_connected)
		return -ENOMEM;

	p->use_repeater_buffer = drm_property_create_bool(dev, 0,
			"WRITEBACK_USE_REPEATER_BUFFER");
	if (!p->use_repeater_buffer)
		return -ENOMEM;

	p->idle_supported = drm_property_create_bool(dev, DRM_MODE_PROP_IMMUTABLE,
			"idle_supported");
	if (!p->idle_supported)
		return -ENOMEM;

	p->dual_blender = drm_property_create_bool(dev, 0, "dual_blender");
	if (!p->dual_blender)
		return -ENOMEM;

	p->backlight_level = drm_property_create_range(dev, 0, "backlight_level",
			0, UINT_MAX);
	if (!p->backlight_level)
		return -ENOMEM;

	return 0;
}
