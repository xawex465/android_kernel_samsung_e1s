/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2020 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Headef file for Display Quality Enhancer.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __EXYNOS_DRM_DQE_H__
#define __EXYNOS_DRM_DQE_H__

#include <linux/spinlock.h>
#include <samsung_drm.h>
#include <dqe_cal.h>

struct exynos_dqe;

struct exynos_dqe_funcs {
	void (*dump)(struct exynos_dqe *dqe);
	void (*prepare)(struct exynos_dqe *dqe, struct drm_crtc_state *crtc_state);
	void (*update)(struct exynos_dqe *dqe, struct drm_crtc_state *crtc_state);
	void (*enable)(struct exynos_dqe *dqe);
	void (*disable)(struct exynos_dqe *dqe);
	void (*suspend)(struct exynos_dqe *dqe);
	void (*resume)(struct exynos_dqe *dqe);
	void (*state)(struct exynos_dqe *dqe, enum dqe_reg_type type, bool *enabled);
};

// currently used LUT regs which attached to the each dqe handle
struct dqe_ctx_reg {
	u32 version;
	u32 disp_dither;
	u32 disp_dither_on; // 0:off, 1:on, 2:auto
	u32 cgc_dither;
	u32 cgc_dither_on;
	u32 *gamma_matrix;
	u32 gamma_matrix_on;
	u32 *degamma_lut;
	u32 degamma_on;
	u32 *regamma_lut;
	u32 regamma_on;
	u32 *cgc_con;
	u16 (*cgc_lut)[3];
	dma_addr_t cgc_dma;
	u32 cgc_on;
	u32 *hsc_con;
	u32 *hsc_poly;
	u32 *hsc_gain;
	u32 hsc_on;
	u32 *atc;
	u32 atc_lux;
	u32 atc_on;
	u32 atc_dim_off;
	u32 *scl;
	u32 scl_on;
	u32 *de;
	u32 de_on;
	u32 *lpd;
	u32 *rcd;
	u32 rcd_on;
	u32 *linear_matrix;
	u32 linear_matrix_on;
};

struct dqe_config {
	u32 width;
	u32 height;
	u32 in_bpc;	// in bpc at dqe
	u32 cur_bpc;	// actual bpc
	u32 out_bpc;	// out bpc from dqe
	u32 rcd_en;
};

struct dqe_colormode_crc {
	u32 key;
	u16 value;
};

#define MAX_DQE_COLORMODE_CTX 3 // 3 ctx buffer per frame

struct dqe_colormode_cfg {
	u8 seq_num;
	int64_t dqe_fd;
	struct dma_buf	*dma_buf;
	void *vaddr;
	struct dqe_colormode_crc *crc;
	char *ctx[MAX_DQE_COLORMODE_CTX];
	int ctx_size;
	atomic_t ctx_no;
};

enum dqe_state {
	DQE_STATE_DISABLE = 0,
	DQE_STATE_ENABLE,
};

#define DQE_XML_SUFFIX_SIZE	128

struct exynos_dqe {
	u32 id;
	struct device *dev;
	struct decon_device *decon;

	struct dqe_regs	regs;
	struct dqe_config cfg;
	struct dqe_ctx_reg ctx;
	enum dqe_state state;
	struct dqe_colormode_cfg colormode;
	u32 num_lut;
	void *lut;
	u32 mode_idx;
	bool sram_retention;
	char xml_suffix[DQE_XML_SUFFIX_SIZE];

	int	irq_edma;	/* EDMA irq number*/
	spinlock_t	slock;
	struct mutex lock;
	atomic_t update_cnt;
	atomic_t cgc_update_cnt;

	const struct exynos_dqe_funcs *funcs;
	bool initialized;
};

#if IS_ENABLED(CONFIG_DRM_SAMSUNG_DQE)
void exynos_dqe_dump(struct exynos_dqe *dqe);
void exynos_dqe_prepare(struct exynos_dqe *dqe,
			struct drm_crtc_state *crtc_state);
void exynos_dqe_update(struct exynos_dqe *dqe,
			struct drm_crtc_state *crtc_state);
void exynos_dqe_enable(struct exynos_dqe *dqe);
void exynos_dqe_disable(struct exynos_dqe *dqe);
void exynos_dqe_suspend(struct exynos_dqe *dqe);
void exynos_dqe_resume(struct exynos_dqe *dqe);
void exynos_dqe_state(struct exynos_dqe *dqe,
			enum dqe_reg_type type,	bool *enabled);
struct exynos_dqe *exynos_dqe_register(struct decon_device *decon);
#else
static inline void exynos_dqe_dump(struct exynos_dqe *dqe) {}
static inline void exynos_dqe_prepare(struct exynos_dqe *dqe, struct drm_crtc_state *crtc_state) {}
static inline void exynos_dqe_update(struct exynos_dqe *dqe, struct drm_crtc_state *crtc_state) {}
static inline void exynos_dqe_enable(struct exynos_dqe *dqe) {}
static inline void exynos_dqe_disable(struct exynos_dqe *dqe) {}
static inline void exynos_dqe_suspend(struct exynos_dqe *dqe) {}
static inline void exynos_dqe_resume(struct exynos_dqe *dqe) {}
static inline void exynos_dqe_state(struct exynos_dqe *dqe,
			enum dqe_reg_type type,	bool *enabled) { *enabled = false; }
static inline struct exynos_dqe *exynos_dqe_register(struct decon_device *decon) { return NULL; }
#endif
#endif /* __EXYNOS_DRM_DQE_H__ */
