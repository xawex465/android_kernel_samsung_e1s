/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2020 GOODIX, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef TFA_SERVICE_H
#define TFA_SERVICE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#ifdef __cplusplus
extern "C" {
#include "TFA_I2C.h"
#endif
#include "tfa_device.h"

/* Linux kernel module defines TFA98XX_GIT_VERSIONS
 * in the linux_driver/Makefile
 */
#define TFA98XX_GIT_VERSIONS "v6.12.1+-Feb.14,2024"

#if !defined(TFA98XX_GIT_VERSIONS)
#include "versions.h"
#endif
#ifdef TFA98XX_GIT_VERSIONS
	#define TFA98XX_API_REV_STR TFA98XX_GIT_VERSIONS
#else
	/* #warning update TFA98XX_API_REV_STR manually */
	#define TFA98XX_API_REV_STR "v6.12.1+-Feb.14,2024"
#endif

#define MEMTRACK_MAX_WORDS           250
#define FW_VAR_API_VERSION          (521)

/* Maximum number of retries for DSP result
 * Keep this value low!
 * If certain calls require longer wait conditions, the
 * application should poll, not the API
 * The total wait time depends on device settings. Those
 * are application specific.
 */
#define TFA98XX_LOADFW_NTRIES			800
#define TFA98XX_WAITRESULT_NTRIES		40
#define TFA98XX_WAITRESULT_NTRIES_LONG	2000
#define TFA98XX_WAITPOWERUP_NTRIES		100

/* following lengths are in bytes */
#define TFA98XX_PRESET_LENGTH			87
#define TFA98XX_CONFIG_LENGTH			201
#define TFA98XX_DRC_LENGTH              381	/* 127 words */

#define TFA_TDMSPKG_IN_BYPASS	14

/* not used in current driver */
/*
 * typedef unsigned char tfa98xx_config_t[TFA98XX_CONFIG_LENGTH];
 * typedef unsigned char tfa98xx_preset_t[TFA98XX_PRESET_LENGTH];
 * typedef unsigned char tfa98xx_drc_parameters_t[TFA98XX_DRC_LENGTH];
 */
/*
 * Type containing all the possible errors that can occur
 */
enum tfa98xx_error {
	TFA_ERROR = -1,
	TFA98XX_ERROR_OK = 0,
	TFA98XX_ERROR_DEVICE,			/* 1. in sync with tfa_error */
	TFA98XX_ERROR_BAD_PARAMETER,	/* 2. */
	TFA98XX_ERROR_FAIL,				/* 3. generic failure */
	TFA98XX_ERROR_NO_CLOCK,			/* 4. no clock detected */
	TFA98XX_ERROR_STATE_TIMED_OUT,	/* 5. */
	TFA98XX_ERROR_DSP_NOT_RUNNING,	/* 6. communication with DSP failed */
	TFA98XX_ERROR_AMPON,			/* 7. amp is still running */
	TFA98XX_ERROR_NOT_OPEN,			/* 8. handle is not open */
	TFA98XX_ERROR_IN_USE,			/* 9. too many handles */
	TFA98XX_ERROR_BUFFER_TOO_SMALL,	/* 10. if a buffer is too small */
	/* the expected response did not occur within the expected time */
	TFA98XX_ERROR_BUFFER_RPC_BASE = 100,
	TFA98XX_ERROR_RPC_BUSY = 101,
	TFA98XX_ERROR_RPC_MOD_ID = 102,
	TFA98XX_ERROR_RPC_PARAM_ID = 103,
	TFA98XX_ERROR_RPC_INVALID_CC = 104,
	TFA98XX_ERROR_RPC_INVALID_SEQ = 105,
	TFA98XX_ERROR_RPC_INVALID_PARAM = 106,
	TFA98XX_ERROR_RPC_BUFFER_OVERFLOW = 107,
	TFA98XX_ERROR_RPC_CALIB_BUSY = 108,
	TFA98XX_ERROR_RPC_CALIB_FAILED = 109,
	TFA98XX_ERROR_NOT_IMPLEMENTED,
	TFA98XX_ERROR_NOT_SUPPORTED,
	TFA98XX_ERROR_I2C_FATAL,		/* Fatal I2C error occurred */
	/* Nonfatal I2C error, and retry count reached */
	TFA98XX_ERROR_I2C_NON_FATAL,
	TFA98XX_ERROR_OTHER = 1000
};

enum tfa_error tfa_convert_error_code(enum tfa98xx_error err);

/*
 * Type containing all the possible msg returns DSP can give
 * TODO: move to tfa_dsp_fw.h
 */
enum tfa98xx_status_id {
	TFA98XX_DSP_NOT_RUNNING = -1,
	/* No response from DSP */
	TFA98XX_I2C_REQ_DONE = 0,
	/* Request executed correctly and result,
	 * if any, is available for download
	 */
	TFA98XX_I2C_REQ_BUSY = 1,
	/* Request is being processed, just wait for result */
	TFA98XX_I2C_REQ_INVALID_M_ID = 2,
	/* Provided M-ID does not fit in valid rang [0..2] */
	TFA98XX_I2C_REQ_INVALID_P_ID = 3,
	/* Provided P-ID isn�t valid in the given M-ID context */
	TFA98XX_I2C_REQ_INVALID_CC = 4,
	/* Invalid channel configuration bits (SC|DS|DP|DC) combination */
	TFA98XX_I2C_REQ_INVALID_SEQ = 5,
	/* Invalid sequence of commands,
	 * in case the DSP expects some commands in a specific order
	 */
	TFA98XX_I2C_REQ_INVALID_PARAM = 6,
	/* Generic error */
	TFA98XX_I2C_REQ_BUFFER_OVERFLOW = 7,
	/* I2C buffer has overflowed:
	 * host has sent too many parameters,
	 * memory integrity is not guaranteed
	 */
	TFA98XX_I2C_REQ_CALIB_BUSY = 8,
	/* Calibration not finished */
	TFA98XX_I2C_REQ_CALIB_FAILED = 9
	/* Calibration failed */
};

/*
 * config file subtypes
 */
enum tfa98xx_config_type {
	TFA98XX_CONFIG_GENERIC,
	TFA98XX_CONFIG_SUB1,
	TFA98XX_CONFIG_SUB2,
	TFA98XX_CONFIG_SUB3,
};

enum tfa98xx_amp_input_sel {
	TFA98XX_AMP_INPUT_SEL_I2SLEFT,
	TFA98XX_AMP_INPUT_SEL_I2SRIGHT,
	TFA98XX_AMP_INPUT_SEL_DSP
};

enum tfa98xx_output_sel {
	TFA98XX_I2S_OUTPUT_SEL_CURRENT_SENSE,
	TFA98XX_I2S_OUTPUT_SEL_DSP_GAIN,
	TFA98XX_I2S_OUTPUT_SEL_DSP_AEC,
	TFA98XX_I2S_OUTPUT_SEL_AMP,
	TFA98XX_I2S_OUTPUT_SEL_DATA3R,
	TFA98XX_I2S_OUTPUT_SEL_DATA3L,
	TFA98XX_I2S_OUTPUT_SEL_DCDC_FFWD_CUR,
};

enum tfa98xx_stereo_gain_sel {
	TFA98XX_STEREO_GAIN_SEL_LEFT,
	TFA98XX_STEREO_GAIN_SEL_RIGHT
};

#define TFA98XX_MAXPATCH_LENGTH (3*1024)

/* the number of biquads supported */
#define TFA98XX_BIQUAD_NUM	10

enum tfa98xx_channel {
	TFA98XX_CHANNEL_L,
	TFA98XX_CHANNEL_R,
	TFA98XX_CHANNEL_L_R,
	TFA98XX_CHANNEL_STEREO
};

enum tfa98xx_mode {
	TFA98XX_MODE_NORMAL = 0,
	TFA98XX_MODE_RCV
};

enum tfa98xx_mute {
	TFA98XX_MUTE_OFF,
	TFA98XX_MUTE_DIGITAL,
	TFA98XX_MUTE_AMPLIFIER
};

enum tfa98xx_speaker_boost_status_flags {
	TFA98XX_SPEAKER_BOOST_ACTIVITY = 0,	/* Input signal activity. */
	TFA98XX_SPEAKER_BOOST_S_CTRL,		/* S Control triggers limiter */
	TFA98XX_SPEAKER_BOOST_MUTED,		/* 1 when signal is muted */
	TFA98XX_SPEAKER_BOOST_X_CTRL,		/* X Control triggers limiter */
	TFA98XX_SPEAKER_BOOST_T_CTRL,		/* T Control triggers limiter */
	TFA98XX_SPEAKER_BOOST_NEW_MODEL,	/* New model is available */
	TFA98XX_SPEAKER_BOOST_VOLUME_RDY,	/* 0:stable vol, 1:smoothing */
	TFA98XX_SPEAKER_BOOST_DAMAGED,		/* Speaker Damage detected  */
	TFA98XX_SPEAKER_BOOST_SIGNAL_CLIPPING	/* input clipping detected */
};

struct tfa_msg {
	uint8_t msg_size;
	unsigned char cmd_id[3];
	int data[9];
};

/* possible memory values for DMEM in CF_CONTROLs */
enum tfa98xx_dmem {
	TFA98XX_DMEM_ERR = -1,
	TFA98XX_DMEM_PMEM = 0,
	TFA98XX_DMEM_XMEM = 1,
	TFA98XX_DMEM_YMEM = 2,
	TFA98XX_DMEM_IOMEM = 3,
};

/*
 * Load the default HW settings in the device
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa98xx_init(struct tfa_device *tfa);

/* control the powerdown bit
 * @param tfa the device struct pointer
 * @param powerdown must be 1 or 0
 */
enum tfa98xx_error tfa98xx_powerdown(struct tfa_device *tfa, int powerdown);

/*
 * set the mtp with user controllable values
 * @param tfa the device struct pointer
 * @param value to be written
 * @param mask to be applied toi the bits affected
 */
enum tfa98xx_error tfa98xx_set_mtp(struct tfa_device *tfa,
	uint16_t value, uint16_t mask);
enum tfa98xx_error tfa98xx_get_mtp(struct tfa_device *tfa, uint16_t *value);

/*
 * lock or unlock KEY2
 * lock = 1 will lock
 * lock = 0 will unlock
 * note that on return all the hidden key will be off
 */
void tfa98xx_key2(struct tfa_device *tfa, int lock);

void tfa98xx_set_exttemp(struct tfa_device *tfa, short ext_temp);
short tfa98xx_get_exttemp(struct tfa_device *tfa);

enum tfa98xx_error tfa98xx_read_reference_temp(short *value);

/* control the volume of the DSP
 * @param vol volume in bit field. It must be between 0 and 255
 */
enum tfa98xx_error tfa98xx_set_volume_level(struct tfa_device *tfa,
	unsigned short vol);

/* set the mode for normal or receiver mode
 * @param mode see tfa98xx_mode enumeration
 */
enum tfa98xx_error tfa98xx_select_mode(struct tfa_device *tfa,
	enum tfa98xx_mode mode);

/* mute/unmute the audio
 * @param mute see tfa98xx_mute enumeration
 */
enum tfa98xx_error tfa98xx_set_mute(struct tfa_device *tfa,
	enum tfa98xx_mute mute);

/*
 * tfa_supported_speakers - required for SmartStudio initialization
 * returns the number of the supported speaker count
 */
enum tfa98xx_error tfa_supported_speakers(struct tfa_device *tfa,
	int *spkr_count);

/*
 * Return the tfa revision
 */
void tfa98xx_rev(int *major, int *minor, int *revision);

/*
 * tfa98xx_set_stream_state
 *  sets the stream: b0: pstream (Rx), b1: cstream (Tx)
 */
enum tfa98xx_error tfa98xx_set_stream_state(struct tfa_device *tfa,
		int stream_state);

/* load the tables to the DSP
 * called after patch load is done
 * @return error code
 */
enum tfa98xx_error tfa98xx_dsp_write_tables(struct tfa_device *tfa,
	int sample_rate);

/* set or clear DSP reset signal
 * @param new state
 * @return error code
 */
enum tfa98xx_error tfa98xx_dsp_reset(struct tfa_device *tfa, int state);

/* check the state of the DSP subsystem
 * return ready = 1 when clocks are stable to allow safe DSP subsystem access
 * @param tfa the device struct pointer
 * @param ready pointer to state flag, non-zero if clocks are not stable
 * @return error code
 */
enum tfa98xx_error tfa98xx_dsp_system_stable(struct tfa_device *tfa,
	int *ready);

enum tfa98xx_error tfa98xx_auto_copy_mtp_to_iic(struct tfa_device *tfa);

/*
 * check the state of the DSP coolflux
 * @param tfa the device struct pointer
 * @return the value of CFE
 */
int tfa_cf_enabled(struct tfa_device *tfa);

/* The following functions can only be called when the DSP is running
 * - I2S clock must be active,
 * - IC must be in operating mode
 */

/*
 * patch the ROM code of the DSP
 * @param tfa the device struct pointer
 * @param patch_length the number of bytes of patch_bytes
 * @param patch_bytes pointer to the bytes to patch
 */
enum tfa98xx_error tfa_dsp_patch(struct tfa_device *tfa,
	int patch_length, const unsigned char *patch_bytes);

/*
 * wrapper for dsp_msg that adds opcode and only writes
 */
enum tfa98xx_error tfa_dsp_cmd_id_write(struct tfa_device *tfa,
	unsigned char module_id, unsigned char param_id, int num_bytes,
	const unsigned char data[]);

/*
 * wrapper for dsp_msg that writes opcode and reads back the data
 */
enum tfa98xx_error tfa_dsp_cmd_id_write_read(struct tfa_device *tfa,
	unsigned char module_id, unsigned char param_id, int num_bytes,
	unsigned char data[]);

/*
 * Disable a certain biquad.
 * @param tfa the device struct pointer
 * @param biquad_index: 1-10 of the biquad that needs to be adressed
 */
enum tfa98xx_error tfa98xx_dsp_biquad_disable(struct tfa_device *tfa,
	int biquad_index);

/*
 * fill the calibration value as milli ohms in the struct
 * assume that the device has been calibrated
 */
enum tfa98xx_error tfa_dsp_get_calibration_impedance(struct tfa_device *tfa);

/*
 * return the mohm value
 */
int tfa_get_calibration_info(struct tfa_device *tfa, int channel);

/*
 * Reads a number of words from dsp memory
 * @param tfa the device struct pointer
 * @param subaddress write address to set in address register
 * @param p_value pointer to read data
 */
enum tfa98xx_error tfa98xx_read_register16(struct tfa_device *tfa,
	unsigned char subaddress, unsigned short *p_value);

/*
 * Reads a number of words from dsp memory
 * @param tfa the device struct pointer
 * @param subaddress write address to set in address register
 * @param value value to write int the memory
 */
enum tfa98xx_error tfa98xx_write_register16(struct tfa_device *tfa,
	unsigned char subaddress, unsigned short value);

/*
 * convert signed 24 bit integers to 32bit aligned bytes
 * input:   data contains "num_bytes/3" int24 elements
 * output:  bytes contains "num_bytes" byte elements
 * @param num_data length of the input data array
 * @param data input data as integer array
 * @param bytes output data as unsigned char array
 */
void tfa98xx_convert_data2bytes(int num_data, const int data[],
	unsigned char bytes[]);

/*
 * convert memory bytes to signed 24 bit integers
 * input:  bytes contains "num_bytes" byte elements
 * output: data contains "num_bytes/3" int24 elements
 * @param num_bytes length of the input data array
 * @param bytes input data as unsigned char array
 * @param data output data as integer array
 */
void tfa98xx_convert_bytes2data(int num_bytes,
	const unsigned char bytes[], int data[]);

/*
 * write/read raw msg functions :
 * the buffer is provided in little endian format, each word occupying
 * 3 bytes, length is in bytes.
 * functions will return immediately and do not not wait for DSP response.
 * @param tfa the device struct pointer (void *)
 * @param length length of the character buffer to write
 * @param buf character buffer to write
 */
int tfa_dsp_msg_rpc(void *tfa, int length, const char *buf);

/*
 * Read a message from dsp
 * @param tfa the device struct pointer (void *)
 * @param length number of bytes of the message
 * @param bytes pointer to unsigned char buffer
 */
int tfa_dsp_msg_read_rpc(void *tfa, int length, unsigned char *bytes);

/*
 * The wrapper functions to call the dsp msg, register and memory function
 * for tfa or probus
 */
enum tfa98xx_error dsp_msg(struct tfa_device *tfa,
	int length, const char *buf);
enum tfa98xx_error dsp_msg_read(struct tfa_device *tfa,
	int length, unsigned char *bytes);
enum tfa98xx_error reg_write(struct tfa_device *tfa,
	unsigned char subaddress, unsigned short value);
enum tfa98xx_error reg_read(struct tfa_device *tfa,
	unsigned char subaddress, unsigned short *value);

/*
 * Get manstate from device
 * @param tfa the device struct pointer
 */
int tfa_get_manstate(struct tfa_device *tfa);

int tfa_set_bf(struct tfa_device *tfa,
	const uint16_t bf, const uint16_t value);
int tfa_set_bf_volatile(struct tfa_device *tfa,
	const uint16_t bf, const uint16_t value);

/*
 * Get the value of a given bitfield
 * @param tfa the device struct pointer
 * @param bf the value indicating which bitfield
 */
int tfa_get_bf(struct tfa_device *tfa, const uint16_t bf);

/*
 * Set the value of a given bitfield
 * @param bf the value indicating which bitfield
 * @param bf_value the value of the bitfield
 * @param p_reg_value a pointer to register where to write the bitfield value
 */
int tfa_set_bf_value(const uint16_t bf,
	const uint16_t bf_value, uint16_t *p_reg_value);

uint16_t tfa_get_bf_value(const uint16_t bf, const uint16_t reg_value);
int tfa_write_reg(struct tfa_device *tfa,
	const uint16_t bf, const uint16_t reg_value);
int tfa_read_reg(struct tfa_device *tfa,
	const uint16_t bf);

/* bitfield */

#define TFA_FAM(tfa, fieldname) TFA2_BF_##fieldname
#define TFA_FAM_FW(tfa, fwname) TFA2_FW_##fwname

/* set/get bit fields to HW register*/
#define TFA_SET_BF(tfa, fieldname, value) \
	tfa_set_bf(tfa, TFA_FAM(tfa, fieldname), value)
#define TFA_SET_BF_VOLATILE(tfa, fieldname, value) \
	tfa_set_bf_volatile(tfa, TFA_FAM(tfa, fieldname), value)
#define TFA_GET_BF(tfa, fieldname) tfa_get_bf(tfa, TFA_FAM(tfa, fieldname))

/* set/get bit field in variable */
#define TFA_SET_BF_VALUE(tfa, fieldname, bf_value, p_reg_value) \
	tfa_set_bf_value(TFA_FAM(tfa, fieldname), bf_value, p_reg_value)
#define TFA_GET_BF_VALUE(tfa, fieldname, reg_value) \
	tfa_get_bf_value(TFA_FAM(tfa, fieldname), reg_value)

/* write/read registers using a bit field name
 * to determine the register address
 */
#define TFA_WRITE_REG(tfa, fieldname, value) \
	tfa_write_reg(tfa, TFA_FAM(tfa, fieldname), value)
#define TFA_READ_REG(tfa, fieldname) \
	tfa_read_reg(tfa, TFA_FAM(tfa, fieldname))

/* TFA98xx specific */
/* #define TFAxx_FAM(fieldname) (TFA98XX_BF_##fieldname) */
#define TFAxx_FAM(fieldname) (TFA9878_BF_##fieldname)

/* set/get bit fields to HW register*/
#define TFAxx_SET_BF(tfa, fieldname, value) \
	tfa_set_bf(tfa, TFAxx_FAM(fieldname), value)
#define TFAxx_SET_BF_VOLATILE(tfa, fieldname, value) \
	tfa_set_bf_volatile(tfa, TFAxx_FAM(fieldname), value)
#define TFAxx_GET_BF(tfa, fieldname) \
	tfa_get_bf(tfa, TFAxx_FAM(fieldname))

/* set/get bit field in variable */
#define TFAxx_SET_BF_VALUE(tfa, fieldname, bf_value, p_reg_value) \
	tfa_set_bf_value(TFAxx_FAM(fieldname), bf_value, p_reg_value)
#define TFAxx_GET_BF_VALUE(tfa, fieldname, reg_value) \
	tfa_get_bf_value(TFAxx_FAM(fieldname), reg_value)

/* write/read registers using a bit field name
 * to determine the register address
 */
#define TFAxx_WRITE_REG(tfa, fieldname, value) \
	tfa_write_reg(tfa, TFAxx_FAM(fieldname), value)
#define TFAxx_READ_REG(tfa, fieldname) \
	tfa_read_reg(tfa, TFAxx_FAM(fieldname))

/* get bit value at nth value from right most */
#define TFA_GET_BIT_VALUE(value, nth) \
	(((value) & (0x1 << (nth))) >> (nth))

/* FOR CALIBRATION RETRIES */
#define TFA98XX_API_WAITRESULT_NTRIES 3000 /* defined in API */
#define TFA98XX_API_WAITCAL_NTRIES 20
#define TFA98XX_API_REWRTIE_MTP_NTRIES 5
#define CAL_STATUS_INTERVAL	100

enum tfa98xx_error tfa_run_mute(struct tfa_device *tfa);
enum tfa98xx_error tfa_run_unmute(struct tfa_device *tfa);

/*
 * run post-calibration process
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_wait_cal(struct tfa_device *tfa);

/*
 * check speaker damage with event / status
 * @param tfa the device struct pointer
 * @param dsp_event event from algorithm
 * @param dsp_status status from algorithm
 */
int tfa_run_damage_check(struct tfa_device *tfa,
	int dsp_event, int dsp_status);

/*
 * check V validation result with event / status
 * @param tfa the device struct pointer
 * @param dsp_event event from algorithm
 * @param dsp_status status from algorithm
 */
int tfa_run_vval_result_check(struct tfa_device *tfa,
	int dsp_event, int dsp_status);

/*
 * wait for calibrate_done
 * @param tfa the device struct pointer
 * @param calibrate_done pointer to status of calibration
 */
enum tfa98xx_error tfa_run_wait_calibration(struct tfa_device *tfa,
	int *calibrate_done);

/*
 * check speaker damage
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_check_speaker_damage(struct tfa_device *tfa);

/*
 * run the startup/init sequence and set ACS bit
 * @param tfa the device struct pointer
 * @param profile the profile that should be loaded
 */
enum tfa98xx_error tfa_run_coldstartup(struct tfa_device *tfa, int profile);

/*
 * run the startup/init sequence and set ACS bit
 * @param tfa the device struct pointer
 * @param state the cold start state that is requested
 */
enum tfa98xx_error tfa_run_coldboot(struct tfa_device *tfa, int state);

/*
 * this will load the patch witch will implicitly start the DSP
 * if no patch is available the DPS is started immediately
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_run_start_dsp(struct tfa_device *tfa);

/*
 * start the clocks and wait until the AMP is switching
 * on return the DSP sub system will be ready for loading
 * @param tfa the device struct pointer
 * @param profile the profile that should be loaded on startup
 */
enum tfa98xx_error tfa_run_startup(struct tfa_device *tfa, int profile);

/*
 * Write calibration values for probus / ext_dsp, to feed RE25C to algorithm
 */
enum tfa98xx_error tfa_set_calibration_values(struct tfa_device *tfa);

/*
 * Call tfa_set_calibration_values at once with loop
 */
enum tfa98xx_error tfa_set_calibration_values_once(struct tfa_device *tfa);

/*
 * Force to bypass and initialize algorithm if it's already configured
 */
enum tfa98xx_error tfa98xx_set_tfadsp_bypass(struct tfa_device *tfa);

/*
 * start the maximus speakerboost algorithm
 * this implies a full system startup when the system was not already started
 * @param tfa the device struct pointer
 * @param force indicates whether a full system startup should be allowed
 * @param profile the profile that should be loaded
 */
enum tfa98xx_error tfa_run_speaker_boost(struct tfa_device *tfa,
	int force, int profile);

/*
 * Startup the device and write all files from device and profile section
 * @param tfa the device struct pointer
 * @param force indicates whether a full system startup should be allowed
 * @param profile the profile that should be loaded on speaker startup
 */
enum tfa98xx_error tfa_run_speaker_startup(struct tfa_device *tfa,
	int force, int profile);

/*
 * Run calibration
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_run_speaker_calibration(struct tfa_device *tfa);

/*
 * startup all devices. all step until patch loading is handled
 * @param tfa the device struct pointer
 */
int tfa_run_startup_all(struct tfa_device *tfa);

/*
 * powerup the coolflux subsystem and wait for it
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_cf_powerup(struct tfa_device *tfa);

/*
 * print the current device manager state
 * @param tfa the device struct pointer
 */
enum tfa98xx_error tfa_show_current_state(struct tfa_device *tfa);

/*
 * Init registers and coldboot dsp
 * @param tfa the device struct pointer
 */
int tfa_reset(struct tfa_device *tfa);

/*
 * Get profile from a register
 * @param tfa the device struct pointer
 */
int tfa_dev_get_swprof(struct tfa_device *tfa);

/*
 * Save profile in a register
 */
int tfa_dev_set_swprof(struct tfa_device *tfa, unsigned short new_value);

int tfa_dev_get_swvstep(struct tfa_device *tfa);

int tfa_dev_set_swvstep(struct tfa_device *tfa, unsigned short new_value);

int tfa_is_cold(struct tfa_device *tfa);

int tfa_is_cold_amp(struct tfa_device *tfa);

enum tfa_status_type {
	TFA_SET_DEVICE = 0,
	TFA_SET_CONFIG = 1,
	TFA_SET_UNKNOWN
};

int tfa_count_status_flag(struct tfa_device *tfa, int type);
void tfa_set_status_flag(struct tfa_device *tfa, int type, int value);

void tfa_set_query_info(struct tfa_device *tfa);

int tfa_reset_sticky_bits(struct tfa_device *tfa);

/*
 * Status of used for monitoring
 * @param tfa the device struct pointer
 * @return tfa error enum
 */
enum tfa98xx_error tfaxx_status(struct tfa_device *tfa);

/*
 * function overload for flag_mtp_busy
 */
int tfa_dev_get_mtpb(struct tfa_device *tfa);

enum tfa98xx_error tfa_read_tspkr(struct tfa_device *tfa, int *spkt);
enum tfa98xx_error tfa_write_volume(struct tfa_device *tfa, int *sknt);

#ifdef __cplusplus
}
#endif
#endif /* TFA_SERVICE_H */

