# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux kernel device drivers.
#
# 15 Sep 2000, Christoph Hellwig <hch@infradead.org>
# Rewritten to use lists instead of if-statements.
#

obj-y				+= irqchip/
obj-y				+= bus/

obj-$(CONFIG_GENERIC_PHY)	+= phy/

# GPIO must come after pinctrl as gpios may need to mux pins etc
obj-$(CONFIG_PINCTRL)		+= pinctrl/
obj-$(CONFIG_GPIOLIB)		+= gpio/
obj-y				+= pwm/

obj-y				+= pci/

obj-$(CONFIG_PARISC)		+= parisc/
obj-$(CONFIG_RAPIDIO)		+= rapidio/
obj-y				+= video/
obj-y				+= idle/

# IPMI must come before ACPI in order to provide IPMI opregion support
obj-y				+= char/ipmi/

obj-$(CONFIG_ACPI)		+= acpi/

# PnP must come after ACPI since it will eventually need to check if acpi
# was used and do nothing if so
obj-$(CONFIG_PNP)		+= pnp/
obj-y				+= amba/

obj-y				+= clk/
# Many drivers will want to use DMA so this has to be made available
# really early.
obj-$(CONFIG_DMADEVICES)	+= dma/

# CLO
obj-$(CONFIG_CLO) += clo/

# SOC specific infrastructure drivers.
obj-y				+= soc/

obj-y				+= virtio/
obj-$(CONFIG_VDPA)		+= vdpa/
obj-$(CONFIG_XEN)		+= xen/

# regulators early, since some subsystems rely on them to initialize
obj-$(CONFIG_REGULATOR)		+= regulator/

# reset controllers early, since gpu drivers might rely on them to initialize
obj-$(CONFIG_RESET_CONTROLLER)	+= reset/

# tty/ comes before char/ so that the VT console is the boot-time
# default.
obj-y				+= tty/
obj-y				+= char/

# iommu/ comes before gpu as gpu are using iommu controllers
obj-y				+= iommu/

# gpu/ comes after char for AGP vs DRM startup and after iommu
obj-y				+= gpu/

obj-$(CONFIG_CONNECTOR)		+= connector/

# i810fb and intelfb depend on char/agp/
obj-$(CONFIG_FB_I810)           += video/fbdev/i810/
obj-$(CONFIG_FB_INTEL)          += video/fbdev/intelfb/

obj-$(CONFIG_PARPORT)		+= parport/
obj-y				+= base/ block/ misc/ mfd/ nfc/
obj-$(CONFIG_LIBNVDIMM)		+= nvdimm/
obj-$(CONFIG_DAX)		+= dax/
obj-$(CONFIG_DMA_SHARED_BUFFER) += dma-buf/
obj-$(CONFIG_NUBUS)		+= nubus/
obj-y				+= cxl/
obj-y				+= macintosh/
obj-y				+= scsi/
obj-y				+= nvme/
obj-$(CONFIG_ATA)		+= ata/
obj-$(CONFIG_TARGET_CORE)	+= target/
obj-$(CONFIG_MTD)		+= mtd/
obj-$(CONFIG_SPI)		+= spi/
obj-$(CONFIG_SPMI)		+= spmi/
obj-$(CONFIG_HSI)		+= hsi/
obj-$(CONFIG_SLIMBUS)		+= slimbus/
obj-y				+= net/
obj-$(CONFIG_ATM)		+= atm/
obj-$(CONFIG_FUSION)		+= message/
obj-y				+= firewire/
obj-$(CONFIG_UIO)		+= uio/
obj-$(CONFIG_VFIO)		+= vfio/
obj-y				+= cdrom/
obj-y				+= auxdisplay/
obj-$(CONFIG_PCCARD)		+= pcmcia/
obj-$(CONFIG_DIO)		+= dio/
obj-$(CONFIG_SBUS)		+= sbus/
obj-$(CONFIG_ZORRO)		+= zorro/
obj-$(CONFIG_ATA_OVER_ETH)	+= block/aoe/
obj-$(CONFIG_PARIDE) 		+= block/paride/
obj-$(CONFIG_TC)		+= tc/
obj-$(CONFIG_USB_PHY)		+= usb/
obj-$(CONFIG_USB)		+= usb/
obj-$(CONFIG_USB_SUPPORT)	+= usb/
obj-$(CONFIG_PCI)		+= usb/
obj-$(CONFIG_USB_GADGET)	+= usb/
obj-$(CONFIG_OF)		+= usb/
obj-$(CONFIG_SERIO)		+= input/serio/
obj-$(CONFIG_GAMEPORT)		+= input/gameport/
obj-$(CONFIG_INPUT)		+= input/
obj-$(CONFIG_RTC_LIB)		+= rtc/
obj-y				+= i2c/ i3c/ media/
obj-$(CONFIG_PPS)		+= pps/
obj-y				+= ptp/
obj-$(CONFIG_W1)		+= w1/
obj-y				+= power/
obj-$(CONFIG_HWMON)		+= hwmon/
obj-$(CONFIG_THERMAL)		+= thermal/
obj-$(CONFIG_WATCHDOG)		+= watchdog/
obj-$(CONFIG_MD)		+= md/
obj-$(CONFIG_BT)		+= bluetooth/
obj-$(CONFIG_ACCESSIBILITY)	+= accessibility/
obj-$(CONFIG_ISDN)		+= isdn/
obj-$(CONFIG_EDAC)		+= edac/
obj-$(CONFIG_EISA)		+= eisa/
obj-$(CONFIG_PM_OPP)		+= opp/
obj-$(CONFIG_CPU_FREQ)		+= cpufreq/
obj-$(CONFIG_CPU_IDLE)		+= cpuidle/
obj-y				+= mmc/
obj-y				+= ufs/
obj-$(CONFIG_MEMSTICK)		+= memstick/
obj-$(CONFIG_NEW_LEDS)		+= leds/
obj-$(CONFIG_INFINIBAND)	+= infiniband/
obj-y				+= firmware/
obj-$(CONFIG_CRYPTO)		+= crypto/
obj-$(CONFIG_SUPERH)		+= sh/
obj-y				+= clocksource/
obj-$(CONFIG_DCA)		+= dca/
obj-$(CONFIG_HID)		+= hid/
obj-$(CONFIG_PPC_PS3)		+= ps3/
obj-$(CONFIG_OF)		+= of/
obj-$(CONFIG_SSB)		+= ssb/
obj-$(CONFIG_BCMA)		+= bcma/
obj-$(CONFIG_VHOST_RING)	+= vhost/
obj-$(CONFIG_VHOST_IOTLB)	+= vhost/
obj-$(CONFIG_VHOST)		+= vhost/
obj-$(CONFIG_VLYNQ)		+= vlynq/
obj-$(CONFIG_GREYBUS)		+= greybus/
obj-$(CONFIG_COMEDI)		+= comedi/
obj-$(CONFIG_STAGING)		+= staging/
obj-y				+= platform/

obj-$(CONFIG_MAILBOX)		+= mailbox/
obj-$(CONFIG_HWSPINLOCK)	+= hwspinlock/
obj-$(CONFIG_REMOTEPROC)	+= remoteproc/
obj-$(CONFIG_RPMSG)		+= rpmsg/
obj-$(CONFIG_SOUNDWIRE)		+= soundwire/

# Virtualization drivers
obj-$(CONFIG_VIRT_DRIVERS)	+= virt/
obj-$(subst m,y,$(CONFIG_HYPERV))	+= hv/

obj-$(CONFIG_PM_DEVFREQ)	+= devfreq/
obj-$(CONFIG_EXTCON)		+= extcon/
obj-$(CONFIG_MEMORY)		+= memory/
obj-$(CONFIG_IIO)		+= iio/
obj-$(CONFIG_IPACK_BUS)		+= ipack/
obj-$(CONFIG_NTB)		+= ntb/
obj-$(CONFIG_POWERCAP)		+= powercap/
obj-$(CONFIG_MCB)		+= mcb/
obj-$(CONFIG_PERF_EVENTS)	+= perf/
obj-$(CONFIG_RAS)		+= ras/
obj-$(CONFIG_USB4)		+= thunderbolt/
obj-$(CONFIG_CORESIGHT)		+= hwtracing/coresight/
obj-y				+= hwtracing/intel_th/
obj-$(CONFIG_STM)		+= hwtracing/stm/
obj-$(CONFIG_HISI_PTT)		+= hwtracing/ptt/
obj-y				+= android/
obj-$(CONFIG_NVMEM)		+= nvmem/
obj-$(CONFIG_FPGA)		+= fpga/
obj-$(CONFIG_FSI)		+= fsi/
obj-$(CONFIG_TEE)		+= tee/
obj-$(CONFIG_MULTIPLEXER)	+= mux/
obj-$(CONFIG_SIOX)		+= siox/
obj-$(CONFIG_GNSS)		+= gnss/
obj-$(CONFIG_INTERCONNECT)	+= interconnect/
obj-$(CONFIG_COUNTER)		+= counter/
obj-$(CONFIG_MOST)		+= most/
obj-$(CONFIG_PECI)		+= peci/
obj-$(CONFIG_HTE)		+= hte/
obj-$(CONFIG_TRUSTONIC_TEE) += gud/
obj-$(CONFIG_VISION_SUPPORT)    += vision/
obj-${CONFIG_SEC_STI}           += sti/
obj-${CONFIG_EXYNOS_BTS}        += bts/
obj-$(CONFIG_UH)		+= uh/

obj-y += samsung/
obj-y				+= knox/
obj-y += sec_panel_notifier_v2/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/typec/manager/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/charger/max77705_charger/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/charger/max77775_charger/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += muic/common/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += gpu/drm/samsung/panel/s6e3fac/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += gpu/drm/samsung/panel/oled_common/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += staging/android/switch/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += samsung/debug/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += input/input_boost/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += sdp/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/common/vbus_notifier/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += input/sec_input/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += net/dropdump/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/fuelgauge/max77705_fuelgauge/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += mfd/maxim/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += vibrator/common/vib_info/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += optics/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += kq/mesh/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += kperfmon/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += vibrator/common/inputff/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/notify/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += regulator/pmic_class/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/vendor_notify/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += fingerprint/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += phy/common/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/core/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += gpu/drm/samsung/panel/s6e3fae/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/typec/common/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += gpu/drm/samsung/panel/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/battery_auth/ds28e30/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += vibrator/cs/cs40l26/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += regulator/s2dos05/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += input/misc/hall/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += phy/ti/tusb2e11/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += usb/typec/maxim/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/charger/pca9481_charger/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += phy/nxp/ptn3222/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/fuelgauge/max77775_fuelgauge/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += sensorhub/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += input/sec_input/stm_spi/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += nfc/lsi/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/common/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
obj-y += battery/wireless/ # ADDED BY LEGO AUTOMATICALLY: DO NOT SUBMIT
