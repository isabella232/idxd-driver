// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019,2020 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/msi.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "../../vfio/pci/vfio_pci_private.h"
#include "mdev.h"
#include "vdev.h"

int vidxd_send_interrupt(struct ims_irq_entry *iie)
{
	/* PLACE HOLDER */
	return 0;
}

int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	/* PLACEHOLDER */
	return 0;
}

int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	/* PLACEHOLDER */
	return 0;
}

int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count)
{
	/* PLACEHOLDER */
	return 0;
}

int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size)
{
	/* PLACEHOLDER */
	return 0;
}

void vidxd_mmio_init(struct vdcm_idxd *vidxd)
{
	/* PLACEHOLDER */
}

void vidxd_reset(struct vdcm_idxd *vidxd)
{
	/* PLACEHOLDER */
}

int vidxd_setup_ims_entries(struct vdcm_idxd *vidxd)
{
	/* PLACEHOLDER */
	return 0;
}

void vidxd_free_ims_entries(struct vdcm_idxd *vidxd)
{
	/* PLACEHOLDER */
}
