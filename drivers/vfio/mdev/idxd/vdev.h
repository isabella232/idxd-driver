/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019,2020 Intel Corporation. All rights rsvd. */

#ifndef _IDXD_VDEV_H_
#define _IDXD_VDEV_H_

#include "mdev.h"

static inline u8 vidxd_state(struct vdcm_idxd *vidxd)
{
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);

	return gensts->state;
}

int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);
int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);
int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count);
int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size);
void vidxd_mmio_init(struct vdcm_idxd *vidxd);
void vidxd_reset(struct vdcm_idxd *vidxd);
int vidxd_send_interrupt(struct ims_irq_entry *iie);
int vidxd_setup_ims_entries(struct vdcm_idxd *vidxd);
void vidxd_free_ims_entries(struct vdcm_idxd *vidxd);
void vidxd_do_command(struct vdcm_idxd *vidxd, u32 val);
void idxd_wq_vidxd_send_errors(struct idxd_wq *wq);

#endif
