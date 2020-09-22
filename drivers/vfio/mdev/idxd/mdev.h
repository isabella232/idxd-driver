/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2020 Intel Corporation. All rights rsvd. */

#ifndef _IDXD_MDEV_H_
#define _IDXD_MDEV_H_

/* two 64-bit BARs implemented */
#define VIDXD_MAX_BARS 2
#define VIDXD_MAX_CFG_SPACE_SZ 4096
#define VIDXD_MAX_MMIO_SPACE_SZ 8192
#define VIDXD_MSIX_TBL_SZ_OFFSET 0x42
#define VIDXD_CAP_CTRL_SZ 0x100
#define VIDXD_GRP_CTRL_SZ 0x100
#define VIDXD_WQ_CTRL_SZ 0x100
#define VIDXD_WQ_OCPY_INT_SZ 0x20
#define VIDXD_MSIX_TBL_SZ 0x90
#define VIDXD_MSIX_PERM_TBL_SZ 0x48

#define VIDXD_MSIX_TABLE_OFFSET 0x600
#define VIDXD_MSIX_PERM_OFFSET 0x300
#define VIDXD_GRPCFG_OFFSET 0x400
#define VIDXD_WQCFG_OFFSET 0x500
#define VIDXD_IMS_OFFSET 0x1000

#define VIDXD_BAR0_SIZE  0x2000
#define VIDXD_BAR2_SIZE  0x2000
#define VIDXD_MAX_MSIX_ENTRIES  (VIDXD_MSIX_TBL_SZ / 0x10)
#define VIDXD_MAX_WQS	1
#define VIDXD_MAX_MSIX_VECS	2

#define	VIDXD_ATS_OFFSET 0x100
#define	VIDXD_PRS_OFFSET 0x110
#define VIDXD_PASID_OFFSET 0x120
#define VIDXD_MSIX_PBA_OFFSET 0x700

struct ims_irq_entry {
	struct vdcm_idxd *vidxd;
	bool irq_set;
	int id;
	int irq;
	int ims_idx;
};

struct idxd_vdev {
	struct mdev_device *mdev;
	struct eventfd_ctx *msix_trigger[VIDXD_MAX_MSIX_ENTRIES];
};

struct vdcm_idxd {
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct idxd_vdev vdev;
	struct vdcm_idxd_type *type;
	int num_wqs;
	struct ims_irq_entry irq_entries[VIDXD_MAX_MSIX_ENTRIES];

	/* For VM use case */
	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];
	struct list_head list;
	struct mutex dev_lock; /* lock for vidxd resources */

	int refcount;
};

static inline struct vdcm_idxd *to_vidxd(struct idxd_vdev *vdev)
{
	return container_of(vdev, struct vdcm_idxd, vdev);
}

#define IDXD_MDEV_NAME_LEN 64

enum idxd_mdev_type {
	IDXD_MDEV_TYPE_DSA_1_DWQ = 0,
	IDXD_MDEV_TYPE_IAX_1_DWQ,
};

#define IDXD_MDEV_TYPES 2

struct vdcm_idxd_type {
	char *name;
	enum idxd_mdev_type type;
	unsigned int avail_instance;
};

enum idxd_vdcm_rw {
	IDXD_VDCM_READ = 0,
	IDXD_VDCM_WRITE,
};

static inline u64 get_reg_val(void *buf, int size)
{
	u64 val = 0;

	switch (size) {
	case 8:
		val = *(u64 *)buf;
		break;
	case 4:
		val = *(u32 *)buf;
		break;
	case 2:
		val = *(u16 *)buf;
		break;
	case 1:
		val = *(u8 *)buf;
		break;
	}

	return val;
}

#define auxdev_to_idxd(_aux_dev) container_of(_aux_dev, struct idxd_device, auxdev)

int idxd_mdev_get_pasid(struct mdev_device *mdev, u32 *pasid);

#endif
