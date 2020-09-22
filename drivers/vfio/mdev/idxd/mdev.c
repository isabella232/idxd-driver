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
#include <linux/circ_buf.h>
#include <linux/irqchip/irq-ims-msi.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "../../vfio/pci/vfio_pci_private.h"
#include "mdev.h"
#include "vdev.h"

static u64 idxd_pci_config[] = {
	0x0010000000008086ULL,
	0x0080000008800000ULL,
	0x000000000000000cULL,
	0x000000000000000cULL,
	0x0000000000000000ULL,
	0x2010808600000000ULL,
	0x0000004000000000ULL,
	0x000000ff00000000ULL,
	0x0000060000015011ULL, /* MSI-X capability, hardcoded 2 entries, Encoded as N-1 */
	0x0000070000000000ULL,
	0x0000000000920010ULL, /* PCIe capability */
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
};

static char idxd_dsa_1dwq_name[IDXD_MDEV_NAME_LEN];
static char idxd_iax_1dwq_name[IDXD_MDEV_NAME_LEN];

static int idxd_vdcm_set_irqs(struct vdcm_idxd *vidxd, uint32_t flags, unsigned int index,
			      unsigned int start, unsigned int count, void *data);

int idxd_mdev_get_pasid(struct mdev_device *mdev, u32 *pasid)
{
	unsigned long ioasid;
	int rc;

	rc = vfio_subdev_ioasid(mdev_dev(mdev), &ioasid);
	if (rc < 0)
		return rc;

	*pasid = (u32)ioasid;
	return 0;
}

static inline void reset_vconfig(struct vdcm_idxd *vidxd)
{
	u16 *devid = (u16 *)(vidxd->cfg + PCI_DEVICE_ID);
	struct idxd_device *idxd = vidxd->idxd;

	memset(vidxd->cfg, 0, VIDXD_MAX_CFG_SPACE_SZ);
	memcpy(vidxd->cfg, idxd_pci_config, sizeof(idxd_pci_config));

	if (idxd->type == IDXD_TYPE_DSA)
		*devid = PCI_DEVICE_ID_INTEL_DSA_SPR0;
	else if (idxd->type == IDXD_TYPE_IAX)
		*devid = PCI_DEVICE_ID_INTEL_IAX_SPR0;
}

static inline void reset_vmmio(struct vdcm_idxd *vidxd)
{
	memset(&vidxd->bar0, 0, VIDXD_MAX_MMIO_SPACE_SZ);
}

static void idxd_vdcm_init(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	reset_vconfig(vidxd);
	reset_vmmio(vidxd);

	vidxd->bar_size[0] = VIDXD_BAR0_SIZE;
	vidxd->bar_size[1] = VIDXD_BAR2_SIZE;

	vidxd_mmio_init(vidxd);

	if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED)
		idxd_wq_disable(wq, NULL);
}

static void idxd_vdcm_release(struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "vdcm_idxd_release %d\n", vidxd->type->type);
	mutex_lock(&vidxd->dev_lock);
	if (!vidxd->refcount)
		goto out;

        idxd_vdcm_set_irqs(vidxd, VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
			   VFIO_PCI_MSIX_IRQ_INDEX, 0, 0, NULL);

	vidxd_free_ims_entries(vidxd);

	/* Re-initialize the VIDXD to a pristine state for re-use */
	idxd_vdcm_init(vidxd);
	vidxd->refcount--;

 out:
	mutex_unlock(&vidxd->dev_lock);
}

static struct idxd_wq *find_any_dwq(struct idxd_device *idxd, struct vdcm_idxd_type *type)
{
	int i;
	struct idxd_wq *wq;
	unsigned long flags;

	switch (type->type) {
	case IDXD_MDEV_TYPE_DSA_1_DWQ:
		if (idxd->type != IDXD_TYPE_DSA)
			return NULL;
		break;
	case IDXD_MDEV_TYPE_IAX_1_DWQ:
		if (idxd->type != IDXD_TYPE_IAX)
			return NULL;
		break;
	default:
		return NULL;
	}

	spin_lock_irqsave(&idxd->dev_lock, flags);
	for (i = 0; i < idxd->max_wqs; i++) {
		wq = &idxd->wqs[i];

		if (wq->state != IDXD_WQ_ENABLED)
			continue;

		if (!wq_dedicated(wq))
			continue;

		if (idxd_wq_refcount(wq) != 0)
			continue;

		spin_unlock_irqrestore(&idxd->dev_lock, flags);
		mutex_lock(&wq->wq_lock);
		if (idxd_wq_refcount(wq)) {
			spin_lock_irqsave(&idxd->dev_lock, flags);
			continue;
		}

		idxd_wq_get(wq);
		mutex_unlock(&wq->wq_lock);
		return wq;
	}

	spin_unlock_irqrestore(&idxd->dev_lock, flags);
	return NULL;
}

static struct vdcm_idxd *vdcm_vidxd_create(struct idxd_device *idxd, struct mdev_device *mdev,
					   struct vdcm_idxd_type *type)
{
	struct vdcm_idxd *vidxd;
	struct idxd_wq *wq = NULL;
	int i, rc;

	wq = find_any_dwq(idxd, type);
	if (!wq)
		return ERR_PTR(-ENODEV);

	vidxd = kzalloc(sizeof(*vidxd), GFP_KERNEL);
	if (!vidxd) {
		rc = -ENOMEM;
		goto err;
	}

	mutex_init(&vidxd->dev_lock);
	vidxd->idxd = idxd;
	vidxd->vdev.mdev = mdev;
	vidxd->wq = wq;
	mdev_set_drvdata(mdev, vidxd);
	vidxd->type = type;
	vidxd->num_wqs = VIDXD_MAX_WQS;

	idxd_vdcm_init(vidxd);

	for (i = 0; i < VIDXD_MAX_MSIX_ENTRIES; i++) {
		vidxd->irq_entries[i].vidxd = vidxd;
		vidxd->irq_entries[i].id = i;
	}

	return vidxd;

 err:
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
	return ERR_PTR(rc);
}

static struct vdcm_idxd_type idxd_mdev_types[IDXD_MDEV_TYPES] = {
	{
		.name = idxd_dsa_1dwq_name,
		.type = IDXD_MDEV_TYPE_DSA_1_DWQ,
	},
	{
		.name = idxd_iax_1dwq_name,
		.type = IDXD_MDEV_TYPE_IAX_1_DWQ,
	},
};

static struct vdcm_idxd_type *idxd_vdcm_find_vidxd_type(struct device *dev,
							const char *name)
{
	int i;
	char dev_name[IDXD_MDEV_NAME_LEN];

	for (i = 0; i < IDXD_MDEV_TYPES; i++) {
		snprintf(dev_name, IDXD_MDEV_NAME_LEN, "idxd-%s",
			 idxd_mdev_types[i].name);

		if (!strncmp(name, dev_name, IDXD_MDEV_NAME_LEN))
			return &idxd_mdev_types[i];
	}

	return NULL;
}

static int idxd_vdcm_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd;
	struct vdcm_idxd_type *type;
	struct device *dev, *parent;
	struct idxd_device *idxd;
	struct idxd_wq *wq;

	parent = mdev_parent_dev(mdev);
	idxd = dev_get_drvdata(parent);
	dev = mdev_dev(mdev);
	mdev_set_iommu_device(dev, parent);
	type = idxd_vdcm_find_vidxd_type(dev, kobject_name(kobj));
	if (!type) {
		dev_err(dev, "failed to find type %s to create\n",
			kobject_name(kobj));
		return -EINVAL;
	}

	vidxd = vdcm_vidxd_create(idxd, mdev, type);
	if (IS_ERR(vidxd)) {
		dev_err(dev, "failed to create vidxd: %ld\n", PTR_ERR(vidxd));
		return PTR_ERR(vidxd);
	}

	wq = vidxd->wq;
	mutex_lock(&wq->wq_lock);
	list_add(&vidxd->list, &wq->vdcm_list);
	mutex_unlock(&wq->wq_lock);
	dev_dbg(dev, "mdev creation success: %s\n", dev_name(mdev_dev(mdev)));

	return 0;
}

static int idxd_vdcm_remove(struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	struct idxd_device *idxd = vidxd->idxd;
	struct device *dev = &idxd->pdev->dev;
	struct idxd_wq *wq = vidxd->wq;

	dev_dbg(dev, "%s: removing for wq %d\n", __func__, vidxd->wq->id);

	mutex_lock(&wq->wq_lock);
	list_del(&vidxd->list);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);

	kfree(vidxd);
	return 0;
}

static int idxd_vdcm_open(struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	int rc = -EINVAL;
	struct vdcm_idxd_type *type = vidxd->type;
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "%s: type: %d\n", __func__, type->type);

	mutex_lock(&vidxd->dev_lock);
	if (vidxd->refcount)
		goto out;

	/* allocate and setup IMS entries */
	rc = vidxd_setup_ims_entries(vidxd);
	if (rc < 0)
		goto out;

	vidxd->refcount++;
	mutex_unlock(&vidxd->dev_lock);

	return rc;

 out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static ssize_t idxd_vdcm_rw(struct mdev_device *mdev, char *buf, size_t count, loff_t *ppos,
			    enum idxd_vdcm_rw mode)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	struct device *dev = mdev_dev(mdev);
	int rc = -EINVAL;

	if (index >= VFIO_PCI_NUM_REGIONS) {
		dev_err(dev, "invalid index: %u\n", index);
		return -EINVAL;
	}

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_cfg_write(vidxd, pos, buf, count);
		else
			rc = vidxd_cfg_read(vidxd, pos, buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_mmio_write(vidxd, vidxd->bar_val[0] + pos, buf, count);
		else
			rc = vidxd_mmio_read(vidxd, vidxd->bar_val[0] + pos, buf, count);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
	default:
		dev_err(dev, "unsupported region: %u\n", index);
	}

	return rc == 0 ? count : rc;
}

static ssize_t idxd_vdcm_read(struct mdev_device *mdev, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			rc = idxd_vdcm_rw(mdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = idxd_vdcm_rw(mdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = idxd_vdcm_rw(mdev, &val, sizeof(val), ppos,
					  IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

 read_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static ssize_t idxd_vdcm_write(struct mdev_device *mdev, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(mdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(mdev, (char *)&val,
					  sizeof(val), ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(mdev, &val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

write_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static int check_vma(struct idxd_wq *wq, struct vm_area_struct *vma)
{
	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	return 0;
}

static int idxd_vdcm_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	unsigned int wq_idx, rc;
	unsigned long req_size, pgoff = 0, offset;
	pgprot_t pg_prot;
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_device *idxd = vidxd->idxd;
	enum idxd_portal_prot virt_portal, phys_portal;
	phys_addr_t base = pci_resource_start(idxd->pdev, IDXD_WQ_BAR);
	struct device *dev = mdev_dev(mdev);

	rc = check_vma(wq, vma);
	if (rc)
		return rc;

	pg_prot = vma->vm_page_prot;
	req_size = vma->vm_end - vma->vm_start;
	vma->vm_flags |= VM_DONTCOPY;

	offset = (vma->vm_pgoff << PAGE_SHIFT) &
		 ((1ULL << VFIO_PCI_OFFSET_SHIFT) - 1);

	wq_idx = offset >> (PAGE_SHIFT + 2);
	if (wq_idx >= 1) {
		dev_err(dev, "mapping invalid wq %d off %lx\n",
			wq_idx, offset);
		return -EINVAL;
	}

	/*
	 * Check and see if the guest wants to map to the limited or unlimited portal.
	 * The driver will allow mapping to unlimited portal only if the the wq is a
	 * dedicated wq. Otherwise, it goes to limited.
	 */
	virt_portal = ((offset >> PAGE_SHIFT) & 0x3) == 1;
	phys_portal = IDXD_PORTAL_LIMITED;
	if (virt_portal == IDXD_PORTAL_UNLIMITED && wq_dedicated(wq))
		phys_portal = IDXD_PORTAL_UNLIMITED;

	/* We always map IMS portals to the guest */
	pgoff = (base + idxd_get_wq_portal_full_offset(wq->id, phys_portal,
						       IDXD_IRQ_IMS)) >> PAGE_SHIFT;

	dev_dbg(dev, "mmap %lx %lx %lx %lx\n", vma->vm_start, pgoff, req_size,
		pgprot_val(pg_prot));
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_private_data = mdev;
	vma->vm_pgoff = pgoff;

	return remap_pfn_range(vma, vma->vm_start, pgoff, req_size, pg_prot);
}

static int idxd_vdcm_get_irq_count(struct vdcm_idxd *vidxd, int type)
{
	/*
	 * Even though the number of MSIX vectors supported are not tied to number of
	 * wqs being exported, the current design is to allow 1 vector per WQ for guest.
	 * So here we end up with num of wqs plus 1 that handles the misc interrupts.
	 */
	if (type == VFIO_PCI_MSI_IRQ_INDEX || type == VFIO_PCI_MSIX_IRQ_INDEX)
		return VIDXD_MAX_MSIX_VECS;

	return 0;
}

static irqreturn_t idxd_guest_wq_completion(int irq, void *data)
{
	struct ims_irq_entry *irq_entry = data;

	vidxd_send_interrupt(irq_entry);
	return IRQ_HANDLED;
}

static int msix_trigger_unregister(struct vdcm_idxd *vidxd, int index)
{
	struct mdev_device *mdev = vidxd->vdev.mdev;
	struct device *dev = mdev_dev(mdev);
	struct ims_irq_entry *irq_entry;
	int rc;

	if (!vidxd->vdev.msix_trigger[index])
		return 0;

	dev_dbg(dev, "disable MSIX trigger %d\n", index);
	if (index) {
		u32 auxval;

		irq_entry = &vidxd->irq_entries[index];
		if (irq_entry->irq_set) {
			free_irq(irq_entry->irq, irq_entry);
			irq_entry->irq_set = false;
		}

		auxval = ims_ctrl_pasid_aux(0, false);
		rc = irq_set_auxdata(irq_entry->irq, IMS_AUXDATA_CONTROL_WORD, auxval);
		if (rc)
			return rc;
	}
	eventfd_ctx_put(vidxd->vdev.msix_trigger[index]);
	vidxd->vdev.msix_trigger[index] = NULL;

	return 0;
}

static int msix_trigger_register(struct vdcm_idxd *vidxd, u32 fd, int index)
{
	struct mdev_device *mdev = vidxd->vdev.mdev;
	struct device *dev = mdev_dev(mdev);
	struct ims_irq_entry *irq_entry;
	struct eventfd_ctx *trigger;
	int rc;

	rc = msix_trigger_unregister(vidxd, index);
	if (rc < 0)
		return rc;

	dev_dbg(dev, "enable MSIX trigger %d\n", index);
	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		dev_warn(dev, "eventfd_ctx_fdget failed %d\n", index);
		return PTR_ERR(trigger);
	}

	if (index) {
		u32 pasid;
		u32 auxval;

		irq_entry = &vidxd->irq_entries[index];
		rc = idxd_mdev_get_pasid(mdev, &pasid);
		if (rc < 0)
			return rc;

		/*
		 * Program and enable the pasid field in the IMS entry. The programmed pasid and
		 * enabled field is checked against the  pasid and enable field for the work queue
		 * configuration and the pasid for the descriptor. A mismatch will result in blocked
		 * IMS interrupt.
		 */
		auxval = ims_ctrl_pasid_aux(pasid, true);
		rc = irq_set_auxdata(irq_entry->irq, IMS_AUXDATA_CONTROL_WORD, auxval);
		if (rc < 0)
			return rc;

		rc = request_irq(irq_entry->irq, idxd_guest_wq_completion, 0, "idxd-ims",
				 irq_entry);
		if (rc) {
			dev_warn(dev, "failed to request ims irq\n");
			eventfd_ctx_put(trigger);
			auxval = ims_ctrl_pasid_aux(0, false);
			irq_set_auxdata(irq_entry->irq, IMS_AUXDATA_CONTROL_WORD, auxval);
			return rc;
		}
		irq_entry->irq_set = true;
	}

	vidxd->vdev.msix_trigger[index] = trigger;
	return 0;
}

static int vdcm_idxd_set_msix_trigger(struct vdcm_idxd *vidxd,
				      unsigned int index, unsigned int start,
				      unsigned int count, uint32_t flags,
				      void *data)
{
	int i, rc = 0;

	if (count > VIDXD_MAX_MSIX_ENTRIES - 1)
		count = VIDXD_MAX_MSIX_ENTRIES - 1;

	if (count == 0 && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		/* Disable all MSIX entries */
		for (i = 0; i < VIDXD_MAX_MSIX_ENTRIES; i++) {
			rc = msix_trigger_unregister(vidxd, i);
			if (rc < 0)
				return rc;
		}
		return 0;
	}

	for (i = 0; i < count; i++) {
		if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
			u32 fd = *(u32 *)(data + i * sizeof(u32));

			rc = msix_trigger_register(vidxd, fd, i);
			if (rc < 0)
				return rc;
		} else if (flags & VFIO_IRQ_SET_DATA_NONE) {
			rc = msix_trigger_unregister(vidxd, i);
			if (rc < 0)
				return rc;
		}
	}
	return rc;
}

static int idxd_vdcm_set_irqs(struct vdcm_idxd *vidxd, uint32_t flags,
			      unsigned int index, unsigned int start,
			      unsigned int count, void *data)
{
	int (*func)(struct vdcm_idxd *vidxd, unsigned int index,
		    unsigned int start, unsigned int count, uint32_t flags,
		    void *data) = NULL;
	struct mdev_device *mdev = vidxd->vdev.mdev;
	struct device *dev = mdev_dev(mdev);

	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		dev_warn(dev, "intx interrupts not supported.\n");
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		dev_dbg(dev, "msi interrupt.\n");
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_idxd_set_msix_trigger;
			break;
		}
		break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_idxd_set_msix_trigger;
			break;
		}
		break;
	default:
		return -ENOTTY;
	}

	if (!func)
		return -ENOTTY;

	return func(vidxd, index, start, count, flags, data);
}

static void vidxd_vdcm_reset(struct vdcm_idxd *vidxd)
{
	vidxd_reset(vidxd);
}

static long idxd_vdcm_ioctl(struct mdev_device *mdev, unsigned int cmd,
			    unsigned long arg)
{
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	unsigned long minsz;
	int rc = -EINVAL;
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "vidxd %p ioctl, cmd: %d\n", vidxd, cmd);

	mutex_lock(&vidxd->dev_lock);
	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz) {
			rc = -EINVAL;
			goto out;
		}

		info.flags = VFIO_DEVICE_FLAGS_PCI;
		info.flags |= VFIO_DEVICE_FLAGS_RESET;
		info.num_regions = VFIO_PCI_NUM_REGIONS;
		info.num_irqs = VFIO_PCI_NUM_IRQS;

		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct vfio_region_info info;
		struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
		struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
		size_t size;
		int nr_areas = 1;
		int cap_type_id = 0;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz) {
			rc = -EINVAL;
			goto out;
		}

		switch (info.index) {
		case VFIO_PCI_CONFIG_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = VIDXD_MAX_CFG_SPACE_SZ;
			info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR0_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = vidxd->bar_size[info.index];
			if (!info.size) {
				info.flags = 0;
				break;
			}

			info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR1_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;
			info.flags = 0;
			break;
		case VFIO_PCI_BAR2_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.flags = VFIO_REGION_INFO_FLAG_CAPS | VFIO_REGION_INFO_FLAG_MMAP |
				     VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			info.size = vidxd->bar_size[1];

			/*
			 * Every WQ has two areas for unlimited and limited
			 * MSI-X portals. IMS portals are not reported
			 */
			nr_areas = 2;

			size = sizeof(*sparse) + (nr_areas * sizeof(*sparse->areas));
			sparse = kzalloc(size, GFP_KERNEL);
			if (!sparse) {
				rc = -ENOMEM;
				goto out;
			}

			sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
			sparse->header.version = 1;
			sparse->nr_areas = nr_areas;
			cap_type_id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;

			/* Unlimited portal */
			sparse->areas[0].offset = 0;
			sparse->areas[0].size = PAGE_SIZE;

			/* Limited portal */
			sparse->areas[1].offset = PAGE_SIZE;
			sparse->areas[1].size = PAGE_SIZE;
			break;

		case VFIO_PCI_BAR3_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;
			info.flags = 0;
			dev_dbg(dev, "get region info bar:%d\n", info.index);
			break;

		case VFIO_PCI_ROM_REGION_INDEX:
		case VFIO_PCI_VGA_REGION_INDEX:
			dev_dbg(dev, "get region info index:%d\n", info.index);
			break;
		default: {
			if (info.index >= VFIO_PCI_NUM_REGIONS)
				rc = -EINVAL;
			else
				rc = 0;
			goto out;
		} /* default */
		} /* info.index switch */

		if ((info.flags & VFIO_REGION_INFO_FLAG_CAPS) && sparse) {
			if (cap_type_id == VFIO_REGION_INFO_CAP_SPARSE_MMAP) {
				rc = vfio_info_add_capability(&caps, &sparse->header,
							      sizeof(*sparse) + (sparse->nr_areas *
							      sizeof(*sparse->areas)));
				kfree(sparse);
				if (rc)
					goto out;
			}
		}

		if (caps.size) {
			if (info.argsz < sizeof(info) + caps.size) {
				info.argsz = sizeof(info) + caps.size;
				info.cap_offset = 0;
			} else {
				vfio_info_cap_shift(&caps, sizeof(info));
				if (copy_to_user((void __user *)arg + sizeof(info),
						 caps.buf, caps.size)) {
					kfree(caps.buf);
					rc = -EFAULT;
					goto out;
				}
				info.cap_offset = sizeof(info);
			}

			kfree(caps.buf);
		}
		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS) {
			rc = -EINVAL;
			goto out;
		}

		switch (info.index) {
		case VFIO_PCI_MSI_IRQ_INDEX:
		case VFIO_PCI_MSIX_IRQ_INDEX:
		default:
			rc = -EINVAL;
			goto out;
		} /* switch(info.index) */

		info.flags = VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE;
		info.count = idxd_vdcm_get_irq_count(vidxd, info.index);

		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
			int max = idxd_vdcm_get_irq_count(vidxd, hdr.index);

			rc = vfio_set_irqs_validate_and_prepare(&hdr, max, VFIO_PCI_NUM_IRQS,
								&data_size);
			if (rc) {
				dev_err(dev, "intel:vfio_set_irqs_validate_and_prepare failed\n");
				rc = -EINVAL;
				goto out;
			}
			if (data_size) {
				data = memdup_user((void __user *)(arg + minsz), data_size);
				if (IS_ERR(data)) {
					rc = PTR_ERR(data);
					goto out;
				}
			}
		}

		if (!data) {
			rc = -EINVAL;
			goto out;
		}

		rc = idxd_vdcm_set_irqs(vidxd, hdr.flags, hdr.index, hdr.start, hdr.count, data);
		kfree(data);
		goto out;
	} else if (cmd == VFIO_DEVICE_RESET) {
		vidxd_vdcm_reset(vidxd);
	}

 out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vdcm_idxd_type *type;

	type = idxd_vdcm_find_vidxd_type(dev, kobject_name(kobj));

	if (type)
		return sprintf(buf, "%s\n", type->name);

	return -EINVAL;
}
static MDEV_TYPE_ATTR_RO(name);

static int find_available_mdev_instances(struct idxd_device *idxd, struct vdcm_idxd_type *type)
{
	int count = 0, i;
	unsigned long flags;

	switch (type->type) {
	case IDXD_MDEV_TYPE_DSA_1_DWQ:
		if (idxd->type != IDXD_TYPE_DSA)
			return 0;
		break;
	case IDXD_MDEV_TYPE_IAX_1_DWQ:
		if (idxd->type != IDXD_TYPE_IAX)
			return 0;
		break;
	default:
		return 0;
	}

	spin_lock_irqsave(&idxd->dev_lock, flags);
	for (i = 0; i < idxd->max_wqs; i++) {
		struct idxd_wq *wq;

		wq = &idxd->wqs[i];
		if (!is_idxd_wq_mdev(wq) || !wq_dedicated(wq) || idxd_wq_refcount(wq))
			continue;

		count++;
	}
	spin_unlock_irqrestore(&idxd->dev_lock, flags);

	return count;
}

static ssize_t available_instances_show(struct kobject *kobj,
					struct device *dev, char *buf)
{
	int count;
	struct idxd_device *idxd = dev_get_drvdata(dev);
	struct vdcm_idxd_type *type;

	type = idxd_vdcm_find_vidxd_type(dev, kobject_name(kobj));
	if (!type)
		return -EINVAL;

	count = find_available_mdev_instances(idxd, type);

	return sprintf(buf, "%d\n", count);
}
static MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *idxd_mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group idxd_mdev_type_dsa_group0 = {
	.name = idxd_dsa_1dwq_name,
	.attrs = idxd_mdev_types_attrs,
};

static struct attribute_group idxd_mdev_type_iax_group0 = {
	.name = idxd_iax_1dwq_name,
	.attrs = idxd_mdev_types_attrs,
};

static struct mdev_parent_ops idxd_vdcm_ops = {
	.create			= idxd_vdcm_create,
	.remove			= idxd_vdcm_remove,
	.open			= idxd_vdcm_open,
	.release		= idxd_vdcm_release,
	.read			= idxd_vdcm_read,
	.write			= idxd_vdcm_write,
	.mmap			= idxd_vdcm_mmap,
	.ioctl			= idxd_vdcm_ioctl,
};

/* Set the mdev type version to the hardware version supported */
static void init_mdev_1dwq_name(struct idxd_device *idxd)
{
	unsigned int version;

	version = (idxd->hw.version & GENMASK(15, 8)) >> 8;
	if (idxd->type == IDXD_TYPE_DSA && strlen(idxd_dsa_1dwq_name) == 0)
		sprintf(idxd_dsa_1dwq_name, "dsa-1dwq-v%u", version);
	else if (idxd->type == IDXD_TYPE_IAX && strlen(idxd_iax_1dwq_name) == 0)
		sprintf(idxd_iax_1dwq_name, "iax-1dwq-v%u", version);
}

static int alloc_supported_types(struct idxd_device *idxd)
{
	struct attribute_group **idxd_mdev_type_groups;

	idxd_mdev_type_groups = kcalloc(2, sizeof(struct attribute_group *), GFP_KERNEL);
	if (!idxd_mdev_type_groups)
		return -ENOMEM;

	switch (idxd->type) {
	case IDXD_TYPE_DSA:
		idxd_mdev_type_groups[0] = &idxd_mdev_type_dsa_group0;
		break;
	case IDXD_TYPE_IAX:
		idxd_mdev_type_groups[0] = &idxd_mdev_type_iax_group0;
		break;
	case IDXD_TYPE_UNKNOWN:
	default:
		return -ENODEV;
	}

	idxd_vdcm_ops.supported_type_groups = idxd_mdev_type_groups;

	return 0;
}

int idxd_mdev_host_init(struct idxd_device *idxd)
{
	struct device *dev = &idxd->pdev->dev;
	int rc;

	if (!test_bit(IDXD_FLAG_SIOV_SUPPORTED, &idxd->flags))
		return -EOPNOTSUPP;

	init_mdev_1dwq_name(idxd);
	rc = alloc_supported_types(idxd);
	if (rc < 0)
		return rc;

	if (iommu_dev_has_feature(dev, IOMMU_DEV_FEAT_AUX)) {
		rc = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_AUX);
		if (rc < 0) {
			dev_warn(dev, "Failed to enable aux-domain: %d\n", rc);
			return rc;
		}
	} else {
		dev_warn(dev, "No aux-domain feature.\n");
		return -EOPNOTSUPP;
	}

	return mdev_register_device(dev, &idxd_vdcm_ops);
}

void idxd_mdev_host_release(struct idxd_device *idxd)
{
	struct device *dev = &idxd->pdev->dev;
	int rc;

	mdev_unregister_device(dev);
	if (iommu_dev_has_feature(dev, IOMMU_DEV_FEAT_AUX)) {
		rc = iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		if (rc < 0)
			dev_warn(dev, "Failed to disable aux-domain: %d\n",
				 rc);
	}

	kfree(idxd_vdcm_ops.supported_type_groups);
	idxd_vdcm_ops.supported_type_groups = NULL;
}

static int idxd_mdev_aux_probe(struct auxiliary_device *auxdev,
			       const struct auxiliary_device_id *id)
{
	struct idxd_device *idxd = auxdev_to_idxd(auxdev);
	int rc;

	rc = idxd_mdev_host_init(idxd);
	if (rc < 0) {
		dev_warn(&auxdev->dev, "mdev host init failed: %d\n", rc);
		return rc;
	}

	set_bit(IDXD_FLAG_MDEV_ENABLED, &idxd->flags);
	return 0;
}

static int idxd_mdev_aux_remove(struct auxiliary_device *auxdev)
{
	struct idxd_device *idxd = auxdev_to_idxd(auxdev);

	clear_bit(IDXD_FLAG_MDEV_ENABLED, &idxd->flags);
	idxd_mdev_host_release(idxd);
	return 0;
}

static void idxd_mdev_aux_shutdown(struct auxiliary_device *auxdev)
{
}

static const struct auxiliary_device_id idxd_mdev_auxbus_id_table[] = {
	{ .name = "idxd.mdev" },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, idxd_mdev_auxbus_id_table);

static struct idxd_mdev_aux_drv idxd_mdev_aux_drv = {
	.auxiliary_drv = {
		.id_table = idxd_mdev_auxbus_id_table,
		.probe = idxd_mdev_aux_probe,
		.remove = idxd_mdev_aux_remove,
		.shutdown = idxd_mdev_aux_shutdown,
	},
};

static int idxd_mdev_auxdev_drv_register(struct idxd_mdev_aux_drv *drv)
{
	return auxiliary_driver_register(&drv->auxiliary_drv);
}

static void idxd_mdev_auxdev_drv_unregister(struct idxd_mdev_aux_drv *drv)
{
	auxiliary_driver_unregister(&drv->auxiliary_drv);
}

module_driver(idxd_mdev_aux_drv, idxd_mdev_auxdev_drv_register, idxd_mdev_auxdev_drv_unregister);
MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
