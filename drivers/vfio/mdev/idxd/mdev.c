// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/auxiliary_bus.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "mdev.h"

static int idxd_mdev_host_init(struct idxd_device *idxd)
{
	/* FIXME: Fill in later */
	return 0;
}

static int idxd_mdev_host_release(struct idxd_device *idxd)
{
	/* FIXME: Fill in later */
	return 0;
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

	return 0;
}

static int idxd_mdev_aux_remove(struct auxiliary_device *auxdev)
{
	struct idxd_device *idxd = auxdev_to_idxd(auxdev);

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

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
