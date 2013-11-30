/*
 * Copyright 2012 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs
 */

#include <subdev/mc.h>
#include <core/option.h>

static irqreturn_t
nouveau_mc_intr(int irq, void *arg)
{
	struct nouveau_mc *pmc = arg;
	const struct nouveau_mc_intr *map = pmc->intr_map;
	struct nouveau_device *device = nv_device(pmc);
	struct nouveau_subdev *unit;
	u32 stat, intr;

	intr = stat = nv_rd32(pmc, 0x000100);
	if (intr == 0xffffffff)
		return IRQ_NONE;
	while (stat && map->stat) {
		if (stat & map->stat) {
			unit = nouveau_subdev(pmc, map->unit);
			if (unit && unit->intr)
				unit->intr(unit);
			intr &= ~map->stat;
		}
		map++;
	}

	if (pmc->use_msi)
		nv_wr08(pmc->base.base.parent, 0x00088068, 0xff);

	if (intr) {
		nv_error(pmc, "unknown intr 0x%08x\n", stat);
	}

	if (stat == IRQ_HANDLED)
		pm_runtime_mark_last_busy(&device->pdev->dev);
	return stat ? IRQ_HANDLED : IRQ_NONE;
}

int
_nouveau_mc_fini(struct nouveau_object *object, bool suspend)
{
	struct nouveau_mc *pmc = (void *)object;
	nv_wr32(pmc, 0x000140, 0x00000000);
	return nouveau_subdev_fini(&pmc->base, suspend);
}

int
_nouveau_mc_init(struct nouveau_object *object)
{
	struct nouveau_mc *pmc = (void *)object;
	int ret = nouveau_subdev_init(&pmc->base);
	if (ret)
		return ret;
	nv_wr32(pmc, 0x000140, 0x00000001);
	return 0;
}

void
_nouveau_mc_dtor(struct nouveau_object *object)
{
	struct nouveau_device *device = nv_device(object);
	struct nouveau_mc *pmc = (void *)object;
	free_irq(device->pdev->irq, pmc);
	if (pmc->use_msi)
		pci_disable_msi(device->pdev);
	nouveau_subdev_destroy(&pmc->base);
}

int
nouveau_mc_create_(struct nouveau_object *parent, struct nouveau_object *engine,
		   struct nouveau_oclass *oclass,
		   const struct nouveau_mc_intr *intr_map,
		   int length, void **pobject)
{
	struct nouveau_device *device = nv_device(parent);
	struct nouveau_mc *pmc;
	int ret;

	ret = nouveau_subdev_create_(parent, engine, oclass, 0, "PMC",
				     "master", length, pobject);
	pmc = *pobject;
	if (ret)
		return ret;

	pmc->intr_map = intr_map;

	switch (device->pdev->device & 0x0ff0) {
	case 0x00f0: /* BR02? */
	case 0x02e0: /* BR02? */
		pmc->use_msi = false;
		break;
	default:
		pmc->use_msi = nouveau_boolopt(device->cfgopt, "NvMSI", false);
		if (pmc->use_msi) {
			pmc->use_msi = pci_enable_msi(device->pdev) == 0;
			if (pmc->use_msi) {
				nv_info(pmc, "MSI interrupts enabled\n");
				nv_wr08(device, 0x00088068, 0xff);
			}
		}
		break;
	}

	ret = request_irq(device->pdev->irq, nouveau_mc_intr,
			  IRQF_SHARED, "nouveau", pmc);
	if (ret < 0)
		return ret;

	return 0;
}
