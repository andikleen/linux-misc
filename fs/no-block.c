/* no-block.c: implementation of routines required for non-BLOCK configuration
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/fs.h>

static int no_blkdev_open(struct inode * inode, struct file * filp)
{
	return -ENODEV;
}

const struct file_operations def_blk_fops = {
	.open		= no_blkdev_open,
	.llseek		= noop_llseek,
};

struct bio *bio_alloc(gfp_t gfp_mask, int nr_iovecs)
{
	return NULL;
}
EXPORT_SYMBOL(bio_alloc);

void bio_put(struct bio *bio)
{
}
EXPORT_SYMBOL(bio_put);

void bio_endio(struct bio *bio, int error)
{
}
EXPORT_SYMBOL(bio_endio);

int bio_get_nr_vecs(struct block_device *bdev)
{
	return 0;
}
EXPORT_SYMBOL(bio_get_nr_vecs);

void bio_check_pages_dirty(struct bio *bio)
{
}
EXPORT_SYMBOL(bio_check_pages_dirty);

void bio_set_pages_dirty(struct bio *bio)
{
}
EXPORT_SYMBOL(bio_set_pages_dirty);
