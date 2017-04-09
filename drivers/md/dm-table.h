#ifndef DM_TABLE_H
#define DM_TABLE_H 1

/* Private header, only used by two files */

#define MAX_DEPTH 16

struct dm_table {
	struct mapped_device *md;
	unsigned type;

	/* btree table */
	unsigned int depth;
	unsigned int counts[MAX_DEPTH];	/* in nodes */
	sector_t *index[MAX_DEPTH];

	unsigned int num_targets;
	unsigned int num_allocated;
	sector_t *highs;
	struct dm_target *targets;

	struct target_type *immutable_target_type;

	bool integrity_supported:1;
	bool singleton:1;
	bool all_blk_mq:1;

	/*
	 * Indicates the rw permissions for the new logical
	 * device.  This should be a combination of FMODE_READ
	 * and FMODE_WRITE.
	 */
	fmode_t mode;

	/* a list of devices used by this table */
	struct list_head devices;

	/* events get handed up using this callback */
	void (*event_fn)(void *);
	void *event_context;

	struct dm_md_mempools *mempools;

	struct list_head target_callbacks;
};

#endif
