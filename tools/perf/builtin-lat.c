#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/cache.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"
#include "util/session.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"

static char			const *input_name		= "perf.data";
static int			latency_value			= 3;

static const char * const lat_usage[] = {
	"perf lat [<options>] {record|report}",
	NULL
};

static const struct option lat_options[] = {
	OPT_INTEGER('L', "latency", &latency_value, "latency to sample"),
	OPT_END()
};

static int __cmd_record(int argc, const char **argv)
{
	int rec_argc, i = 0, j;
	const char **rec_argv;
	char event[] = "r100b:xxxx:p";

	rec_argc = argc + 4;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));
	rec_argv[i++] = strdup("record");
	rec_argv[i++] = strdup("-l");
	rec_argv[i++] = strdup("-d");
	rec_argv[i++] = strdup("-e");
	snprintf(event, strlen(event) + 1, "r100b:%04x:p", latency_value);
	rec_argv[i++] = strdup(event);
	for (j = 1; j < argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

#define LEN 56
struct perf_latency_data_source {
	char name[LEN];
	u64 count;
	u64 latency;
};

struct perf_latency_address {
	struct rb_node rb_node;
	u64 addr;
	u64 count;
	u64 latency;
};

struct rb_root addr_entries;

static struct perf_latency_data_source latency_data[7][4][4] = {
 [LD_LAT_L1] = {
	[LD_LAT_LOCAL >> 2] = {
		[LD_LAT_MODIFIED >> 4] = {
			"L1-local", 0, 0
		},
	},
 },
 [LD_LAT_L2] = {
	[LD_LAT_SNOOP >> 2] = {
		[LD_LAT_MODIFIED >> 4] = {
			"L2-snoop", 0, 0
		},
	},
	[LD_LAT_LOCAL >> 2] = {
		[LD_LAT_MODIFIED >> 4] = {
			"L2-local", 0, 0
		},
	},
 },
 [LD_LAT_L3] = {
	[LD_LAT_SNOOP >> 2] = {
		[LD_LAT_MODIFIED >> 4] = {
			"L3-snoop, found M", 0, 0
		},
		[LD_LAT_SHARED >> 4] = {
			"L3-snoop, found no M", 0, 0
		},
		[LD_LAT_INVALID >> 4] = {
			"L3-snoop, no coherency actions", 0, 0
		},
	},
 },
 [LD_LAT_RAM] = {
	[LD_LAT_SNOOP >> 2] = {
		[LD_LAT_SHARED >> 4] = {
			"L3-miss, snoop, shared", 0, 0
		},
	},
	[LD_LAT_LOCAL >> 2] = {
		[LD_LAT_EXCLUSIVE >> 4] = {
			"L3-miss, local, exclusive", 0, 0
		},
		[LD_LAT_SHARED >> 4] = {
			"L3-miss, local, shared", 0, 0
		},
	},
	[LD_LAT_REMOTE >> 2] = {
		[LD_LAT_EXCLUSIVE >> 4] = {
			"L3-miss, remote, exclusive", 0, 0
		},
		[LD_LAT_SHARED >> 4] = {
			"L3-miss, remote, shared", 0, 0
		},
	},
 },
 [LD_LAT_UNKNOWN + 4] = {
	[LD_LAT_TOGGLE] = {
		[0] = {
			"Unknown L3", 0, 0
		},
	},
 },
 [LD_LAT_IO + 4] = {
	[LD_LAT_TOGGLE] = {
		[0] = {
			"IO", 0, 0
		},
	},
 },
 [LD_LAT_UNCACHED + 4] = {
	[LD_LAT_TOGGLE] = {
		[0] = {
			"Uncached", 0, 0
		},
	},
 },
};

static void output_resort_insert(struct rb_root *entries,
		struct perf_latency_address *entry)
{
	struct rb_node **p = &entries->rb_node;
	struct rb_node *parent = NULL;
	struct perf_latency_address *lat_entry;

	while (*p != NULL) {
		parent = *p;
		lat_entry = rb_entry(parent, struct perf_latency_address, rb_node);

		if(entry->latency > lat_entry->latency)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&entry->rb_node, parent, p);
	rb_insert_color(&entry->rb_node, entries);
}
static void output_resort(struct rb_root *entries)
{
	struct rb_root tmp;
	struct rb_node *next;
	struct perf_latency_address *entry;

	tmp = RB_ROOT;
	next = rb_first(entries);

	while (next) {
		entry = rb_entry(next, struct perf_latency_address, rb_node);
		next = rb_next(&entry->rb_node);

		rb_erase(&entry->rb_node, entries);
		output_resort_insert(&tmp, entry);
	}

	*entries = tmp;
}

static void dump_latency_data(void)
{
	struct perf_latency_address *lat_entry;
	struct rb_node *next;
	int i, j, k;

	printf("Data source statistics\n========================\n");
	for (i = 0; i < 7; i++)
		for (j = 0; j < 4; j++)
			for (k = 0; k < 4; k++) {
				if (!latency_data[i][j][k].name[0])
					continue;
				printf("%30s: total latency=%8ld, count=%8ld (avg=%ld)\n",
					latency_data[i][j][k].name,
					latency_data[i][j][k].latency,
					latency_data[i][j][k].count,
					latency_data[i][j][k].count ?
					(latency_data[i][j][k].latency /
					latency_data[i][j][k].count) : 0);
			}

	printf("\nData linear address statistics\n=================================\n");

	output_resort(&addr_entries);

	next = rb_first(&addr_entries);
	while (next) {
		lat_entry = rb_entry(next, struct perf_latency_address, rb_node);
		printf("%30lx: total latency=%8ld, count=%8ld (avg=%ld)\n",
			lat_entry->addr, lat_entry->latency, lat_entry->count,
			lat_entry->latency / lat_entry->count);

		next = rb_next(&lat_entry->rb_node);
	}
}

static void add_entry(u64 addr, u64 latency)
{
	struct rb_node **p = &addr_entries.rb_node;
	struct rb_node *parent = NULL;
	struct perf_latency_address *lat_entry;

	while (*p != NULL) {
		parent = *p;
		lat_entry = rb_entry(parent, struct perf_latency_address, rb_node);

		if (addr == lat_entry->addr) {
			lat_entry->count++;
			lat_entry->latency += latency;
			return;
		}
		else if(addr < lat_entry->addr)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	lat_entry = malloc(sizeof(*lat_entry));
	if (!lat_entry)
		return;

	rb_link_node(&lat_entry->rb_node, parent, p);
	rb_insert_color(&lat_entry->rb_node, &addr_entries);
	lat_entry->addr = addr;
	lat_entry->count = 1;
	lat_entry->latency = latency;

	return;
}

static int process_sample_event(union perf_event *event __unused, struct perf_sample *sample,
                                struct perf_evsel *evsel __unused, struct perf_session *session __unused)
{
	u64 latency;
	u64 extra;
	int i, j, k;

	latency = sample->latency;
	extra = sample->extra;

	i = extra & 0x3;
	j = (extra >> 2) & 0x3;
	k = (extra >> 4) & 0x3;

	if (j == 0)
		i += 4;

	latency_data[i][j][k].latency += latency;
	latency_data[i][j][k].count++;

	add_entry(sample->addr, latency);

	return 0;
}

static struct perf_event_ops event_ops = {
	.sample			= process_sample_event,
	.mmap			= perf_event__process_mmap,
	.comm			= perf_event__process_comm,
	.lost			= perf_event__process_lost,
	.fork			= perf_event__process_task,
	.ordered_samples	= true,
};

static int report_events(void)
{
	int err = -EINVAL;
	struct perf_session *session = perf_session__new(input_name, O_RDONLY,
							 0, false, &event_ops);

	if (symbol__init() < 0)
		return -1;

	if (session == NULL)
		return -ENOMEM;

	err = perf_session__process_events(session, &event_ops);

	dump_latency_data();

	perf_session__delete(session);
	return err;
}

int cmd_lat(int argc, const char **argv, const char *prefix __used)
{
	argc = parse_options(argc, argv, lat_options, lat_usage,
                        PARSE_OPT_STOP_AT_NON_OPTION);

	if (!argc)
		usage_with_options(lat_usage, lat_options);

        if (!strncmp(argv[0], "rec", 3))
		return __cmd_record(argc, argv);
	else if (!strncmp(argv[0], "rep", 3))
		return report_events();
	else
		usage_with_options(lat_usage, lat_options);

	return 0;
}
