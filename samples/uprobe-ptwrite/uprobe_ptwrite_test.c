// SPDX-License-Identifier: GPL-2.0-only
/*
 * uprobe_ptwrite_test - minimal ptwrite uprobe prototype driver.
 *
 * Registers a trap-free ptwrite uprobe at a user-specified file offset and
 * emits the requested live registers / immediates into an externally
 * configured Intel PT stream (no kernel entry at probe-hit time):
 *
 *   perf record -e intel_pt/ptw=1,fup_on_ptw=1//u -o perf.data ./test_prog
 *
 * Usage (module params):
 *   path=/path/to/prog   file to probe
 *   offset=0xADDR        file offset of the probe site
 *   args="r0,r1,i0x42"             comma-separated;
 *                        r<N> = x86-64 GPR index 0..15,
 *                        i<hex> = immediate constant,
 *   event_id=0x1234      identifier carried in the PTW header word
 */
#include <linux/module.h>
#include <linux/uprobes.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>

static char *path = "/nonexistent";
module_param(path, charp, 0444);
MODULE_PARM_DESC(path, "path of the binary to probe");

static ulong offset;
module_param(offset, ulong, 0444);
MODULE_PARM_DESC(offset, "file offset of the 5-byte NOP to probe");

static ushort event_id = 0x1234;
module_param(event_id, ushort, 0444);
MODULE_PARM_DESC(event_id, "event id carried in the PTW header word");

static char *args = "r0";
module_param(args, charp, 0444);
MODULE_PARM_DESC(args, "comma-separated args: r<N> GPR, i<hex> immediate, m<N>[:disp][:4|8] memory");

static struct file *probe_file;
static struct uprobe *probe;
static struct uprobe_consumer consumer;
static struct uprobe_ptwrite_desc desc;

/* Never invoked: ptwrite probes do not trap. Satisfies the core contract. */
static int noop_handler(struct uprobe_consumer *self, struct pt_regs *regs,
			__u64 *data)
{
	return 0;
}

static int parse_probe_args(void)
{
	char *s, *p, *tok;
	unsigned int n = 0;

	s = kstrdup(args, GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	p = s;
	while ((tok = strsep(&p, ",")) != NULL) {
		struct uprobe_ptwrite_arg *a;

		if (n >= UPROBE_PTWRITE_MAX_ARGS) {
			pr_err("uprobe_ptwrite_test: too many args\n");
			goto err;
		}
		a = &desc.args[n];

		a->size = 8;
		if (tok[0] == 'r') {
			unsigned long reg;

			if (kstrtoul(tok + 1, 10, &reg) || reg > 15) {
				pr_err("uprobe_ptwrite_test: bad reg '%s'\n", tok);
				goto err;
			}
			a->src = UPROBE_PTW_SRC_REG;
			a->reg = reg;
		} else if (tok[0] == 'i') {
			unsigned long long v;

			if (kstrtoull(tok + 1, 0, &v)) {
				pr_err("uprobe_ptwrite_test: bad imm '%s'\n", tok);
				goto err;
			}
			a->src = UPROBE_PTW_SRC_IMM;
			a->val = v;
		} else {
			pr_err("uprobe_ptwrite_test: bad arg '%s'\n", tok);
			goto err;
		}
		n++;
	}
	if (!n || n > UPROBE_PTWRITE_MAX_ARGS) {
		pr_err("uprobe_ptwrite_test: need 1..%d args\n",
		       UPROBE_PTWRITE_MAX_ARGS);
		goto err;
	}
	desc.nargs = n;
	kfree(s);
	return 0;
err:
	kfree(s);
	return -EINVAL;
}

static int __init uprobe_ptwrite_test_init(void)
{
	struct inode *inode;
	int ret;

	desc.event_id = event_id;
	ret = parse_probe_args();
	if (ret)
		return ret;

	probe_file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(probe_file))
		return PTR_ERR(probe_file);

	inode = file_inode(probe_file);
	if (!inode->i_mapping->a_ops->read_folio &&
	    !shmem_mapping(inode->i_mapping)) {
		pr_err("uprobe_ptwrite_test: unsupported mapping\n");
		ret = -EIO;
		goto out_file;
	}

	consumer.handler = noop_handler;
	consumer.ret_handler = NULL;
	consumer.filter = NULL;

	probe = uprobe_register_ptwrite(inode, probe_file, offset, &consumer, &desc);
	if (IS_ERR(probe)) {
		ret = PTR_ERR(probe);
		pr_err("uprobe_ptwrite_test: register failed: %d\n", ret);
		goto out_file;
	}

	pr_info("uprobe_ptwrite_test: probe %s+0x%lx, %u args, event_id=0x%x\n",
		path, offset, desc.nargs, desc.event_id);
	return 0;

out_file:
	fput(probe_file);
	return ret;
}

static void __exit uprobe_ptwrite_test_exit(void)
{
	uprobe_unregister_nosync(probe, &consumer);
	uprobe_unregister_sync();
	fput(probe_file);
	pr_info("uprobe_ptwrite_test: unregistered\n");
}

module_init(uprobe_ptwrite_test_init);
module_exit(uprobe_ptwrite_test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ptwrite uprobes testing driver");
