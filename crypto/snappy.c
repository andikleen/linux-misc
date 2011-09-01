/*
 * Cryptographic API.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/snappy.h>

struct snappy_ctx {
	struct snappy_env env;
};

/* Only needed for compression actually */
static int snappy_init(struct crypto_tfm *tfm)
{
	struct snappy_ctx *ctx = crypto_tfm_ctx(tfm);

	return snappy_init_env(&ctx->env);
}

static void snappy_exit(struct crypto_tfm *tfm)
{
	struct snappy_ctx *ctx = crypto_tfm_ctx(tfm);

	snappy_free_env(&ctx->env);
}

static int snp_compress(struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct snappy_ctx *ctx = crypto_tfm_ctx(tfm);
	size_t olen;
	int err;

	/* XXXX very pessimistic. check in snappy? */
	if (*dlen < snappy_max_compressed_length(*dlen))
		return -EINVAL;
	err = snappy_compress(&ctx->env, src, slen, dst, &olen);
	*dlen = olen;
	return err;
}

static int snp_decompress(struct crypto_tfm *tfm, const u8 *src,
			      unsigned int slen, u8 *dst, unsigned int *dlen)
{
	size_t ulen;

	if (!snappy_uncompressed_length(src, slen, &ulen))
		return -EIO;
	if (*dlen < ulen)
		return -EINVAL;
	*dlen = ulen;
	return snappy_uncompress(src, slen, dst) ? 0 : -EIO;
}

static struct crypto_alg alg = {
	.cra_name		= "snappy",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct snappy_ctx),
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(alg.cra_list),
	.cra_init		= snappy_init,
	.cra_exit		= snappy_exit,
	.cra_u			= { .compress = {
	.coa_compress 		= snp_compress,
	.coa_decompress  	= snp_decompress } }
};

static int __init snappy_mod_init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit snappy_mod_fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(snappy_mod_init);
module_exit(snappy_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Snappy Compression Algorithm");
