/* Test compiler warnings for alloc size. 
 * Only build if you want lots of warnings 
 */
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/kernel.h>

/* Should never be called because it will leak memory */
void test_alloc(void)
{
	unsigned long p;
	void *ptr;
	struct page *page;

	kmalloc(-1, GFP_KERNEL); /*  warning: argument 1 value '18446744073709551615' exceeds maximum object size 9223372036854775807 */

	ptr = kmalloc(100, GFP_KERNEL);
	ptr = krealloc(ptr, -1, GFP_KERNEL);
	ptr = kmalloc_node(-1, GFP_KERNEL, 0);
	ptr = kmalloc_array(-1, 100, GFP_KERNEL);
	ptr = kcalloc(100, -1, GFP_KERNEL);
	ptr = kzalloc(-1, GFP_KERNEL);
	ptr = kzalloc_node(-1, GFP_KERNEL, 0);

	page = __alloc_pages(GFP_KERNEL, -1, node_zonelist(0, GFP_KERNEL));
	page = alloc_pages_node(0, GFP_KERNEL, -1);
	page = alloc_pages_current(GFP_KERNEL, -1);
	page = alloc_pages(GFP_KERNEL, -100);
	/* not testing alloc_pages_vma */
	p = __get_free_pages(GFP_KERNEL, -1);
	p = __get_free_pages(GFP_KERNEL, 0);
	free_pages(p, -1);
	__free_pages(virt_to_page(p), -1);

}
