/* Patch file at specific offset
 * patchfile file-to-patch offset patch-file [len-of-patch]
 */
#define _GNU_SOURCE 1
#include <sys/mman.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define ROUNDUP(x, y) (((x) + (y) - 1) & ~((y) - 1))

static void *mmapfile(char *file, size_t *size)
{
	int pagesize = sysconf(_SC_PAGESIZE);
	int fd = open(file, O_RDONLY);
	void *res = NULL;
	struct stat st;

	*size = 0;
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) >= 0) {
		*size = st.st_size;
		res = mmap(NULL, ROUNDUP(st.st_size, pagesize),
				PROT_READ, MAP_SHARED,
				fd, 0);
		if (res == (void *)-1)
			res = NULL;
	}
	close(fd);
	return res;
}

static void usage(void)
{
	fprintf(stderr, "Usage: patchfile file-to-patch offset file-to-patch-in\n");
	exit(1);
}

static size_t get_num(char *s)
{
	char *endp;
	size_t v = strtoul(s, &endp, 0);
	if (s == endp)
		usage();
	return v;
}

int main(int ac, char **av)
{
	char *patch;
	size_t patchsize;
	int infd;
	size_t offset;

	if (ac != 5 && ac != 4)
		usage();
	offset = get_num(av[2]);
	patch = mmapfile(av[3], &patchsize);
	if (av[4]) {
		size_t newsize = get_num(av[4]);
		if (newsize > patchsize)
			fprintf(stderr, "kallsyms: warning, size larger than patch\n");
		if (newsize < patchsize)
			patchsize = newsize;
	}
	infd = open(av[1], O_RDWR);
	if (infd < 0) {
		fprintf(stderr, "Cannot open %s\n", av[1]);
		exit(1);
	}
	if (pwrite(infd, patch, patchsize, offset) != patchsize) {
		fprintf(stderr, "Cannot write patch to %s\n", av[1]);
		exit(1);
	}
	close(infd);
	return 0;
}
