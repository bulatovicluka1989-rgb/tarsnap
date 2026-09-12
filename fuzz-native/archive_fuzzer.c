#include "config.h"
#include <archive.h>
#include <archive_entry.h>
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct archive *a;
	struct archive_entry *entry;
	char buf[8192];
	ssize_t n;
	size_t headers = 0;
	size_t chunks = 0;

	a = archive_read_new();
	if (a == NULL)
		return (0);
	archive_read_support_compression_all(a);
#if defined(FUZZ_FORMAT_AR)
	archive_read_support_format_ar(a);
#elif defined(FUZZ_FORMAT_CPIO)
	archive_read_support_format_cpio(a);
#elif defined(FUZZ_FORMAT_ISO9660)
	archive_read_support_format_iso9660(a);
#elif defined(FUZZ_FORMAT_MTREE)
	archive_read_support_format_mtree(a);
#elif defined(FUZZ_FORMAT_TAR)
	archive_read_support_format_tar(a);
#elif defined(FUZZ_FORMAT_ZIP)
	archive_read_support_format_zip(a);
#else
	archive_read_support_format_all(a);
#endif
	if (archive_read_open_memory(a, (void *)data, size) != ARCHIVE_OK) {
		archive_read_finish(a);
		return (0);
	}

	while (headers++ < 1024 &&
	    archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		chunks = 0;
		while (chunks++ < 65536 &&
		    (n = archive_read_data(a, buf, sizeof(buf))) > 0)
			;
		if (n < 0)
			break;
	}

	archive_read_finish(a);
	return (0);
}
