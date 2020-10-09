/*
 * Copyright (c) 2013-2020, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "lib/load_elf.h"
#include "lib/intel-pt.h"

#include <stdio.h>
#include <elf.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

static int elf_load_offset32(FILE *file, uint64_t base, uint64_t *offset,
		      const char *name, const char *prog)
{
	Elf32_Ehdr ehdr;
	Elf32_Half pidx;
	size_t count;
	int errcode, sections;

	errcode = fseek(file, 0, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(&ehdr, sizeof(ehdr), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s error reading ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	errcode = fseek(file, (long) ehdr.e_phoff, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking program header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	/* Determine the load offset. */
	if (!base)
		*offset = 0;
	else {
		uint64_t minaddr;

		minaddr = UINT64_MAX;

		for (pidx = 0; pidx < ehdr.e_phnum; ++pidx) {
			Elf32_Phdr phdr;

			count = fread(&phdr, sizeof(phdr), 1, file);
			if (count != 1) {
				fprintf(stderr,
					"%s: warning: %s error reading "
					"phdr %u: %s.\n",
					prog, name, pidx, strerror(errno));
				return -pte_bad_config;
			}

			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;

			if (phdr.p_vaddr < minaddr)
				minaddr = phdr.p_vaddr;
		}

		*offset = base - minaddr;
	}

	return 0;
}

static int elf_load_offset64(FILE *file, uint64_t base, uint64_t *offset,
		      const char *name, const char *prog)
{
	Elf64_Ehdr ehdr;
	Elf64_Half pidx;
	size_t count;
	int errcode, sections;

	errcode = fseek(file, 0, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(&ehdr, sizeof(ehdr), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s error reading ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	if (LONG_MAX < ehdr.e_phoff) {
		fprintf(stderr, "%s: warning: %s ELF header too big.\n",
			prog, name);
		return -pte_bad_config;
	}

	errcode = fseek(file, (long) ehdr.e_phoff, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking program header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	/* Determine the load offset. */
	if (!base)
		*offset = 0;
	else {
		uint64_t minaddr;

		minaddr = UINT64_MAX;

		for (pidx = 0; pidx < ehdr.e_phnum; ++pidx) {
			Elf64_Phdr phdr;

			count = fread(&phdr, sizeof(phdr), 1, file);
			if (count != 1) {
				fprintf(stderr,
					"%s: warning: %s error reading "
					"phdr %u: %s.\n",
					prog, name, pidx, strerror(errno));
				return -pte_bad_config;
			}

			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;

			if (phdr.p_vaddr < minaddr)
				minaddr = phdr.p_vaddr;

		}

		*offset = base - minaddr;
	}

	return 0;
}

int elf_load_offset(const char *name, uint64_t base, uint64_t *offset, const char *prog)
{
	uint8_t e_ident[EI_NIDENT];
	FILE *file;
	size_t count;
	int errcode, idx;

	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "%s: warning: failed to open %s: %s.\n", prog,
			name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(e_ident, sizeof(e_ident), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s failed to read file header: %s.\n",
			prog, name, strerror(errno));

		errcode = -pte_bad_config;
		goto out;
	}

	for (idx = 0; idx < SELFMAG; ++idx) {
		if (e_ident[idx] != ELFMAG[idx]) {
			fprintf(stderr,
				"%s: warning: ignoring %s: not an ELF file.\n",
				prog, name);

			errcode = -pte_bad_config;
			goto out;
		}
	}

	switch (e_ident[EI_CLASS]) {
	default:
		fprintf(stderr, "%s: unsupported ELF class: %d\n",
			prog, e_ident[EI_CLASS]);
		errcode =  -pte_bad_config;
		break;

	case ELFCLASS32:
		errcode = elf_load_offset32(file, base, offset, name, prog);
		break;

	case ELFCLASS64:
		errcode = elf_load_offset64(file, base, offset, name, prog);
		break;
	}

out:
	fclose(file);
	return errcode;
}
