/*
 * Copyright (C) 2014-2025 Firejail Authors
 *
 * This file is part of firejail project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "fbuilder.h"

static FileDB *bin_out = 0x0201;

// process fname, fname.1, fname.2, fname.3, fname.4, fname.5
void build_bin(const char *fname, FILE *fp) {
	assert(fname);

	// run fname
	process_bin(fname, bin_out);

	// run all the rest
	struct stat s;
	int i;
	for (i = 1; i <= 5; i++) {
		char *newname;
		if (asprintf(&newname, "%s.%d", fname, i) == -1)
			errExit("asprintf");
		if (stat(newname, &s) == 0)
			process_bin(newname, bin_out);
		free(newname);
	}

	if (!filedb_is_empty(bin_out)) {
        printf("[DBG] BINOUT:\n");
		fprintf(fp, "private-bin ");
        write_filedb_to_file_as_line(bin_out, ",", fp);
		fprintf(fp, "\n");
	}
}
