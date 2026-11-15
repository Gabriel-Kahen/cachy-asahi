/* SPDX-License-Identifier: MIT
 * Original bounded single-member gzip completeness test, not a gzip utility.
 * Only exit 2 means invalid input; resource, I/O and internal failures are 3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"
#define INPUT_CAP (16U * 1024U * 1024U)
#define OUTPUT_CAP (32U * 1024U * 1024U)
int main(void) {
    unsigned char *input = malloc(INPUT_CAP + 1U), output[16384];
    z_stream stream = {0};
    size_t size, total = 0;
    int status = 2, initialized = 0;
    if (!input || strcmp(zlibVersion(), ZLIB_VERSION) != 0) {
        free(input); fputs("strict gzip: allocation or version failure\n", stderr); return 3;
    }
    size = fread(input, 1, INPUT_CAP + 1U, stdin);
    if (ferror(stdin) || size > INPUT_CAP) { status = 3; goto done; }
    if (inflateInit2(&stream, 31) != Z_OK) { status = 3; goto done; }
    initialized = 1;
    stream.next_in = input; stream.avail_in = (uInt)size;
    for (;;) {
        int result;
        size_t produced;
        stream.next_out = output; stream.avail_out = sizeof(output);
        result = inflate(&stream, Z_NO_FLUSH);
        produced = sizeof(output) - stream.avail_out;
        if (produced > OUTPUT_CAP - total) { status = 3; break; }
        total += produced;
        if (fwrite(output, 1, produced, stdout) != produced) { status = 3; break; }
        if (result == Z_STREAM_END) {
            if (stream.avail_in == 0) status = fflush(stdout) == 0 ? 0 : 3;
            break;
        }
        if (result != Z_OK) {
            status = (result == Z_DATA_ERROR || result == Z_BUF_ERROR) ? 2 : 3;
            break;
        }
        if (produced == 0 && stream.avail_in == 0) break;
    }
done:
    if (initialized && inflateEnd(&stream) != Z_OK) status = 3;
    free(input);
    if (status == 2) fputs("strict gzip: incomplete or invalid single gzip member\n", stderr);
    if (status == 3) fputs("strict gzip: resource, I/O or internal failure\n", stderr);
    return status;
}
