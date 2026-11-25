/* SPDX-License-Identifier: MIT */
/* Run inside a disposable installation or against the staged library pair. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <tiffio.h>

int main(int argc, char **argv)
{
    enum { width = 32, height = 4 };
    unsigned char pixels[][width / 8] = {
        {0x00, 0x5a, 0x20, 0xff},
        {0x12, 0x00, 0xff, 0x7e},
        {0xaa, 0x55, 0x17, 0x03},
        {0xf0, 0x33, 0xc0, 0x00},
    };
    unsigned char decoded[sizeof(pixels)] = {0};
    uint16_t compression = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s NEW-SCRATCH-TIFF\n", argv[0]);
        return 2;
    }
    if (!TIFFIsCODECConfigured(COMPRESSION_JBIG))
        return 1;

    int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    TIFF *tiff = TIFFFdOpen(fd, argv[1], "w");
    if (!tiff) {
        close(fd);
        return 1;
    }

    int written = TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, width)
        && TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, height)
        && TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 1)
        && TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1)
        && TIFFSetField(tiff, TIFFTAG_ROWSPERSTRIP, height)
        && TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)
        && TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISWHITE)
        && TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_JBIG)
        && TIFFWriteEncodedStrip(tiff, 0, pixels, sizeof(pixels)) == sizeof(pixels)
        && TIFFWriteDirectory(tiff);
    TIFFClose(tiff);
    if (!written)
        return 1;

    tiff = TIFFOpen(argv[1], "r");
    if (!tiff)
        return 1;

    int equal = TIFFGetField(tiff, TIFFTAG_COMPRESSION, &compression)
        && compression == COMPRESSION_JBIG && TIFFNumberOfStrips(tiff) == 1
        && TIFFReadEncodedStrip(tiff, 0, decoded, sizeof(decoded)) == sizeof(decoded)
        && memcmp(pixels, decoded, sizeof(pixels)) == 0;
    TIFFClose(tiff);
    if (!equal)
        return 1;
    puts("TIFF JBIG roundtrip passed");
    return 0;
}
