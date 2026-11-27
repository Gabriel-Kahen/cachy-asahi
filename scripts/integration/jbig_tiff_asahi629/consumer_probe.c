/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>
#include <spandsp.h>
#include <tiffio.h>

enum { RGB_SIZE = 32, FAX_WIDTH = 1728, FAX_ROWS = 16 };

static void rgb_pixel(unsigned int x, unsigned int y, uint8_t pixel[3])
{
    pixel[0] = (uint8_t)(37 * x + 11 * y);
    pixel[1] = (uint8_t)(13 * x + 43 * y);
    pixel[2] = (uint8_t)(7 * x + 29 * y);
}

static int write_rgb(const char *path)
{
    TIFF *image = TIFFOpen(path, "w");
    if (!image)
        return 0;

    int ok = TIFFSetField(image, TIFFTAG_IMAGEWIDTH, RGB_SIZE)
        && TIFFSetField(image, TIFFTAG_IMAGELENGTH, RGB_SIZE)
        && TIFFSetField(image, TIFFTAG_BITSPERSAMPLE, 8)
        && TIFFSetField(image, TIFFTAG_SAMPLESPERPIXEL, 3)
        && TIFFSetField(image, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB)
        && TIFFSetField(image, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)
        && TIFFSetField(image, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT)
        && TIFFSetField(image, TIFFTAG_ROWSPERSTRIP, RGB_SIZE);
    for (unsigned int y = 0; ok && y < RGB_SIZE; ++y) {
        uint8_t row[RGB_SIZE * 3];
        for (unsigned int x = 0; x < RGB_SIZE; ++x)
            rgb_pixel(x, y, row + 3 * x);
        ok = TIFFWriteScanline(image, row, y, 0) == 1;
    }
    if (ok)
        ok = TIFFWriteDirectory(image);
    TIFFClose(image);
    return ok;
}

static int check_rgb(const char *path)
{
    TIFF *image = TIFFOpen(path, "r");
    if (!image)
        return 0;

    uint32_t width = 0, height = 0;
    uint32_t pixels[RGB_SIZE * RGB_SIZE];
    int ok = TIFFGetField(image, TIFFTAG_IMAGEWIDTH, &width)
        && TIFFGetField(image, TIFFTAG_IMAGELENGTH, &height)
        && width == RGB_SIZE && height == RGB_SIZE
        && TIFFReadRGBAImageOriented(image, width, height, pixels, ORIENTATION_TOPLEFT, 1);
    TIFFClose(image);
    for (unsigned int y = 0; ok && y < RGB_SIZE; ++y) {
        for (unsigned int x = 0; ok && x < RGB_SIZE; ++x) {
            uint8_t expected[3];
            rgb_pixel(x, y, expected);
            uint32_t readback = pixels[y * RGB_SIZE + x];
            ok = TIFFGetR(readback) == expected[0] && TIFFGetG(readback) == expected[1]
                && TIFFGetB(readback) == expected[2] && TIFFGetA(readback) == UINT8_MAX;
        }
    }
    return ok;
}

/* The selected GTK can write a TIFF from a memory texture without a display. */
static int gtk_tiff(const char *path)
{
    uint8_t pixels[RGB_SIZE * RGB_SIZE * 3];
    for (unsigned int y = 0; y < RGB_SIZE; ++y) {
        for (unsigned int x = 0; x < RGB_SIZE; ++x)
            rgb_pixel(x, y, pixels + 3 * (y * RGB_SIZE + x));
    }

    GBytes *bytes = g_bytes_new(pixels, sizeof(pixels));
    GdkTexture *texture = gdk_memory_texture_new(RGB_SIZE, RGB_SIZE, GDK_MEMORY_R8G8B8,
                                               bytes, RGB_SIZE * 3);
    g_bytes_unref(bytes);
    if (!texture)
        return 0;
    int ok = gdk_texture_save_to_tiff(texture, path);
    g_object_unref(texture);
    return ok && check_rgb(path);
}

static int write_fax(const char *path)
{
    TIFF *image = TIFFOpen(path, "w");
    if (!image)
        return 0;

    int ok = TIFFSetField(image, TIFFTAG_IMAGEWIDTH, FAX_WIDTH)
        && TIFFSetField(image, TIFFTAG_IMAGELENGTH, FAX_ROWS)
        && TIFFSetField(image, TIFFTAG_BITSPERSAMPLE, 1)
        && TIFFSetField(image, TIFFTAG_SAMPLESPERPIXEL, 1)
        && TIFFSetField(image, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISWHITE)
        && TIFFSetField(image, TIFFTAG_FILLORDER, FILLORDER_MSB2LSB)
        && TIFFSetField(image, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)
        && TIFFSetField(image, TIFFTAG_ROWSPERSTRIP, FAX_ROWS)
        && TIFFSetField(image, TIFFTAG_COMPRESSION, COMPRESSION_CCITTFAX3)
        && TIFFSetField(image, TIFFTAG_RESOLUTIONUNIT, RESUNIT_INCH)
        && TIFFSetField(image, TIFFTAG_XRESOLUTION, 204.0)
        && TIFFSetField(image, TIFFTAG_YRESOLUTION, 98.0);
    for (unsigned int y = 0; ok && y < FAX_ROWS; ++y) {
        uint8_t row[FAX_WIDTH / 8] = {0};
        row[y] = 0x5a;
        row[2 * y + 7] = 0xa5;
        ok = TIFFWriteScanline(image, row, y, 0) == 1;
    }
    if (ok)
        ok = TIFFWriteDirectory(image);
    TIFFClose(image);
    return ok;
}

static int fax_tiff(const char *path)
{
    if (!write_fax(path))
        return 0;
    t4_tx_state_t *fax = t4_tx_init(NULL, path, 0, 0);
    if (!fax)
        return 0;
    t4_tx_set_tx_encoding(fax, T4_COMPRESSION_ITU_T4_1D);
    uint8_t encoded[4096];
    int ok = t4_tx_get_pages_in_file(fax) == 1
        && t4_tx_start_page(fax) == 0
        && t4_tx_get_image_width(fax) == FAX_WIDTH;
    int length = ok ? t4_tx_get_chunk(fax, encoded, sizeof(encoded)) : 0;
    if (ok)
        ok = length > 0 && length < (int)sizeof(encoded) && t4_tx_end_page(fax) == 0;
    return t4_tx_free(fax) == 0 && ok;
}

int main(int argc, char **argv)
{
    if (argc != 3 || !argv[2][0])
        return 2;
    if (!strcmp(argv[1], "write-rgb") && write_rgb(argv[2]))
        puts("RGB_TIFF_FIXTURE_WRITTEN");
    else if (!strcmp(argv[1], "check-rgb") && check_rgb(argv[2]))
        puts("RGB_TIFF_PIXELS_MATCH");
    else if (!strcmp(argv[1], "gtk") && gtk_tiff(argv[2]))
        puts("GTK_TIFF_PIXELS_MATCH");
    else if (!strcmp(argv[1], "fax") && fax_tiff(argv[2]))
        puts("SPANDSP_TIFF_FAX_PAGE_ENCODED");
    else
        return 1;
    return 0;
}
