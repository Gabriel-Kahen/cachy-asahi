/* SPDX-License-Identifier: MIT
 * Guest-only capability probe, not an M2 or scanout acceptance test.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror gbm_probe.c -o gbm-probe \
 *           $(pkg-config --cflags --libs egl gbm glesv2 libdrm)
 * Audited sources (no upstream source copied):
 * Mesa mesa-26.2.4, 96cb43121031992b85767f9c1be8f3f48e22b1d2:
 * https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/gbm/backends/dri/gbm_dri.c
 * https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/egl/drivers/dri2/platform_drm.c
 * Aquamarine v0.15.1, f31c47a1b9d300847d8fc3108ad959448103dfc1:
 * https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/allocator/GBM.cpp
 * The launcher must attest a disposable QEMU guest with no host devices.
 * The three guest declarations below are refusal gates, not provenance proof.
 */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <drm_fourcc.h>
#include <errno.h>
#include <fcntl.h>
#include <gbm.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <xf86drm.h>

enum { WIDTH = 64, HEIGHT = 64 };

static bool extension(const char *list, const char *name) {
    size_t n = strlen(name);
    if (!list) return false;
    for (const char *p = list; (p = strstr(p, name)); p += n)
        if ((p == list || p[-1] == ' ') && (!p[n] || p[n] == ' ')) return true;
    return false;
}

static bool guest_guard(void) {
    const char *decl = getenv("CACHY_ASAHI_VIRTUAL_GUEST");
    struct utsname u;
    if (!decl || strcmp(decl, "1") || uname(&u) || strcmp(u.machine, "aarch64"))
        return false;
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) return false;
    char line[8192];
    bool read = fgets(line, sizeof line, f) != NULL;
    bool complete = read && feof(f);
    if (read && !complete && !ferror(f)) complete = fgetc(f) == EOF;
    bool bad = ferror(f);
    fclose(f);
    if (!complete || bad) return false;
    char *save = NULL;
    for (char *p = strtok_r(line, " \t\r\n", &save); p; p = strtok_r(NULL, " \t\r\n", &save))
        if (!strcmp(p, "cachy_asahi_virtual_proof=1")) return true;
    return false;
}

static int card_number(const char *path) {
    const char *prefix = "/dev/dri/card";
    size_t n = strlen(prefix);
    if (strncmp(path, prefix, n) || !path[n]) return -1;
    unsigned card = 0;
    for (const char *p = path + n; *p; ++p) {
        if (*p < '0' || *p > '9' || card > 6) return -1;
        card = card * 10 + (unsigned)(*p - '0');
    }
    return card < 64 ? (int)card : -1;
}

static void quoted(const char *s) {
    if (!s) { fputs("null", stdout); return; }
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void field(const char *name, const char *value) {
    printf(",\"%s\":", name);
    quoted(value);
}

int main(int argc, char **argv) {
    const char *stage = "guest_guard", *failure = NULL;
    const char *egl_vendor = NULL, *egl_version = NULL, *egl_extensions = NULL;
    const char *gl_vendor = NULL, *gl_version = NULL, *renderer = NULL, *gl_extensions = NULL;
    const char *allocation = NULL, *import_modifier = NULL;
    int fd = -1, dma_fd = -1, saved_errno = 0, gles = 0, card = -1;
    EGLint egl_error = EGL_SUCCESS;
    GLenum gl_error = GL_NO_ERROR, framebuffer_status = 0;
    uint64_t prime = 0, modifier = DRM_FORMAT_MOD_INVALID;
    uint32_t stride = 0, offset = 0;
    unsigned verified = 0;
    unsigned char pixels[WIDTH * HEIGHT * 4] = {0};
    GLuint renderbuffer = 0, framebuffer = 0;
    struct gbm_device *gbm = NULL;
    struct gbm_bo *bo = NULL;
    drmVersionPtr driver = NULL;
    EGLDisplay display = EGL_NO_DISPLAY;
    EGLContext context = EGL_NO_CONTEXT;
    EGLImageKHR image = EGL_NO_IMAGE_KHR;
    PFNEGLDESTROYIMAGEKHRPROC destroy_image = NULL;
    bool initialized = false, current = false, passed = false;
#define CHECK(c, why) do { if (!(c)) { failure = (why); goto done; } } while (0)
#define EGL_CHECK(c, why) do { if (!(c)) { egl_error = eglGetError(); failure = (why); goto done; } } while (0)
#define GL_CHECK(why) do { gl_error = glGetError(); CHECK(gl_error == GL_NO_ERROR, (why)); } while (0)

    CHECK(guest_guard(), "guest_declaration_architecture_or_cmdline_missing");
    stage = "device_argument";
    CHECK(argc == 2 && (card = card_number(argv[1])) >= 0, "expected_primary_guest_drm_card_path");
    stage = "device_open";
    fd = open(argv[1], O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { saved_errno = errno; failure = "open_failed"; goto done; }
    struct stat st;
    if (fstat(fd, &st)) { saved_errno = errno; failure = "fstat_failed"; goto done; }
    CHECK(S_ISCHR(st.st_mode) && major(st.st_rdev) == 226 &&
          minor(st.st_rdev) == (unsigned)card, "not_primary_drm_character_device");
    stage = "virtio_gpu_driver";
    driver = drmGetVersion(fd);
    CHECK(driver && driver->name && driver->name_len == 10 &&
          !memcmp(driver->name, "virtio_gpu", 10), "expected_virtio_gpu_driver");
    stage = "prime_capabilities";
    if (drmGetCap(fd, DRM_CAP_PRIME, &prime)) {
        saved_errno = errno; failure = "prime_query_failed"; goto done;
    }
    CHECK((prime & (DRM_PRIME_CAP_IMPORT | DRM_PRIME_CAP_EXPORT)) ==
          (DRM_PRIME_CAP_IMPORT | DRM_PRIME_CAP_EXPORT), "prime_import_export_required");
    stage = "gbm_device";
    gbm = gbm_create_device(fd);
    if (!gbm) saved_errno = errno;
    CHECK(gbm, "gbm_create_device_failed");
    stage = "egl_display";
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_display =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    CHECK(get_display, "egl_platform_entrypoint_missing");
    display = get_display(EGL_PLATFORM_GBM_KHR, gbm, NULL);
    EGL_CHECK(display != EGL_NO_DISPLAY, "gbm_platform_display_failed");
    EGL_CHECK(eglInitialize(display, NULL, NULL), "egl_initialize_failed");
    initialized = true;
    egl_vendor = eglQueryString(display, EGL_VENDOR);
    egl_version = eglQueryString(display, EGL_VERSION);
    egl_extensions = eglQueryString(display, EGL_EXTENSIONS);
    stage = "egl_extensions";
    CHECK(extension(egl_extensions, "EGL_KHR_surfaceless_context") &&
          extension(egl_extensions, "EGL_KHR_image_base") &&
          extension(egl_extensions, "EGL_EXT_image_dma_buf_import"), "required_egl_extensions_missing");
    PFNEGLCREATEIMAGEKHRPROC create_image = (PFNEGLCREATEIMAGEKHRPROC)eglGetProcAddress("eglCreateImageKHR");
    destroy_image = (PFNEGLDESTROYIMAGEKHRPROC)eglGetProcAddress("eglDestroyImageKHR");
    PFNGLEGLIMAGETARGETRENDERBUFFERSTORAGEOESPROC image_storage =
        (PFNGLEGLIMAGETARGETRENDERBUFFERSTORAGEOESPROC)eglGetProcAddress("glEGLImageTargetRenderbufferStorageOES");
    CHECK(create_image && destroy_image && image_storage, "image_entrypoints_missing");
    stage = "gles_context";
    EGL_CHECK(eglBindAPI(EGL_OPENGL_ES_API), "gles_api_bind_failed");
    for (int version = 3; version >= 2; --version) {
        EGLint attrs[] = {EGL_SURFACE_TYPE, 0, EGL_RENDERABLE_TYPE,
            version == 3 ? EGL_OPENGL_ES3_BIT_KHR : EGL_OPENGL_ES2_BIT,
            EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE};
        EGLint ctx_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, version, EGL_NONE};
        EGLConfig config;
        EGLint count = 0;
        if (eglChooseConfig(display, attrs, &config, 1, &count) && count > 0)
            context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attrs);
        if (context != EGL_NO_CONTEXT) { gles = version; break; }
        egl_error = eglGetError();
    }
    CHECK(context != EGL_NO_CONTEXT, "gles2_and_gles3_context_creation_failed");
    egl_error = EGL_SUCCESS;
    EGL_CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, context), "surfaceless_make_current_failed");
    current = true;
    gl_vendor = (const char *)glGetString(GL_VENDOR);
    gl_version = (const char *)glGetString(GL_VERSION);
    renderer = (const char *)glGetString(GL_RENDERER);
    gl_extensions = (const char *)glGetString(GL_EXTENSIONS);
    GL_CHECK("gl_identity_query_failed");
    stage = "software_renderer";
    CHECK(renderer && (!strncmp(renderer, "llvmpipe", 8) || !strncmp(renderer, "softpipe", 8)), "llvmpipe_or_softpipe_required");
    stage = "gl_extensions";
    CHECK(extension(gl_extensions, "GL_EXT_texture_format_BGRA8888") &&
          extension(gl_extensions, "GL_OES_EGL_image"), "bgra_and_egl_image_extensions_required");
    stage = "linear_gbm_buffer";
    allocation = "rendering_linear_flags";
    bo = gbm_bo_create(gbm, WIDTH, HEIGHT, GBM_FORMAT_XRGB8888, GBM_BO_USE_RENDERING | GBM_BO_USE_LINEAR);
    if (!bo) {
        const uint64_t linear = DRM_FORMAT_MOD_LINEAR;
        allocation = "explicit_linear_modifier";
        bo = gbm_bo_create_with_modifiers2(gbm, WIDTH, HEIGHT, GBM_FORMAT_XRGB8888,
                                         &linear, 1, GBM_BO_USE_RENDERING | GBM_BO_USE_LINEAR);
    }
    if (!bo) saved_errno = errno;
    CHECK(bo, "linear_renderable_allocation_failed");
    modifier = gbm_bo_get_modifier(bo);
    CHECK(gbm_bo_get_format(bo) == GBM_FORMAT_XRGB8888 && gbm_bo_get_plane_count(bo) == 1 &&
          modifier == DRM_FORMAT_MOD_LINEAR, "single_plane_linear_xrgb8888_required");
    stride = gbm_bo_get_stride_for_plane(bo, 0);
    offset = gbm_bo_get_offset(bo, 0);
    CHECK(stride >= WIDTH * 4 && stride <= INT_MAX && offset <= INT_MAX, "invalid_plane_layout");
    stage = "dmabuf_export";
    dma_fd = gbm_bo_get_fd_for_plane(bo, 0);
    if (dma_fd < 0) saved_errno = errno;
    CHECK(dma_fd >= 0, "plane_fd_export_failed");
    stage = "egl_dmabuf_import";
    EGLint image_attrs[24] = {EGL_WIDTH, WIDTH, EGL_HEIGHT, HEIGHT,
        EGL_LINUX_DRM_FOURCC_EXT, (EGLint)DRM_FORMAT_XRGB8888,
        EGL_DMA_BUF_PLANE0_FD_EXT, dma_fd, EGL_DMA_BUF_PLANE0_OFFSET_EXT, (EGLint)offset,
        EGL_DMA_BUF_PLANE0_PITCH_EXT, (EGLint)stride};
    int end = 12;
    import_modifier = "implicit_linear";
    if (extension(egl_extensions, "EGL_EXT_image_dma_buf_import_modifiers")) {
        image_attrs[end++] = EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT;
        image_attrs[end++] = 0;
        image_attrs[end++] = EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT;
        image_attrs[end++] = 0;
        import_modifier = "explicit_linear";
    }
    image_attrs[end] = EGL_NONE;
    image = create_image(display, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, NULL, image_attrs);
    EGL_CHECK(image != EGL_NO_IMAGE_KHR, "egl_dmabuf_image_import_failed");
    stage = "image_renderbuffer";
    glGenRenderbuffers(1, &renderbuffer);
    glBindRenderbuffer(GL_RENDERBUFFER, renderbuffer);
    image_storage(GL_RENDERBUFFER, image);
    GL_CHECK("egl_image_renderbuffer_storage_failed");
    glGenFramebuffers(1, &framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_RENDERBUFFER, renderbuffer);
    framebuffer_status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    GL_CHECK("framebuffer_attachment_failed");
    CHECK(framebuffer_status == GL_FRAMEBUFFER_COMPLETE, "framebuffer_incomplete");
    stage = "clear_and_readback";
    glViewport(0, 0, WIDTH, HEIGHT);
    glDisable(GL_DITHER);
    glClearColor(1, 0, 1, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    glFinish();
    glReadPixels(0, 0, WIDTH, HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    GL_CHECK("clear_or_readback_failed");
    stage = "pixel_verification";
    for (unsigned i = 0; i < WIDTH * HEIGHT; ++i) {
        const unsigned char *p = pixels + i * 4;
        CHECK(p[0] == 255 && p[1] == 0 && p[2] == 255 && p[3] == 255, "rgba_pixel_mismatch");
        ++verified;
    }
    stage = "complete";
    passed = true;

done:
    printf("{\"schema\":1,\"status\":\"%s\",\"scope\":\"guest_software_gbm_egl_only\"", passed ? "PASS" : "FAILED");
    field("stage", stage); field("failure", failure);
    field("egl_vendor", egl_vendor); field("egl_version", egl_version); field("egl_extensions", egl_extensions);
    field("gl_vendor", gl_vendor); field("gl_version", gl_version); field("renderer", renderer); field("gl_extensions", gl_extensions);
    field("allocation", allocation); field("import_modifier", import_modifier);
    printf(",\"errno\":%d,\"egl_error\":%d,\"gl_error\":%u,\"gles_context\":%d,\"prime_caps\":%" PRIu64,
           saved_errno, egl_error, gl_error, gles, prime);
    printf(",\"width\":%d,\"height\":%d,\"stride\":%u,\"offset\":%u,\"modifier\":%" PRIu64,
           WIDTH, HEIGHT, stride, offset, modifier);
    printf(",\"framebuffer_status\":%u,\"verified_pixels\":%u,\"expected_rgba\":[255,0,255,255]", framebuffer_status, verified);
    if (!passed && !strcmp(stage, "pixel_verification")) {
        unsigned char *p = pixels + verified * 4;
        printf(",\"mismatch_rgba\":[%u,%u,%u,%u]", p[0], p[1], p[2], p[3]);
    }
    fputs(",\"scanout\":\"NOT_RUN\",\"m2_hardware\":\"NOT_RUN\",\"performance\":\"NOT_RUN\"}\n", stdout);
    bool output_ok = !ferror(stdout) && fflush(stdout) == 0;
    if (current) {
        if (framebuffer) glDeleteFramebuffers(1, &framebuffer);
        if (renderbuffer) glDeleteRenderbuffers(1, &renderbuffer);
    }
    if (image != EGL_NO_IMAGE_KHR && destroy_image) destroy_image(display, image);
    if (current) eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (context != EGL_NO_CONTEXT) eglDestroyContext(display, context);
    if (initialized) eglTerminate(display);
    if (dma_fd >= 0) close(dma_fd);
    if (bo) gbm_bo_destroy(bo);
    if (gbm) gbm_device_destroy(gbm);
    if (driver) drmFreeVersion(driver);
    if (fd >= 0) close(fd);
    return passed && output_ok ? 0 : 1;
}
