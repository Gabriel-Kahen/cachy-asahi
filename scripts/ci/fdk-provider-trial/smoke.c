/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors.
 * Finite installed PipeWire AAC codec consumer; no daemon or Bluetooth device.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "media-codecs.h"

#define REQUIRE(test, phase) do { if (!(test)) { failure = phase; goto done; } } while (0)

int main(int argc, char **argv)
{
    const char *failure = NULL;
    void *library = NULL, *state = NULL, *props = NULL;
    struct spa_handle *handle = NULL;
    const struct media_codec *codec = NULL;
    int initialized = 0, result = 1;
    unsigned packets = 0, decoded = 0, nonzero = 0;
    size_t pcm_bytes = 0;
    enum { RATE = 48000, CHANNELS = 2, FRAMES = 40, MTU = 1500 };
    uint8_t caps[A2DP_MAX_CAPS_SIZE], config[A2DP_MAX_CAPS_SIZE], packet[4096];
    int16_t input[4096], output[8192];

    REQUIRE(argc == 2 && argv[1][0] == '/', "absolute-plugin-argument");
    library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    REQUIRE(library != NULL, "plugin-dlopen");
    spa_handle_factory_enum_func_t enumerate =
        (spa_handle_factory_enum_func_t)dlsym(library, SPA_HANDLE_FACTORY_ENUM_FUNC_NAME);
    REQUIRE(enumerate != NULL, "factory-symbol");
    const struct spa_handle_factory *factory = NULL;
    uint32_t index = 0;
    REQUIRE(enumerate(&factory, &index) == 1 && factory != NULL,
            "factory-enumeration");
    REQUIRE(factory->version == SPA_VERSION_HANDLE_FACTORY && factory->name != NULL &&
            strcmp(factory->name, MEDIA_CODEC_FACTORY_NAME("aac")) == 0,
            "factory-identity");
    size_t size = spa_handle_factory_get_size(factory, NULL);
    REQUIRE(size >= sizeof(*handle) && size <= 65536, "factory-size");
    handle = calloc(1, size);
    REQUIRE(handle != NULL, "handle-allocation");
    REQUIRE(spa_handle_factory_init(factory, handle, NULL, NULL, 0) == 0,
            "factory-init");
    initialized = 1;
    struct spa_bluez5_codec_a2dp *media = NULL;
    REQUIRE(spa_handle_get_interface(handle, SPA_TYPE_INTERFACE_Bluez5CodecMedia,
                                    (void **)&media) == 0 && media != NULL,
            "codec-interface");
    REQUIRE(media->iface.version == 16 && media->codecs != NULL,
            "private-api-version16");
    for (unsigned i = 0; i < 8 && media->codecs[i] != NULL; ++i) {
        if (media->codecs[i]->id == SPA_BLUETOOTH_AUDIO_CODEC_AAC &&
            media->codecs[i]->name != NULL &&
            strcmp(media->codecs[i]->name, "aac") == 0) {
            codec = media->codecs[i];
            break;
        }
    }
    REQUIRE(codec != NULL && codec->kind == MEDIA_CODEC_A2DP &&
            codec->fill_caps && codec->select_config && codec->validate_config &&
            codec->init_props && codec->clear_props && codec->init && codec->deinit &&
            codec->get_block_size && codec->start_encode && codec->encode &&
            codec->start_decode && codec->decode, "aac-methods");
    int caps_size = codec->fill_caps(codec, 0, NULL, caps);
    REQUIRE(caps_size == (int)sizeof(a2dp_aac_t), "aac-capabilities");
    /* Exercise AAC-LC rather than optional AAC-ELD or xHE capability. */
    ((a2dp_aac_t *)caps)->object_type = AAC_OBJECT_TYPE_MPEG4_AAC_LC;
    ((a2dp_aac_t *)caps)->vbr = 0;
    struct media_codec_audio_info preference = { .rate = RATE, .channels = CHANNELS };
    int config_size = codec->select_config(codec, 0, caps, (size_t)caps_size,
                                           &preference, NULL, config, NULL);
    REQUIRE(config_size == (int)sizeof(a2dp_aac_t), "aac-configuration");
    struct spa_audio_info info;
    REQUIRE(codec->validate_config(codec, 0, config, (size_t)config_size, &info) == 0,
            "configuration-validation");
    REQUIRE(info.media_type == SPA_MEDIA_TYPE_audio &&
            info.media_subtype == SPA_MEDIA_SUBTYPE_raw &&
            info.info.raw.format == SPA_AUDIO_FORMAT_S16 &&
            info.info.raw.rate == RATE && info.info.raw.channels == CHANNELS,
            "pcm-format");
    props = codec->init_props(codec, 0, NULL);
    REQUIRE(props != NULL, "codec-properties");
    state = codec->init(codec, 0, config, (size_t)config_size, &info, props, MTU);
    REQUIRE(state != NULL, "codec-init");
    int block = codec->get_block_size(state);
    REQUIRE(block == 1024 * CHANNELS * (int)sizeof(int16_t) &&
            (size_t)block <= sizeof(input), "pcm-block");
    for (unsigned frame = 0; frame < FRAMES; ++frame) {
        for (unsigned i = 0; i < (unsigned)block / sizeof(input[0]); ++i)
            input[i] = (int16_t)(((int)((frame * 1024 + i / CHANNELS) % 128) - 64) * 128);
        int header = codec->start_encode(state, packet, sizeof(packet),
                                         (uint16_t)frame, frame * 1024);
        REQUIRE(header > 0 && (size_t)header < sizeof(packet), "rtp-encode-header");
        size_t payload = 0;
        int flush = NEED_FLUSH_NO;
        int used = codec->encode(state, input, (size_t)block, packet + header,
                                 sizeof(packet) - (size_t)header, &payload, &flush);
        REQUIRE(used == block && payload <= sizeof(packet) - (size_t)header &&
                flush == NEED_FLUSH_ALL, "aac-encode");
        if (payload == 0)
            continue;
        ++packets;
        uint16_t sequence = UINT16_MAX;
        uint32_t timestamp = UINT32_MAX;
        int consumed = codec->start_decode(state, packet, (size_t)header + payload,
                                             &sequence, &timestamp);
        REQUIRE(consumed == header && sequence == frame && timestamp == frame * 1024,
                "rtp-decode-header");
        size_t produced = 0;
        memset(output, 0, sizeof(output));
        int decoded_bytes = codec->decode(state, packet + consumed, payload,
                                            output, sizeof(output), &produced);
        REQUIRE(decoded_bytes == (int)payload && produced == (size_t)block &&
                produced <= sizeof(output), "aac-decode");
        for (size_t i = 0; i < produced / sizeof(output[0]); ++i)
            nonzero |= output[i] != 0;
        pcm_bytes += produced;
        ++decoded;
    }
    REQUIRE(packets >= 32 && decoded == packets && nonzero, "decoded-pcm-evidence");
    Dl_info loaded;
    void *aac = dlsym(library, "aacEncOpen");
    REQUIRE(aac != NULL && dladdr(aac, &loaded) != 0 && loaded.dli_fname != NULL,
            "loaded-fdk-identity");
    printf("FDK_LIBRARY=%s\n", loaded.dli_fname);
    result = 0;
done:
    if (state != NULL)
        codec->deinit(state);
    if (props != NULL)
        codec->clear_props(props);
    if (initialized && spa_handle_clear(handle) != 0 && failure == NULL)
        failure = "handle-clear";
    free(handle);
    if (library != NULL && dlclose(library) != 0 && failure == NULL)
        failure = "plugin-dlclose";
    if (failure != NULL) {
        fprintf(stderr, "FDK_PIPEWIRE_CODEC_FAIL phase=%s\n", failure);
        return 1;
    }
    if (result == 0)
        printf("FDK_PIPEWIRE_CODEC_PASS packets=%u decoded=%u pcm_bytes=%zu nonzero=%u rate=%u channels=%u\n",
               packets, decoded, pcm_bytes, nonzero, RATE, CHANNELS);
    return result;
}
