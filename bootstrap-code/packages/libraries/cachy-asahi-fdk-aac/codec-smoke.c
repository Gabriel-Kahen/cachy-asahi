/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors.
 * Original bounded API smoke, not an upstream conformance or quality suite.
 */
#include <stdio.h>
#include <string.h>
#include "aacenc_lib.h"
#include "aacdecoder_lib.h"
#include "xHEAACEnc.h"

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", #condition); \
        goto done; \
    } \
} while (0)

enum { RATE = 48000, FRAME_SAMPLES = 1024, PCM_CAPACITY = 2048,
       PACKET_CAPACITY = 8192, INPUT_FRAMES = 24, FLUSH_FRAMES = 8 };

static int decode_packet(HANDLE_AACDECODER decoder, UCHAR *packet, UINT size,
                         unsigned *frames, int *nonzero)
{
    INT_PCM pcm[PCM_CAPACITY] = {0};
    UINT available = size;
    int result = 0;
    REQUIRE(size >= 7 && size <= PACKET_CAPACITY);
    REQUIRE(packet[0] == 0xff && (packet[1] & 0xf0) == 0xf0);
    REQUIRE((((UINT)(packet[3] & 3) << 11) | ((UINT)packet[4] << 3) |
             ((UINT)packet[5] >> 5)) == size);
    REQUIRE(aacDecoder_Fill(decoder, &packet, &size, &available) == AAC_DEC_OK);
    REQUIRE(available == 0);
    for (int attempt = 0; attempt < 4; ++attempt) {
        AAC_DECODER_ERROR error = aacDecoder_DecodeFrame(decoder, pcm, PCM_CAPACITY, 0);
        if (error == AAC_DEC_NOT_ENOUGH_BITS) {
            result = 1;
            goto done;
        }
        REQUIRE(error == AAC_DEC_OK);
        CStreamInfo *info = aacDecoder_GetStreamInfo(decoder);
        REQUIRE(info != NULL && info->sampleRate == RATE && info->numChannels == 1);
        REQUIRE(info->frameSize > 0 && info->frameSize <= PCM_CAPACITY);
        for (int i = 0; i < info->frameSize; ++i)
            if (pcm[i] != 0) *nonzero = 1;
        ++*frames;
    }
done:
    return result;
}

static int classic_roundtrip(void)
{
    HANDLE_AACENCODER encoder = NULL;
    HANDLE_AACDECODER decoder = NULL;
    AACENC_InfoStruct info = {0};
    INT_PCM pcm[FRAME_SAMPLES];
    UCHAR packet[PACKET_CAPACITY];
    void *input[] = {pcm}, *output[] = {packet};
    INT input_id[] = {IN_AUDIO_DATA}, output_id[] = {OUT_BITSTREAM_DATA};
    INT input_size[] = {sizeof(pcm)}, output_size[] = {sizeof(packet)};
    INT input_element[] = {sizeof(pcm[0])}, output_element[] = {sizeof(packet[0])};
    AACENC_BufDesc input_desc = {1, input, input_id, input_size, input_element};
    AACENC_BufDesc output_desc = {1, output, output_id, output_size, output_element};
    unsigned decoded_frames = 0;
    int nonzero = 0, eof = 0, result = 0;

    REQUIRE(aacEncOpen(&encoder, 0, 1) == AACENC_OK && encoder != NULL);
    REQUIRE(aacEncoder_SetParam(encoder, AACENC_AOT, AOT_AAC_LC) == AACENC_OK);
    REQUIRE(aacEncoder_SetParam(encoder, AACENC_SAMPLERATE, RATE) == AACENC_OK);
    REQUIRE(aacEncoder_SetParam(encoder, AACENC_CHANNELMODE, MODE_1) == AACENC_OK);
    REQUIRE(aacEncoder_SetParam(encoder, AACENC_BITRATE, 64000) == AACENC_OK);
    REQUIRE(aacEncoder_SetParam(encoder, AACENC_TRANSMUX, TT_MP4_ADTS) == AACENC_OK);
    REQUIRE(aacEncEncode(encoder, NULL, NULL, NULL, NULL) == AACENC_OK);
    REQUIRE(aacEncInfo(encoder, &info) == AACENC_OK);
    REQUIRE(info.inputChannels == 1 && info.frameLength == FRAME_SAMPLES);
    REQUIRE(info.maxOutBufBytes > 0 && info.maxOutBufBytes <= PACKET_CAPACITY);
    decoder = aacDecoder_Open(TT_MP4_ADTS, 1);
    REQUIRE(decoder != NULL);

    for (int frame = 0; frame < INPUT_FRAMES + FLUSH_FRAMES; ++frame) {
        AACENC_InArgs args = {0};
        AACENC_OutArgs encoded = {0};
        int flushing = frame >= INPUT_FRAMES;
        for (int i = 0; i < FRAME_SAMPLES; ++i)
            pcm[i] = (INT_PCM)(((frame * FRAME_SAMPLES + i) % 128 - 64) * 128);
        args.numInSamples = flushing ? -1 : FRAME_SAMPLES;
        AACENC_ERROR error = aacEncEncode(encoder, flushing ? NULL : &input_desc,
                                          &output_desc, &args, &encoded);
        if (error == AACENC_ENCODE_EOF) {
            REQUIRE(flushing);
            eof = 1;
            break;
        }
        REQUIRE(error == AACENC_OK);
        if (!flushing) REQUIRE(encoded.numInSamples == FRAME_SAMPLES);
        REQUIRE(encoded.numOutBytes >= 0 && encoded.numOutBytes <= PACKET_CAPACITY);
        if (encoded.numOutBytes)
            REQUIRE(decode_packet(decoder, packet, (UINT)encoded.numOutBytes,
                                  &decoded_frames, &nonzero));
    }
    REQUIRE(eof && decoded_frames >= INPUT_FRAMES && nonzero);
    printf("PASS: classic AAC-LC ADTS roundtrip; %u decoded mono frames at %d Hz\n",
           decoded_frames, RATE);
    result = 1;
done:
    if (decoder != NULL) aacDecoder_Close(decoder);
    if (encoder != NULL && aacEncClose(&encoder) != AACENC_OK) result = 0;
    return result;
}

static int xhe_configuration_lifecycle(void)
{
    IIS_XHEAACENC_CONFIG_INSTANCE_HANDLE config = NULL;
    const char *version = IIS_xHEAACEnc_GetVersionInfoStr();
    int result = 0;
    /* The pinned encoder reports its own API version, not package version 3.0.0. */
    REQUIRE(version != NULL && strcmp(version, "1.0AOSP") == 0);
    for (int repeat = 0; repeat < 3; ++repeat) {
        REQUIRE(IIS_xHEAACEnc_Config_Open(&config, RATE, IIS_XHEAACENC_CHANNELCONFIG_MONO)
                == IIS_XHEAACENC_NO_ERROR && config != NULL);
        REQUIRE(IIS_xHEAACEnc_Config_AddParamValueInt(config, IIS_XHEAACENC_PARAMETER_BITRATE,
                                                     64000) == IIS_XHEAACENC_NO_ERROR);
        IIS_XHEAACENC_RETURN_CODE error = IIS_xHEAACEnc_Config_Delete(config);
        config = NULL; /* Delete consumes the handle by value. */
        REQUIRE(error == IIS_XHEAACENC_NO_ERROR);
    }
    printf("PASS: xHE API %s configuration lifecycle; encoding/roundtrip NOT RUN\n", version);
    result = 1;
done:
    if (config != NULL) IIS_xHEAACEnc_Config_Delete(config);
    return result;
}

int main(void)
{
    int classic = classic_roundtrip();
    int xhe = xhe_configuration_lifecycle();
    return classic && xhe ? 0 : 1;
}
