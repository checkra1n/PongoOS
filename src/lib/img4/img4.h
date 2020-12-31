/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#define RESERVE_DIGEST_SPACE 20
#define E000000000000000 (ASN1_CONSTRUCTED | ASN1_PRIVATE)

#define IS_EQUAL(a, b) ((a).length == (b).length && !memcmp((a).data, (b).data, (a).length))

#define FOURCC(tag) (unsigned char)((tag) >> 24), (unsigned char)((tag) >> 16), (unsigned char)((tag) >> 8), (unsigned char)(tag)


typedef enum {
    DictMANP,
    DictOBJP
} DictType;

typedef struct {
    DERItem item;
    DERTag tag;
} DERMonster;

typedef struct {
    DERItem magic;      // "IM4P"
    DERItem type;       // "illb"
    DERItem version;    // "iBoot-2261.3.33"
    DERItem imageData;
    DERItem keybag;
#ifdef iOS10
    DERItem compression;
#endif
    DERByte full_digest[RESERVE_DIGEST_SPACE];
} TheImg4Payload;

typedef struct {
    DERItem magic;      // "IM4M"
    DERItem version;    // 0
    DERItem theset;     // MANB + MANP
    DERItem sig_blob;   // RSA
    DERItem chain_blob; // cert chain
    DERItem img4_blob;
    DERByte full_digest[RESERVE_DIGEST_SPACE];
    DERByte theset_digest[RESERVE_DIGEST_SPACE];
} TheImg4Manifest;

typedef struct {
    DERItem magic;      // "IM4R"
    DERItem nonce;
} TheImg4RestoreInfo;

typedef struct {
    bool payloadHashed;
    bool manifestHashed;
    DERItem payloadRaw;
    DERItem manifestRaw;
    DERItem manb;
    DERItem manp;
    DERItem objp;
    TheImg4Payload payload;
    TheImg4Manifest manifest;
    TheImg4RestoreInfo restoreInfo;
} TheImg4;

typedef struct {
    uint64_t CHIP;
    uint64_t ECID;
    uint64_t SEPO;
    uint64_t SDOM;
    uint64_t BORD;
    unsigned char CPRO;
    unsigned char CSEC;
    unsigned char field_2A;
    unsigned char field_2B;
    unsigned char field_2C;
    unsigned char field_2D;
    unsigned char field_2E;
    unsigned char field_2F;
    uint64_t field_30;
    unsigned char boot_manifest_hash[20];
    unsigned char hashvalid;
    unsigned char field_4D;
    unsigned char field_4E;
    unsigned char field_4F;
} ContextH;

typedef struct {
    unsigned char field_0;
    unsigned char field_1;
    unsigned char field_2;
    unsigned char field_3;
    unsigned char field_4;
    unsigned char field_5;
    unsigned char field_6;
    unsigned char field_7;
    unsigned char manifest_hash[20];
    bool has_manifest;
    unsigned char field_1D;
    unsigned char payload_hash[20];
} ContextU;

typedef struct {
    TheImg4 *img4;
    ContextH *hardware;
    ContextU *unknown;
} CTX;

int Img4DecodeGetPayload(TheImg4 *img4, DERItem *a2);
int Img4DecodeGetPayloadType(TheImg4 *img4, unsigned int *a2);
int Img4DecodeGetPayloadKeybag(TheImg4 *img4, DERItem *a2);
int Img4DecodeInit(DERByte *data, DERSize length, TheImg4 *img4);
int makeRestoreInfo(DERItem *where, void* nonceBytes, size_t nonceLength);
DERReturn Img4Encode(DERItem* out, DERItem* items, int itemLen);
