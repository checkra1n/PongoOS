/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2021 checkra1n team
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
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include <libDER/libDER_config.h>
#include <libDER/asn1Types.h> // This include MUST come after libDER_config.h
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>

#if !DER_MULTIBYTE_TAGS
#   error "DER_MULTIBYTE_TAGS not set"
#endif
#if DER_TAG_SIZE != 8
#   error "DER_TAG_SIZE != 8"
#endif

// ==================== ==================== ==================== Constants ==================== ==================== ====================

#define ASN1_CONSTR_CONT        (ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC)
#define ASN1_CONSTR_PRIVATE     (ASN1_CONSTRUCTED | ASN1_PRIVATE)

// ==================== ==================== ==================== Types ==================== ==================== ====================

typedef struct
{
    DERItem content;
    DERTag  tag;
} Img4Property;

typedef struct
{
    DERItem magic;
    DERItem type;
    DERItem version;
    DERItem payload;
    DERItem keybag;
    DERItem compression;
    uint8_t hash[0x30];
} Img4Payload;

typedef struct
{
    DERItem magic;
    DERItem zero;
    DERItem properties;
    DERItem signature;
    DERItem certificates;
    DERItem embedded;
    uint8_t full_hash[0x30];
    uint8_t prop_hash[0x30];
} Img4Manifest;

typedef struct
{
    DERItem magic;
    DERItem nonce;
} Img4RestoreInfo;

typedef struct
{
    bool payloadHashValid;
    bool manifestHashValid;
    DERItem payloadRaw;
    DERItem manifestRaw;
    DERItem manb;
    DERItem manp;
    DERItem objp;
    Img4Payload payload;
    Img4Manifest manifest;
    Img4RestoreInfo restoreInfo;
} Img4;

// ==================== ==================== ==================== Functions ==================== ==================== ====================

DERReturn DERImg4DecodeFindInSequence(DERByte *nextItem, DERByte *end, DERTag tag, DERItem *out);
DERReturn DERImg4DecodeContentFindItemWithTag(const DERItem *der, DERTag tag, DERItem *out);
DERReturn DERImg4DecodeTagCompare(const DERItem *der, uint32_t name);
DERReturn DERImg4Decode(const DERItem *der, DERItem *items);
DERReturn DERImg4DecodePayload(const DERItem *der, Img4Payload *payload);
DERReturn DERImg4DecodeManifest(const DERItem *der, Img4Manifest *manifest);
DERReturn DERImg4DecodeRestoreInfo(const DERItem *der, Img4RestoreInfo *restoreInfo);
DERReturn DERImg4DecodeFindProperty(const DERItem *der, DERTag ktag, DERTag vtag, Img4Property *prop);
DERReturn Img4DecodeGetPayload(const Img4 *img4, DERItem *item);
DERReturn Img4DecodeGetPayloadType(const Img4 *img4, uint32_t *type);
DERReturn Img4DecodeGetPayloadKeybag(const Img4 *img4, DERItem *kbag);
DERReturn Img4DecodeInit(const DERByte *data, DERSize length, Img4 *img4);
DERReturn Img4Encode(DERItem *der, const DERItem *items);
DERReturn Img4EncodeRestoreInfo(DERItem *der, void *bytes, size_t len);
DERReturn Img4EncodeSequence(DERTag tag, const void *src, DERShort numItems, const DERItemSpec *itemSpecs, DERItem *der);
