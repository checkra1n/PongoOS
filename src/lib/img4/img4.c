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
#include <stdlib.h>
#include "img4.h"

// ==================== ==================== ==================== Data ==================== ==================== ====================

const DERItemSpec DERImg4ItemSpecs[] =
{
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,      0                                    }, // IMG4
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE, DER_DEC_SAVE_DER | DER_ENC_WRITE_DER }, // Payload
    { 2 * sizeof(DERItem), ASN1_CONSTR_CONT | 0, DER_DEC_OPTIONAL                     }, // Manifest
    { 3 * sizeof(DERItem), ASN1_CONSTR_CONT | 1, DER_DEC_OPTIONAL                     }, // RestoreInfo
};
const DERItemSpec DERImg4PayloadItemSpecs[] =
{
    { __builtin_offsetof(Img4Payload, magic),       ASN1_IA5_STRING,      0                }, // IM4P
    { __builtin_offsetof(Img4Payload, type),        ASN1_IA5_STRING,      0                }, // Type
    { __builtin_offsetof(Img4Payload, version),     ASN1_IA5_STRING,      0                }, // Version
    { __builtin_offsetof(Img4Payload, payload),     ASN1_OCTET_STRING,    0                }, // Payload
    { __builtin_offsetof(Img4Payload, keybag),      ASN1_OCTET_STRING,    DER_DEC_OPTIONAL }, // Keybag
    { __builtin_offsetof(Img4Payload, compression), ASN1_CONSTR_SEQUENCE, DER_DEC_OPTIONAL }, // Compression
};
const DERItemSpec DERImg4ManifestItemSpecs[] =
{
    { __builtin_offsetof(Img4Manifest, magic),        ASN1_IA5_STRING,      0                                    }, // IM4M
    { __builtin_offsetof(Img4Manifest, zero),         ASN1_INTEGER,         0                                    }, // 0
    { __builtin_offsetof(Img4Manifest, properties),   ASN1_CONSTR_SET,      DER_DEC_SAVE_DER | DER_ENC_WRITE_DER }, // Properties
    { __builtin_offsetof(Img4Manifest, signature),    ASN1_OCTET_STRING,    0                                    }, // Signature
    { __builtin_offsetof(Img4Manifest, certificates), ASN1_CONSTR_SEQUENCE, 0                                    }, // Certificates
};
const DERItemSpec DERImg4RestoreInfoItemSpecs[] =
{
    { __builtin_offsetof(Img4RestoreInfo, magic), ASN1_IA5_STRING, 0 }, // IM4R
    { __builtin_offsetof(Img4RestoreInfo, nonce), ASN1_CONSTR_SET, 0 }, // Nonce
};
const DERItemSpec DERImg4NonceItemSpecs[] =
{
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,   0 }, // BNCN
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING, 0 }, // Nonce
};
const DERItemSpec DERImg4CompressionItemSpecs[] =
{
    { 0 * sizeof(DERItem), ASN1_INTEGER, 0 },
    { 1 * sizeof(DERItem), ASN1_INTEGER, 0 },
};

// ==================== ==================== ==================== Code ==================== ==================== ====================

DERReturn DERImg4DecodeFindInSequence(DERByte *nextItem, DERByte *end, DERTag tag, DERItem *out)
{
    DERDecodedInfo decoded;
    DERSequence seq = { nextItem, end };
    do
    {
        DERReturn ret = DERDecodeSeqNext(&seq, &decoded);
        if(ret != DR_Success)
        {
            return ret;
        }
    } while(decoded.tag != tag);
    *out = decoded.content;
    return DR_Success;
}

DERReturn DERImg4DecodeContentFindItemWithTag(const DERItem *der, DERTag tag, DERItem *out)
{
    DERSequence seq;
    DERReturn ret = DERDecodeSeqContentInit(der, &seq);
    if(ret != DR_Success)
    {
        return ret;
    }
    return DERImg4DecodeFindInSequence(seq.nextItem, seq.end, tag, out);
}

DERReturn DERImg4DecodeTagCompare(const DERItem *der, uint32_t name)
{
    if(der->length < 4)
    {
        return -1;
    }
    if(der->length > 4)
    {
        return 1;
    }
    uint32_t value;
    if(DERParseInteger(der, &value) != DR_Success)
    {
        return -2;
    }
    if(value < name)
    {
        return -1;
    }
    if(value > name)
    {
        return 1;
    }
    return 0;
}

DERReturn DERImg4Decode(const DERItem *der, DERItem *items)
{
    DERReturn ret;
    DERDecodedInfo decoded;
    if(!der || !items)
    {
        return DR_ParamErr;
    }
    ret = DERDecodeItem(der, &decoded);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(decoded.tag != ASN1_CONSTR_SEQUENCE)
    {
        return DR_UnexpectedTag;
    }
    if(der->data + der->length != decoded.content.data + decoded.content.length)
    {
        return DR_BufOverflow;
    }
    ret = DERParseSequenceContent(&decoded.content, sizeof(DERImg4ItemSpecs)/sizeof(DERImg4ItemSpecs[0]), DERImg4ItemSpecs, items, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(DERImg4DecodeTagCompare(&items[0], 'IMG4') != 0)
    {
        return DR_UnexpectedTag;
    }
    return DR_Success;
}

DERReturn DERImg4DecodePayload(const DERItem *der, Img4Payload *payload)
{
    if(!der || !payload)
    {
        return DR_ParamErr;
    }
    DERReturn ret = DERParseSequence(der, sizeof(DERImg4PayloadItemSpecs)/sizeof(DERImg4PayloadItemSpecs[0]), DERImg4PayloadItemSpecs, payload, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(DERImg4DecodeTagCompare(&payload->magic, 'IM4P') != 0)
    {
        return DR_UnexpectedTag;
    }
    if(!payload->compression.data)
    {
        return DR_Success;
    }
    uint32_t val = -1;

    DERItem items[2];
    ret = DERParseSequenceContent(&payload->compression, sizeof(DERImg4CompressionItemSpecs)/sizeof(DERImg4CompressionItemSpecs[0]), DERImg4CompressionItemSpecs, items, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    ret = DERParseInteger(&items[0], &val);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(val >= 2)
    {
        return DR_ParamErr;
    }
    return DR_Success;
}

DERReturn DERImg4DecodeManifest(const DERItem *der, Img4Manifest *manifest)
{
    if(!der || !manifest)
    {
        return DR_ParamErr;
    }
    if(!der->data || !der->length)
    {
        return DR_Success;
    }
    DERReturn ret = DERParseSequence(der, sizeof(DERImg4ManifestItemSpecs)/sizeof(DERImg4ManifestItemSpecs[0]), DERImg4ManifestItemSpecs, manifest, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(DERImg4DecodeTagCompare(&manifest->magic, 'IM4M') != 0)
    {
        return DR_UnexpectedTag;
    }
    uint32_t zero;
    ret = DERParseInteger(&manifest->zero, &zero);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(zero != 0)
    {
        return DR_UnexpectedTag;
    }
    return DR_Success;
}

DERReturn DERImg4DecodeRestoreInfo(const DERItem *der, Img4RestoreInfo *restoreInfo)
{
    if(!der)
    {
        return DR_Success;
    }
    if(!restoreInfo)
    {
        return DR_ParamErr;
    }
    if(!der->data || !der->length)
    {
        return DR_Success;
    }
    DERReturn ret = DERParseSequence(der, sizeof(DERImg4RestoreInfoItemSpecs)/sizeof(DERImg4RestoreInfoItemSpecs[0]), DERImg4RestoreInfoItemSpecs, restoreInfo, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    if(DERImg4DecodeTagCompare(&restoreInfo->magic, 'IM4R') != 0)
    {
        return DR_UnexpectedTag;
    }
    return DR_Success;
}

DERReturn DERImg4DecodeFindProperty(const DERItem *der, DERTag ktag, DERTag vtag, Img4Property *prop)
{
    DERItem key;
    DERReturn ret = DERImg4DecodeContentFindItemWithTag(der, ktag, &key);
    if(ret != DR_Success)
    {
        return ret;
    }
    DERItemSpec spec[] =
    {
        { 0 * sizeof(Img4Property), ASN1_IA5_STRING, 0 },
        { 1 * sizeof(Img4Property), vtag,            0 },
    };
    ret = DERParseSequence(&key, sizeof(spec) / sizeof(DERItemSpec), spec, prop, 0);
    if(ret != DR_Success)
    {
        return ret;
    }
    uint32_t tag;
    ret = DERParseInteger(&prop[0].content, &tag);
    if(ret != DR_Success)
    {
        return ret;
    }
    if((ASN1_CONSTR_PRIVATE | tag) != ktag)
    {
        return DR_UnexpectedTag;
    }
    prop[0].tag = ASN1_CONSTR_PRIVATE | ktag;
    prop[1].tag = vtag;
    return DR_Success;
}

DERReturn Img4DecodeGetPayload(const Img4 *img4, DERItem *item)
{
    if(!img4 || !item)
    {
        return DR_ParamErr;
    }
    if(!img4->payload.payload.data || !img4->payload.payload.length)
    {
        return DR_EndOfSequence;
    }
    *item = img4->payload.payload;
    return DR_Success;
}

DERReturn Img4DecodeGetPayloadType(const Img4 *img4, uint32_t *type)
{
    if(!img4 || !type)
    {
        return DR_ParamErr;
    }
    if(!img4->payload.payload.data || !img4->payload.payload.length)
    {
        return DR_EndOfSequence;
    }
    return DERParseInteger(&img4->payload.type, type);
}

DERReturn Img4DecodeGetPayloadKeybag(const Img4 *img4, DERItem *kbag)
{
    if(!img4 || !kbag)
    {
        return DR_ParamErr;
    }
    if(!img4->payload.payload.data || !img4->payload.payload.length)
    {
        return DR_EndOfSequence;
    }
    *kbag = img4->payload.keybag;
    return DR_Success;
}

DERReturn Img4DecodeInit(const DERByte *data, DERSize length, Img4 *img4)
{
    DERReturn ret;
    if(!data || !img4)
    {
        return DR_ParamErr;
    }
    DERItem der = { .data = (DERByte*)data, .length = length };
    DERItem items[4] = {};
    bzero(img4, sizeof(Img4));
    ret = DERImg4Decode(&der, items);
    if(ret != DR_Success)
    {
        return ret;
    }
    ret = DERImg4DecodePayload(&items[1], &img4->payload);
    if(ret != DR_Success)
    {
        return ret;
    }
    ret = DERImg4DecodeManifest(&items[2], &img4->manifest);
    if(ret != DR_Success)
    {
        return ret;
    }
    ret = DERImg4DecodeRestoreInfo(&items[3], &img4->restoreInfo);
    if(ret != DR_Success)
    {
        return ret;
    }
    img4->payloadRaw = items[1];
    img4->manifestRaw = items[2];
    return DR_Success;
}

DERReturn Img4Encode(DERItem *der, const DERItem *items)
{
    return Img4EncodeSequence(ASN1_CONSTR_SEQUENCE, items, sizeof(DERImg4ItemSpecs)/sizeof(DERImg4ItemSpecs[0]), DERImg4ItemSpecs, der);
}

DERReturn Img4EncodeRestoreInfo(DERItem *der, void *bytes, size_t len)
{
    Img4RestoreInfo restoreInfo =
    {
        .magic = { .data = (DERByte*)"IM4R", .length = 4 },
    };
    DERItem bncn;
    DERItem items[] =
    {
        { .data = (DERByte*)"BNCN", .length = 4 },
        { .data = bytes, .length = len },
    };
    DERReturn ret = Img4EncodeSequence(ASN1_CONSTR_SEQUENCE, items, sizeof(DERImg4NonceItemSpecs)/sizeof(DERImg4NonceItemSpecs[0]), DERImg4NonceItemSpecs, &bncn);
    if(ret == DR_Success)
    {
        DERSize inOutLen = 20 + bncn.length;
        DERByte *buf = malloc(inOutLen);
        if(!buf)
        {
            ret = -1;
        }
        else
        {
            ret = DEREncodeItem(ASN1_CONSTR_PRIVATE | 'BNCN', bncn.length, bncn.data, buf, &inOutLen);
            if(ret == DR_Success)
            {
                restoreInfo.nonce.data = buf;
                restoreInfo.nonce.length = inOutLen;
                ret = Img4EncodeSequence(ASN1_CONSTR_SEQUENCE, &restoreInfo, sizeof(DERImg4RestoreInfoItemSpecs)/sizeof(DERImg4RestoreInfoItemSpecs[0]), DERImg4RestoreInfoItemSpecs, der);
            }
            free(buf);
        }
        free(bncn.data);
    }
    return ret;
}

DERReturn Img4EncodeSequence(DERTag tag, const void *src, DERShort numItems, const DERItemSpec *itemSpecs, DERItem *der)
{
    if(!tag || !src || !numItems || !itemSpecs || !der)
    {
        return DR_ParamErr;
    }
    DERSize inOutLen = 20;
    for(DERShort i = 0; i < numItems; ++i)
    {
        const DERItemSpec *spec = &itemSpecs[i];
        const DERItem *item = (const DERItem*)((uintptr_t)src + spec->offset);
        if(spec->options & DER_ENC_WRITE_DER)
        {
            inOutLen += item->length;
        }
        else if(item->length == 0 && (spec->options & DER_DEC_OPTIONAL))
        {
            // Skip
        }
        else
        {
            inOutLen += item->length + 20; /* 1+9 tag, 1+8 size, 1 null pad */
        }
    }
    DERByte *buf = malloc(inOutLen);
    if(!buf)
    {
        return -1;
    }
    DERReturn ret = DEREncodeSequence(tag, src, numItems, itemSpecs, buf, &inOutLen);
    if(ret == DR_Success)
    {
        der->data = buf;
        der->length = inOutLen;
    }
    else
    {
        free(buf);
    }
    return ret;
}
