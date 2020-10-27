// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
#import <pongo.h>
const DERItemSpec DERImg4ItemSpecs[4] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IMG4"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_ENC_WRITE_DER|DER_DEC_SAVE_DER },     // SEQUENCE(payload)
    { 2 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },     // CONS(SEQUENCE(manifest))
    { 3 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 1,  DER_DEC_OPTIONAL }      // CONS(SEQUENCE(restoreInfo))
};

const DERItemSpec DERImg4PayloadItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4P"
    { 1 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "illb"
    { 2 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "iBoot-2261.3.33"
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // binary data
    { 4 * sizeof(DERItem), ASN1_OCTET_STRING,                           DER_DEC_OPTIONAL }      // keybag
};

const DERItemSpec DERImg4ManifestItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4M"
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },                    // 0
    { 2 * sizeof(DERItem), ASN1_CONSTR_SET,                             DER_DEC_SAVE_DER },     // SET(things)
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // RSA
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 }                     // chain
};

const DERItemSpec DERImg4RestoreInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4R"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SET,                             0 }                     // SET(nonce)
};

const DERItemSpec DERSignedCertCrlItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_DEC_SAVE_DER },
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 2 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERTBSCertItemSpecs[10] = {
    { 0 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },
    { 2 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 3 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 5 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 6 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 7 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 1,                   DER_DEC_OPTIONAL },
    { 8 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 2,                   DER_DEC_OPTIONAL },
    { 9 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 3,  DER_DEC_OPTIONAL }
};

const DERItemSpec DERAttributeTypeAndValueItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERExtensionItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), ASN1_BOOLEAN,                                DER_DEC_OPTIONAL },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 }
};

const DERItemSpec DERAlgorithmIdItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_OPTIONAL | DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERSubjPubKeyInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 1 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERRSAPubKeyPKCS1ItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,                                0x100 },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0x100 }
};

const DERByte _oidAppleImg4ManifestCertSpec[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 6, 1, 0xF };
const DERItem oidAppleImg4ManifestCertSpec = { (DERByte *)_oidAppleImg4ManifestCertSpec, sizeof(_oidAppleImg4ManifestCertSpec) };

const DERItem AppleSecureBootCA = { (DERByte *)"\x13)Apple Secure Boot Certification Authority", 0x2B };

const DERItemSpec kbagSpecs[] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,                                0 },
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },
};

const DERItemSpec nonceItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "BNCN"
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 }                     // nonce
};


int
DERImg4DecodeFindInSequence(unsigned char *a1, unsigned char *a2, DERTag tag, DERItem *a5)
{
    DERDecodedInfo currDecoded;
    DERSequence derSeq;

    derSeq.nextItem = a1;
    derSeq.end = a2;

    do {
        int rv = DERDecodeSeqNext(&derSeq, &currDecoded);
        if (rv) {
            return rv;
        }
    } while (currDecoded.tag != tag);

    *a5 = currDecoded.content;
    return 0;
}

int
DERImg4DecodeContentFindItemWithTag(const DERItem *a1, DERTag tag, DERItem *a4)
{
    int rv;
    DERSequence derSeq;

    rv = DERDecodeSeqContentInit(a1, &derSeq);
    if (rv) {
        return rv;
    }
    return DERImg4DecodeFindInSequence(derSeq.nextItem, derSeq.end, tag, a4);
}

int
DERImg4DecodeTagCompare(const DERItem *a1, uint32_t nameTag)
{
    uint32_t var_14;

    if (a1->length < 4) {
        return -1;
    }
    if (a1->length > 4) {
        return 1;
    }

    if (DERParseInteger(a1, &var_14)) {
        return -2;
    }

    if (var_14 < nameTag) {
        return -1;
    }
    if (var_14 > nameTag) {
        return 1;
    }
    return 0;
}

int
DERImg4Decode(const DERItem *a1, DERItem *a2)
{
    int rv;
    DERDecodedInfo var_38;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeItem(a1, &var_38);
    if (rv) {
        return rv;
    }

    if (var_38.tag != ASN1_CONSTR_SEQUENCE) {
        return DR_UnexpectedTag;
    }

    if (a1->data + a1->length < var_38.content.data + var_38.content.length) {
        return DR_BufOverflow;
    }

    rv = DERParseSequenceContent(&var_38.content, 4, DERImg4ItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(a2, 'IMG4')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodePayload(const DERItem *a1, TheImg4Payload *a2)
{
    int rv;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

#ifdef iOS10
    rv = DERParseSequence(a1, 6, DERImg4PayloadItemSpecs, a2, 0);
#else
    rv = DERParseSequence(a1, 5, DERImg4PayloadItemSpecs, a2, 0);
#endif
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4P')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodeManifest(const DERItem *a1, TheImg4Manifest *a2)
{
    int rv;
    uint32_t var_14;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 5, DERImg4ManifestItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4M')) {
        return DR_UnexpectedTag;
    }

    rv = DERParseInteger(&a2->version, &var_14);
    if (rv) {
        return rv;
    }

    if (var_14) {
        return DR_UnexpectedTag;
    }
    return 0;
}

int
DERImg4DecodeRestoreInfo(const DERItem *a1, TheImg4RestoreInfo *a2)
{
    int rv;

    if (a1 == NULL) {
        return 0;
    }
    if (a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 2, DERImg4RestoreInfoItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4R')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodeProperty(const DERItem *a1, DERTag etag, DERMonster *a4)
{
    int rv;
    uint32_t var_6C;
    DERTag tag;
    DERSequence var_60;
    DERDecodedInfo var_50;
    DERDecodedInfo var_38;

    if (a1 == NULL || a4 == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeSeqInit(a1, &tag, &var_60);
    if (rv) {
        return rv;
    }

    if (tag != ASN1_CONSTR_SEQUENCE) {
        return DR_UnexpectedTag;
    }

    rv = DERDecodeSeqNext(&var_60, &var_38);
    if (rv) {
        return rv;
    }

    if (var_38.tag != ASN1_IA5_STRING) {
        return DR_UnexpectedTag;
    }

    rv = DERParseInteger(&var_38.content, &var_6C);
    if (rv) {
        return rv;
    }

    if ((E000000000000000 | var_6C) != etag) {
        return DR_UnexpectedTag;
    }

    a4[0].item = var_38.content;

    rv = DERDecodeSeqNext(&var_60, &var_50);
    if (rv) {
        return rv;
    }

    a4[1].tag = var_50.tag;
    a4[1].item = var_50.content;

    rv = DERDecodeSeqNext(&var_60, &var_50);
    if (rv != DR_EndOfSequence) {
        return DR_UnexpectedTag;
    }
    return 0;
}

int
DERImg4DecodeFindProperty(const DERItem *a1, DERTag etag, DERTag atag, DERMonster *dest)
{
    int rv;
    DERItemSpec var_70[2];
    uint32_t var_3C;
    DERItem var_38;

    rv = DERImg4DecodeContentFindItemWithTag(a1, etag, &var_38);
    if (rv) {
        return rv;
    }

    var_70[0].offset = 0;
    var_70[0].tag = ASN1_IA5_STRING;
    var_70[0].options = 0;
    var_70[1].offset = sizeof(DERMonster);
    var_70[1].tag = atag;
    var_70[1].options = 0;

    rv = DERParseSequence(&var_38, 2, var_70, dest, 0);
    if (rv) {
        return rv;
    }

    rv = DERParseInteger(&dest[0].item, &var_3C);
    if (rv) {
        return rv;
    }

    if ((E000000000000000 | var_3C) != etag) {
        return DR_UnexpectedTag;
    }

    dest[0].tag = etag | E000000000000000;
    dest[1].tag = atag;
    return 0;
}

int
Img4DecodeGetPayload(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.imageData;
    return 0;
}

int
Img4DecodeGetPayloadType(TheImg4 *img4, unsigned int *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    return DERParseInteger(&img4->payload.type, a2);
}

int
Img4DecodeGetPayloadKeybag(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.keybag;
    return 0;
}

int
Img4DecodeCopyPayloadHash(TheImg4 *img4, void *hash, DERSize length)
{
    //unsigned char var_3C[20];

    if (img4 == NULL || hash == NULL || length != 20) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    if (!img4->payloadHashed) {
        panic("can't actually do this without sha1 impl");
//        sha1_digest(img4->payloadRaw.data, img4->payloadRaw.length, var_3C);
 //       memmove(hash, &var_3C, length);
        return 0;
    }
    if (length != 20) {
        return DR_BufOverflow;
    }
    memcpy(hash, img4->payload.full_digest, 20);
    return 0;
}

int
Img4DecodeManifestExists(TheImg4 *img4, bool *exists)
{
    if (img4 == NULL || exists == NULL) {
        return DR_ParamErr;
    }
    *exists = (img4->manifestRaw.data != NULL);
    return 0;
}

int
Img4DecodeCopyManifestHash(TheImg4 *img4, void *hash, DERSize length)
{
    //unsigned char var_3C[20];

    if (img4 == NULL || hash == NULL || length != 20) {
        return DR_ParamErr;
    }
    if (img4->manifestRaw.data == NULL) {
        return DR_EndOfSequence;
    }
    if (!img4->manifestHashed) {
        panic("can't actually do this without sha1 impl");
//        sha1_digest(img4->manifestRaw.data, img4->manifestRaw.length, var_3C);
//        memmove(hash, var_3C, length);
        return 0;
    }
    if (length != 20) {
        return DR_BufOverflow;
    }
    memcpy(hash, img4->manifest.full_digest, 20);
    return 0;
}

int
Img4DecodeGetRestoreInfoNonce(TheImg4 *img4, DERTag etag, DERTag atag, DERMonster *dest)
{
    if (img4 == NULL || dest == NULL) {
        return DR_ParamErr;
    }
    if (img4->restoreInfo.nonce.data == NULL || img4->restoreInfo.nonce.length == 0) {
        return 0;
    }
    return DERImg4DecodeFindProperty(&img4->restoreInfo.nonce, etag, atag, dest);
}

int
Img4DecodeGetRestoreInfoData(TheImg4 *img4, DERTag tag, DERByte **a4, DERSize *a5)
{
    int rv;
    DERMonster var_40[2];

    if (img4 == NULL || a4 == NULL || a5 == NULL) {
        return DR_ParamErr;
    }
    rv = Img4DecodeGetRestoreInfoNonce(img4, E000000000000000 | tag, ASN1_OCTET_STRING, var_40);
    if (rv) {
        return rv;
    }
    *a4 = var_40[1].item.data;
    *a5 = var_40[1].item.length;
    return 0;
}

int
Img4DecodeGetPropertyInteger64(const DERItem *a1, DERTag tag, uint64_t *value)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_INTEGER) {
        return DR_UnexpectedTag;
    }

    return DERParseInteger64(&var_40[1].item, value);
}

int
Img4DecodeGetPropertyBoolean(const DERItem *a1, DERTag tag, bool *value)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_BOOLEAN) {
        return DR_UnexpectedTag;
    }

    return DERParseBoolean(&var_40[1].item, value);
}

int
Img4DecodeGetPropertyData(const DERItem *a1, DERTag tag, DERByte **a4, DERSize *a5)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_OCTET_STRING) {
        return DR_UnexpectedTag;
    }

    *a4 = var_40[1].item.data;
    *a5 = var_40[1].item.length;
    return 0;
}

int
Img4DecodeEvaluateCertificateProperties(TheImg4 *img4)
{
    int rv;
    DERItem var_130;
    DERItem var_118;
    DERMonster var_108[2];
    DERMonster var_D8[2];
    DERDecodedInfo var_A8;
    DERDecodedInfo var_90;
    DERTag tag;
    DERSequence var_70;
    DERSequence var_60;

    if (img4 == NULL) {
        return DR_ParamErr;
    }
    rv = DERDecodeSeqInit(&img4->manifest.img4_blob, &tag, &var_60);
    if (rv) {
        return rv;
    }

    if (tag != ASN1_CONSTR_SET) {
        return DR_UnexpectedTag;
    }

    while (!DERDecodeSeqNext(&var_60, &var_90)) {
        if (var_90.tag != (E000000000000000 | 'OBJP')) {
            if (var_90.tag != (E000000000000000 | 'MANP')) {
                return DR_UnexpectedTag;
            }
            var_130 = img4->manp;
        } else {
            var_130 = img4->objp;
        }

        rv = DERImg4DecodeProperty(&var_90.content, var_90.tag, var_D8);
        if (rv) {
            return rv;
        }

        if (var_D8[1].tag != ASN1_CONSTR_SET) {
            return DR_UnexpectedTag;
        }

        rv = DERDecodeSeqContentInit(&var_D8[1].item, &var_70);
        if (rv) {
            return rv;
        }

        while (!DERDecodeSeqNext(&var_70, &var_A8)) {
            rv = DERImg4DecodeProperty(&var_A8.content, var_A8.tag, var_108);
            if (rv) {
                return rv;
            }

            rv = DERImg4DecodeContentFindItemWithTag(&var_130, var_A8.tag, &var_118);
            if ((var_108[1].tag & (ASN1_CLASS_MASK | ASN1_METHOD_MASK)) > ASN1_CONTEXT_SPECIFIC) {
                if (var_108[1].tag != (ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC)) {
                    if (var_108[1].tag != (ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 1)) {
                        return DR_UnexpectedTag;
                    }
                    if (rv == DR_EndOfSequence) {
                        rv = 0;
                    }
                }
                if (rv) {
                    return rv;
                }
            } else {
                if (var_108[1].tag != ASN1_OCTET_STRING && var_108[1].tag != ASN1_INTEGER && var_108[1].tag != ASN1_BOOLEAN) {
                    return DR_UnexpectedTag;
                }
                if (rv) {
                    return rv;
                }
                if (!IS_EQUAL(var_A8.content, var_118)) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

int
Img4DecodeEvaluateDictionaryProperties(const DERItem *a1, DictType what, int (*property_cb)(DERTag, DERItem *, DictType, void *), void *ctx)
{
    int rv;
    DERMonster var_98[2];
    DERItem var_68;
    DERSequence var_58;
    DERDecodedInfo var_48;

    if (!property_cb) {
        return DR_ParamErr;
    }

    rv = DERDecodeSeqContentInit(a1, &var_58);
    if (rv) {
        return rv;
    }

    while (1) {
        rv = DERDecodeSeqNext(&var_58, &var_48);
        if (rv == DR_EndOfSequence) {
            return 0;
        }
        if (rv) {
            return rv;
        }
        rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
        if (rv) {
            return rv;
        }

        if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
            return DR_UnexpectedTag;
        }

        if ((var_48.tag & E000000000000000) == 0) {
            return DR_UnexpectedTag;
        }

        var_68.data = var_48.content.data;
        var_68.length = var_48.content.length;
        rv = property_cb(var_48.tag, &var_68, what, ctx);
        if (rv) {
            return rv;
        }
    }
}

int
Img4DecodeInit(DERByte *data, DERSize length, TheImg4 *img4)
{
    int rv;
    DERItem var_70[4];
    DERItem var_30;

    if (data == NULL || img4 == NULL) {
        return DR_ParamErr;
    }

    var_30.data = data;
    var_30.length = length;

    memset(var_70, 0, sizeof(var_70));
    memset(img4, 0, sizeof(TheImg4));

    rv = DERImg4Decode(&var_30, var_70);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodePayload(&var_70[1], &img4->payload);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeManifest(&var_70[2], &img4->manifest);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeRestoreInfo(&var_70[3], &img4->restoreInfo);
    if (rv) {
        return rv;
    }

    img4->payloadRaw = var_70[1];
    img4->manifestRaw = var_70[2];
    return 0;
}

static DERReturn
aDEREncodeItem(DERItem *item, DERTag tag, DERSize length, DERByte *src, bool freeOld)
{
    DERReturn rv;
    DERByte *old = freeOld ? src : NULL;
    DERSize inOutLen = DER_MAX_ENCODED_SIZE(length);
    DERByte *der = malloc(inOutLen);
    if (!der) {
        if (old)
            free(old);
        return -1;
    }

    rv = DEREncodeItem(tag, length, src, der, &inOutLen);
    if (old)
        free(old);
    if (rv) {
        if (der)
            free(der);
        return rv;
    }

    item->data = der;
    item->length = inOutLen;
    return 0;
}

static DERReturn
aDEREncodeSequence(DERItem *where, DERTag topTag, const void *src, DERShort numItems, const DERItemSpec *itemSpecs, int freeElt)
{
    int i;
    DERReturn rv;
    DERByte *der;
    DERSize inOutLen;
    DERByte *old = NULL;

    inOutLen = 1000; // XXX blah
    for (i = numItems - 1; i >= 0; i--) {
        const DERItem *item = (DERItem *)((char *)src + itemSpecs[i].offset);
        inOutLen += DER_MAX_ENCODED_SIZE(item->length);
        if (i == freeElt) {
            old = item->data;
        }
    }
    der = malloc(inOutLen);
    if (!der) {
        if (old)
            free(old);
        return -1;
    }

    rv = DEREncodeSequence(topTag, src, numItems, itemSpecs, der, &inOutLen);
    if (old)
        free(old);
    if (rv) {
        if (der)
            free(der);
        return rv;
    }

    where->data = der;
    where->length = inOutLen;
    return 0;
}
DERReturn Img4Encode(DERItem* out, DERItem* items, int itemLen) {
    return aDEREncodeSequence(out, ASN1_CONSTR_SEQUENCE, items, itemLen, DERImg4ItemSpecs, -1);
}
int
makeRestoreInfo(DERItem *where, void* nonceBytes, size_t nonceLength)
{
    int rv;
    char IM4R[] = "IM4R";
    char BNCN[] = "BNCN";

    DERItem item;
    DERItem elements[2];
    DERItem restoreInfo[2];

    elements[0].data = (DERByte *)BNCN;
    elements[0].length = sizeof(BNCN) - 1;
    elements[1].data = nonceBytes;
    elements[1].length = nonceLength;

    rv = aDEREncodeSequence(&item, ASN1_CONSTR_SEQUENCE, elements, 2, nonceItemSpecs, -1);
    if (rv) {
        return rv;
    }

    rv = aDEREncodeItem(restoreInfo + 1, ASN1_CONSTRUCTED | ASN1_PRIVATE | 'BNCN', item.length, item.data, true);
    if (rv) {
        return rv;
    }

    restoreInfo[0].data = (DERByte *)IM4R;
    restoreInfo[0].length = sizeof(IM4R) - 1;

    return aDEREncodeSequence(where, ASN1_CONSTR_SEQUENCE, restoreInfo, 2, DERImg4RestoreInfoItemSpecs, 1);
}
