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

DERReturn DERImg4DecodeTagCompare(const DERItem *der, uint32_t name);
DERReturn DERImg4Decode(const DERItem *der, DERItem *items);
DERReturn DERImg4DecodePayload(const DERItem *der, Img4Payload *payload);
DERReturn DERImg4DecodeManifest(const DERItem *der, Img4Manifest *manifest);
DERReturn DERImg4DecodeRestoreInfo(const DERItem *der, Img4RestoreInfo *restoreInfo);
DERReturn Img4DecodeGetPayload(const Img4 *img4, DERItem *item);
DERReturn Img4DecodeGetPayloadType(const Img4 *img4, uint32_t *type);
DERReturn Img4DecodeGetPayloadKeybag(const Img4 *img4, DERItem *kbag);
DERReturn Img4DecodeInit(const DERByte *data, DERSize length, Img4 *img4);
DERReturn Img4Encode(DERItem *der, const DERItem *items);
DERReturn Img4EncodeRestoreInfo(DERItem *der, void *bytes, size_t len);
DERReturn Img4EncodeSequence(DERTag tag, const void *src, DERShort numItems, const DERItemSpec *itemSpecs, DERItem *der);
