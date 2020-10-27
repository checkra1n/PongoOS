/*
 * Copyright (c) 2005-2009,2011-2014 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */


/*
 * oids.h - declaration of OID consts
 *
 */

#ifndef	_LIB_DER_OIDS_H_
#define _LIB_DER_OIDS_H_

#include <libDER/libDER.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm oids. */
extern const DERItem
    oidRsa,         /* PKCS1 RSA encryption, used to identify RSA keys */
    oidMd2Rsa,      /* PKCS1 md2withRSAEncryption signature alg */
    oidMd5Rsa,      /* PKCS1 md5withRSAEncryption signature alg */
    oidSha1Rsa,     /* PKCS1 sha1withRSAEncryption signature alg */
    oidSha256Rsa,   /* PKCS1 sha256WithRSAEncryption signature alg */
    oidEcPubKey,    /* ECDH or ECDSA public key in a certificate */
    oidSha1Ecdsa,   /* ECDSA with SHA1 signature alg */
    oidSha224Ecdsa, /* ECDSA with SHA224 signature alg */
    oidSha256Ecdsa, /* ECDSA with SHA256 signature alg */
    oidSha384Ecdsa, /* ECDSA with SHA384 signature alg */
    oidSha512Ecdsa, /* ECDSA with SHA512 signature alg */
    oidMd2,         /* OID_RSA_HASH 2 */
    oidMd4,         /* OID_RSA_HASH 4 */
    oidMd5,         /* OID_RSA_HASH 5 */
    oidSha1,        /* OID_OIW_ALGORITHM 26 */
    oidSha256,      /* OID_NIST_HASHALG 1 */
    oidSha384,      /* OID_NIST_HASHALG 2 */
    oidSha512,      /* OID_NIST_HASHALG 3 */
    oidSha224;      /* OID_NIST_HASHALG 4 */

/* Standard X.509 Cert and CRL extensions. */
extern const DERItem
    oidSubjectKeyIdentifier,
    oidKeyUsage,
    oidPrivateKeyUsagePeriod,
    oidSubjectAltName,
    oidIssuerAltName,
    oidBasicConstraints,
    oidCrlDistributionPoints,
    oidCertificatePolicies,
    oidAnyPolicy,
    oidPolicyMappings,
    oidAuthorityKeyIdentifier,
    oidPolicyConstraints,
    oidExtendedKeyUsage,
    oidAnyExtendedKeyUsage,
    oidInhibitAnyPolicy,
    oidAuthorityInfoAccess,
    oidSubjectInfoAccess,
    oidAdOCSP,
    oidAdCAIssuer,
    oidNetscapeCertType,
    oidEntrustVersInfo,
    oidMSNTPrincipalName,
    /* Policy Qualifier IDs for Internet policy qualifiers. */
    oidQtCps,
    oidQtUNotice,
    /* X.501 Name IDs. */
    oidCommonName,
    oidCountryName,
    oidLocalityName,
    oidStateOrProvinceName,
    oidOrganizationName,
    oidOrganizationalUnitName,
    oidDescription,
    oidEmailAddress,
    oidFriendlyName,
    oidLocalKeyId,
    oidExtendedKeyUsageServerAuth,
    oidExtendedKeyUsageClientAuth,
    oidExtendedKeyUsageCodeSigning,
    oidExtendedKeyUsageEmailProtection,
    oidExtendedKeyUsageOCSPSigning,
    oidExtendedKeyUsageIPSec,
    oidExtendedKeyUsageMicrosoftSGC,
    oidExtendedKeyUsageNetscapeSGC,
    /* Secure Boot Spec oid */
    oidAppleSecureBootCertSpec,
    oidAppleProvisioningProfile,
    oidAppleApplicationSigning,
    oidAppleInstallerPackagingSigningExternal,
    oidAppleExtendedKeyUsageAppleID,
    oidAppleExtendedKeyUsageShoebox,
    oidAppleExtendedKeyUsageProfileSigning,
    oidAppleExtendedKeyUsageQAProfileSigning,
    oidAppleIntmMarkerAppleID,
    oidAppleIntmMarkerAppleID2,
    oidApplePushServiceClient,
    oidApplePolicyMobileStore,
    oidApplePolicyTestMobileStore,
    oidApplePolicyEscrowService,
    oidAppleCertExtensionAppleIDRecordValidationSigning,
    oidAppleIntmMarkerAppleSystemIntg2,
    oidAppleIntmMarkerAppleSystemIntgG3,
    oidAppleCertExtAppleSMPEncryption,
    oidAppleCertExtAppleServerAuthentication,
    oidAppleIntmMarkerAppleServerAuthentication;

/* Compare two decoded OIDs.  Returns true iff they are equivalent. */
bool DEROidCompare(const DERItem *oid1, const DERItem *oid2);

#ifdef __cplusplus
}
#endif

#endif	/* _LIB_DER_UTILS_H_ */
