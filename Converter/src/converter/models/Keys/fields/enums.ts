
export enum V3FunctionName {
    "aaid" = 1,
    "aaguid" = 2,
    "attestationCertificateKeyIdentifiers" = 3,
    "authenticatorVersion" = 4,
    "protocolFamily" = 5,
    "schema" = 6,
    "upv" = 7,
    "authenticationAlgorithms" = 8,
    "publicKeyAlgAndEncodings" = 9,
    "attestationTypes" = 10,
    "userVerificationDetails" = 11,
    "keyProtection" = 12,
    "matcherProtection" = 13,
    "cryptoStrength" = 14,
    "attachmentHint" = 15,
    "tcDisplay" = 16,
    "tcDisplayContentType" = 17,
    "tcDisplayPNGCharacteristics" = 18,
    "attestationRootCertificates" = 19,
    "ecdaaTrustAnchors" = 20,
    "icon" = 21,
    "authenticatorGetInfo" = 22,
    //supportedExtensions = 23,
}

export enum V2FunctionName{
    "aaid" = 1,
    "aaguid" = 2,
    "attestationCertificateKeyIdentifiers" = 3,
    "authenticatorVersion" = 4,
    "protocolFamily" = 5,
    "upv" = 6,
    "assertionScheme" = 7,
    "authenticationAlgorithm" = 8,
    "authenticationAlgorithms" = 9,
    "publicKeyAlgAndEncoding" = 10,
    "publicKeyAlgAndEncodings" = 11,
    "attestationTypes" = 12,
    "userVerificationDetails" = 13,
    "keyProtection" = 14,
    "matcherProtection" = 15,
    "cryptoStrengthCeck" = 16,
    "operatingEnv" = 17,
    "attachmentHint" = 18,
    "tcDisplay" = 19,
    "tcDisplayContentType" = 20,
    "tcDisplayPNGCharacteristics" = 21,
    "attestationRootCertificates" = 22,
    "ecdaaTrustAnchors" = 23,
    "icon" = 24,
    //supportedExtensions = 25,   
}

export enum assertionSchemeEnum{
    "U2FV1BIN",
    "FIDOV2",
    "UAFV1TLV",
}

export enum tcDisplayEnum {
    "any",
    "privileged_software",
    "tee",
    "hardware",
    "remote",
}

export enum attachmentHintEnum {
    "internal",
    "external",
    "wired",
    "wireless",
    "nfc",
    "bluetooth",
    "network",
    "ready",
    "wifi_direct",
}

export enum matcherProtectionEnum {
    "software",
    "tee",
    "on_chip",
}

export enum keyProtectionEnum {
    "software",
    "hardware",
    "tee",
    "secure_element",
    "remote_handle",
}

export enum protocolFamilyEnum {
    "uaf",
    "u2f",
    "fido2",
}

//errore documentazione: 0x000B == 0x003 (solo nome tra virgolette)
export enum authenticationAlgorithmsEnum {
    "secp256r1_ecdsa_sha256_raw",
    "secp256r1_ecdsa_sha256_der",
    "rsassa_pss_sha256_raw",
    "rsassa_pss_sha256_der",
    "secp256k1_ecdsa_sha256_raw",
    "secp256k1_ecdsa_sha256_der",
    "sm2_sm3_raw",
    "rsa_emsa_pkcs1_sha256_raw",
    "rsa_emsa_pkcs1_sha256_der",
    "rsassa_pss_sha384_raw",
    "rsassa_pss_sha512_raw",
    "rsassa_pkcsv15_sha256_raw",
    "rsassa_pkcsv15_sha384_raw",
    "rsassa_pkcsv15_sha512_raw",
    "rsassa_pkcsv15_sha1_raw",
    "secp384r1_ecdsa_sha384_raw",
    "secp512r1_ecdsa_sha256_raw",
    "ed25519_eddsa_sha512_raw",
}

export enum publicKeyAlgAndEncodingsEnum {
    "ecc_x962_raw",
    "ecc_x962_der",
    "rsa_2048_raw",
    "rsa_2048_der",
    "cose",
}

export enum attestationTypesEnum {
    "basic_full",
    "basic_surrogate",
    "ecdaa",
    "attca",
}

export enum tcDisplayContentTypeEnum {
    "application/octet-stream",
    "application/postscript",
    "message/external-body",
    "message/rfc822",
    "audio/basic",
    "image/jpeg",
    "image/gif",
    "image/png",
    "text/enriched",
    "text/plain",
    "text/foo",
}

export enum operatingEnvEnum {
    "TEEs based on ARM TrustZone HW",
    "TEE Based on Intel VT HW",
    "TEE Based on Intel SGX HW",
    "TEE Based on Intel ME/TXE HW",
    "TEE with GlobalPlatform TEE Protection Profile Certification",
    "Windows 10 Virtualization-based Security",
    "Secure World of AMD PSP (Platform Security coProcessor)",
    "Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications",
    "Secure Element (SE)",
}

export enum VerificationMethodDescriptorUserVerificationMethodEnum {
    "error",
    "presence_internal",
    "fingerprint_internal",
    "passcode_internal",
    "voiceprint_internal",
    "faceprint_internal",
    "location_internal",
    "eyeprint_internal",
    "pattern_internal",
    "handprint_internal",
    "none",
    "all",
    "passcode_external",
    "pattern_external",
}
export enum G1CurveEnum {
    "BN_P256",
    "BN_P638",
    "BN_ISOP256",
    "BN_ISOP512",
}