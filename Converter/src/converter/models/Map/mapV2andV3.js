"use strict";
exports.__esModule = true;
exports.publicKeyAlgAndEncodingsConverter = exports.authenticationAlgorithmsConverter = exports.tcDisplayConverter = exports.attachmentHintConverter = exports.matcherProtectionConverter = exports.keyProtectionConverter = exports.userVerificationDetailsConverter = exports.attestationTypesConverter = void 0;
function attestationTypesConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return attestationTypesEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in attestationTypesEnumMap) {
            if (iter === x) {
                return attestationTypesEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.attestationTypesConverter = attestationTypesConverter;
function userVerificationDetailsConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return userVerificationDetailsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in userVerificationDetailsEnumMap) {
            if (iter === x) {
                return userVerificationDetailsEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.userVerificationDetailsConverter = userVerificationDetailsConverter;
function keyProtectionConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return keyProtectionEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in keyProtectionEnumMap) {
            if (iter === x) {
                return keyProtectionEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.keyProtectionConverter = keyProtectionConverter;
function matcherProtectionConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return matcherProtectionEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in matcherProtectionEnumMap) {
            if (iter === x) {
                return matcherProtectionEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.matcherProtectionConverter = matcherProtectionConverter;
function attachmentHintConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return attachmentHintEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in attachmentHintEnumMap) {
            if (iter === x) {
                return attachmentHintEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.attachmentHintConverter = attachmentHintConverter;
function tcDisplayConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return tcDisplayEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in tcDisplayEnumMap) {
            if (iter === x) {
                return tcDisplayEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.tcDisplayConverter = tcDisplayConverter;
function authenticationAlgorithmsConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return authenticationAlgorithmsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in authenticationAlgorithmsEnumMap) {
            if (iter === x) {
                return authenticationAlgorithmsEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.authenticationAlgorithmsConverter = authenticationAlgorithmsConverter;
function publicKeyAlgAndEncodingsConverter(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return publicKeyAlgAndEncodingsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in publicKeyAlgAndEncodingsEnumMap) {
            if (iter === x) {
                return publicKeyAlgAndEncodingsEnumMap[iter];
            }
        }
        return undefined;
    }
}
exports.publicKeyAlgAndEncodingsConverter = publicKeyAlgAndEncodingsConverter;
var attestationTypesEnumMap;
(function (attestationTypesEnumMap) {
    attestationTypesEnumMap[attestationTypesEnumMap["basic_full"] = 15879] = "basic_full";
    attestationTypesEnumMap[attestationTypesEnumMap["basic_surrogate"] = 15880] = "basic_surrogate";
    attestationTypesEnumMap[attestationTypesEnumMap["ecdaa"] = 15881] = "ecdaa";
    attestationTypesEnumMap[attestationTypesEnumMap["attca"] = 15882] = "attca";
})(attestationTypesEnumMap || (attestationTypesEnumMap = {}));
var userVerificationDetailsEnumMap;
(function (userVerificationDetailsEnumMap) {
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["presence_internal"] = 1] = "presence_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["fingerprint_internal"] = 2] = "fingerprint_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["passcode_internal"] = 4] = "passcode_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["voiceprint_internal"] = 8] = "voiceprint_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["faceprint_internal"] = 16] = "faceprint_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["location_internal"] = 32] = "location_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["eyeprint_internal"] = 64] = "eyeprint_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["pattern_internal"] = 128] = "pattern_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["handprint_internal"] = 256] = "handprint_internal";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["none"] = 512] = "none";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["all"] = 1024] = "all";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["passcode_external"] = 2048] = "passcode_external";
    userVerificationDetailsEnumMap[userVerificationDetailsEnumMap["pattern_external"] = 4096] = "pattern_external";
})(userVerificationDetailsEnumMap || (userVerificationDetailsEnumMap = {}));
var keyProtectionEnumMap;
(function (keyProtectionEnumMap) {
    keyProtectionEnumMap[keyProtectionEnumMap["software"] = 1] = "software";
    keyProtectionEnumMap[keyProtectionEnumMap["hardware"] = 2] = "hardware";
    keyProtectionEnumMap[keyProtectionEnumMap["tee"] = 4] = "tee";
    keyProtectionEnumMap[keyProtectionEnumMap["secure_element"] = 8] = "secure_element";
    keyProtectionEnumMap[keyProtectionEnumMap["remote_handle"] = 16] = "remote_handle";
})(keyProtectionEnumMap || (keyProtectionEnumMap = {}));
var matcherProtectionEnumMap;
(function (matcherProtectionEnumMap) {
    matcherProtectionEnumMap[matcherProtectionEnumMap["software"] = 1] = "software";
    matcherProtectionEnumMap[matcherProtectionEnumMap["tee"] = 2] = "tee";
    matcherProtectionEnumMap[matcherProtectionEnumMap["on_chip"] = 4] = "on_chip";
})(matcherProtectionEnumMap || (matcherProtectionEnumMap = {}));
var attachmentHintEnumMap;
(function (attachmentHintEnumMap) {
    attachmentHintEnumMap[attachmentHintEnumMap["internal"] = 1] = "internal";
    attachmentHintEnumMap[attachmentHintEnumMap["external"] = 2] = "external";
    attachmentHintEnumMap[attachmentHintEnumMap["wired"] = 4] = "wired";
    attachmentHintEnumMap[attachmentHintEnumMap["wireless"] = 8] = "wireless";
    attachmentHintEnumMap[attachmentHintEnumMap["nfc"] = 16] = "nfc";
    attachmentHintEnumMap[attachmentHintEnumMap["bluetooth"] = 32] = "bluetooth";
    attachmentHintEnumMap[attachmentHintEnumMap["network"] = 64] = "network";
    attachmentHintEnumMap[attachmentHintEnumMap["ready"] = 128] = "ready";
    attachmentHintEnumMap[attachmentHintEnumMap["wifi_direct"] = 256] = "wifi_direct";
})(attachmentHintEnumMap || (attachmentHintEnumMap = {}));
var tcDisplayEnumMap;
(function (tcDisplayEnumMap) {
    tcDisplayEnumMap[tcDisplayEnumMap["any"] = 1] = "any";
    tcDisplayEnumMap[tcDisplayEnumMap["privileged_software"] = 2] = "privileged_software";
    tcDisplayEnumMap[tcDisplayEnumMap["tee"] = 4] = "tee";
    tcDisplayEnumMap[tcDisplayEnumMap["hardware"] = 8] = "hardware";
    tcDisplayEnumMap[tcDisplayEnumMap["remote"] = 16] = "remote";
})(tcDisplayEnumMap || (tcDisplayEnumMap = {}));
var authenticationAlgorithmsEnumMap;
(function (authenticationAlgorithmsEnumMap) {
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["secp256r1_ecdsa_sha256_raw"] = 1] = "secp256r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["secp256r1_ecdsa_sha256_der"] = 2] = "secp256r1_ecdsa_sha256_der";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pss_sha256_raw"] = 3] = "rsassa_pss_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pss_sha256_der"] = 4] = "rsassa_pss_sha256_der";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["esecp256k1_ecdsa_sha256_raw"] = 5] = "esecp256k1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["secp256k1_ecdsa_sha256_der"] = 6] = "secp256k1_ecdsa_sha256_der";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["sm2_sm3_raw"] = 7] = "sm2_sm3_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsa_emsa_pkcs1_sha256_raw"] = 8] = "rsa_emsa_pkcs1_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsa_emsa_pkcs1_sha256_der"] = 9] = "rsa_emsa_pkcs1_sha256_der";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pss_sha384_raw"] = 10] = "rsassa_pss_sha384_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pss_sha512_raw"] = 11] = "rsassa_pss_sha512_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pkcsv15_sha256_raw"] = 12] = "rsassa_pkcsv15_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pkcsv15_sha384_raw"] = 13] = "rsassa_pkcsv15_sha384_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pkcsv15_sha512_raw"] = 14] = "rsassa_pkcsv15_sha512_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["rsassa_pkcsv15_sha1_raw"] = 15] = "rsassa_pkcsv15_sha1_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["secp384r1_ecdsa_sha384_raw"] = 16] = "secp384r1_ecdsa_sha384_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["secp512r1_ecdsa_sha256_raw"] = 17] = "secp512r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumMap[authenticationAlgorithmsEnumMap["ed25519_eddsa_sha512_raw"] = 18] = "ed25519_eddsa_sha512_raw";
})(authenticationAlgorithmsEnumMap || (authenticationAlgorithmsEnumMap = {}));
var publicKeyAlgAndEncodingsEnumMap;
(function (publicKeyAlgAndEncodingsEnumMap) {
    publicKeyAlgAndEncodingsEnumMap[publicKeyAlgAndEncodingsEnumMap["ecc_x962_raw"] = 256] = "ecc_x962_raw";
    publicKeyAlgAndEncodingsEnumMap[publicKeyAlgAndEncodingsEnumMap["ecc_x962_der"] = 257] = "ecc_x962_der";
    publicKeyAlgAndEncodingsEnumMap[publicKeyAlgAndEncodingsEnumMap["rsa_2048_raw"] = 258] = "rsa_2048_raw";
    publicKeyAlgAndEncodingsEnumMap[publicKeyAlgAndEncodingsEnumMap["rsa_2048_der"] = 259] = "rsa_2048_der";
    publicKeyAlgAndEncodingsEnumMap[publicKeyAlgAndEncodingsEnumMap["cose"] = 260] = "cose";
})(publicKeyAlgAndEncodingsEnumMap || (publicKeyAlgAndEncodingsEnumMap = {}));
