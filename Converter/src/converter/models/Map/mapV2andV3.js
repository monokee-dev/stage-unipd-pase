"use strict";
exports.__esModule = true;
exports.publicKeyAlgAndEncodingsMap = exports.authenticationAlgorithmsMap = exports.tcDisplayMap = exports.attachmentHintMap = exports.matcherProtectionMap = exports.keyProtectionMap = exports.userVerificationDetailsMap = exports.attestationTypesMap = void 0;
function attestationTypesMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return attestationTypesEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in attestationTypesEnumConverter) {
            if (iter === x) {
                return attestationTypesEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.attestationTypesMap = attestationTypesMap;
function userVerificationDetailsMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return userVerificationDetailsEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in userVerificationDetailsEnumConverter) {
            if (iter === x) {
                return userVerificationDetailsEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.userVerificationDetailsMap = userVerificationDetailsMap;
function keyProtectionMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return keyProtectionEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in keyProtectionEnumConverter) {
            if (iter === x) {
                return keyProtectionEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.keyProtectionMap = keyProtectionMap;
function matcherProtectionMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return matcherProtectionEnumConvereter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in matcherProtectionEnumConvereter) {
            if (iter === x) {
                return matcherProtectionEnumConvereter[iter];
            }
        }
        return undefined;
    }
}
exports.matcherProtectionMap = matcherProtectionMap;
function attachmentHintMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return attachmentHintEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in attachmentHintEnumConverter) {
            if (iter === x) {
                return attachmentHintEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.attachmentHintMap = attachmentHintMap;
function tcDisplayMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return tcDisplayEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in tcDisplayEnumConverter) {
            if (iter === x) {
                return tcDisplayEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.tcDisplayMap = tcDisplayMap;
function authenticationAlgorithmsMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return authenticationAlgorithmsEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in authenticationAlgorithmsEnumConverter) {
            if (iter === x) {
                return authenticationAlgorithmsEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.authenticationAlgorithmsMap = authenticationAlgorithmsMap;
function publicKeyAlgAndEncodingsMap(x) {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if (typeof x === "number") {
        return publicKeyAlgAndEncodingsEnumConverter[x];
    }
    //se stringa si ritorna il valore numerico
    else if (typeof x === "string") {
        for (var iter in publicKeyAlgAndEncodingsEnumConverter) {
            if (iter === x) {
                return publicKeyAlgAndEncodingsEnumConverter[iter];
            }
        }
        return undefined;
    }
}
exports.publicKeyAlgAndEncodingsMap = publicKeyAlgAndEncodingsMap;
var attestationTypesEnumConverter;
(function (attestationTypesEnumConverter) {
    attestationTypesEnumConverter[attestationTypesEnumConverter["basic_full"] = 15879] = "basic_full";
    attestationTypesEnumConverter[attestationTypesEnumConverter["basic_surrogate"] = 15880] = "basic_surrogate";
    attestationTypesEnumConverter[attestationTypesEnumConverter["ecdaa"] = 15881] = "ecdaa";
    attestationTypesEnumConverter[attestationTypesEnumConverter["attca"] = 15882] = "attca";
})(attestationTypesEnumConverter || (attestationTypesEnumConverter = {}));
var userVerificationDetailsEnumConverter;
(function (userVerificationDetailsEnumConverter) {
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["presence_internal"] = 1] = "presence_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["fingerprint_internal"] = 2] = "fingerprint_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["passcode_internal"] = 4] = "passcode_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["voiceprint_internal"] = 8] = "voiceprint_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["faceprint_internal"] = 16] = "faceprint_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["location_internal"] = 32] = "location_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["eyeprint_internal"] = 64] = "eyeprint_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["pattern_internal"] = 128] = "pattern_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["handprint_internal"] = 256] = "handprint_internal";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["none"] = 512] = "none";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["all"] = 1024] = "all";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["passcode_external"] = 2048] = "passcode_external";
    userVerificationDetailsEnumConverter[userVerificationDetailsEnumConverter["pattern_external"] = 4096] = "pattern_external";
})(userVerificationDetailsEnumConverter || (userVerificationDetailsEnumConverter = {}));
var keyProtectionEnumConverter;
(function (keyProtectionEnumConverter) {
    keyProtectionEnumConverter[keyProtectionEnumConverter["software"] = 1] = "software";
    keyProtectionEnumConverter[keyProtectionEnumConverter["hardware"] = 2] = "hardware";
    keyProtectionEnumConverter[keyProtectionEnumConverter["tee"] = 4] = "tee";
    keyProtectionEnumConverter[keyProtectionEnumConverter["secure_element"] = 8] = "secure_element";
    keyProtectionEnumConverter[keyProtectionEnumConverter["remote_handle"] = 16] = "remote_handle";
})(keyProtectionEnumConverter || (keyProtectionEnumConverter = {}));
var matcherProtectionEnumConvereter;
(function (matcherProtectionEnumConvereter) {
    matcherProtectionEnumConvereter[matcherProtectionEnumConvereter["software"] = 1] = "software";
    matcherProtectionEnumConvereter[matcherProtectionEnumConvereter["tee"] = 2] = "tee";
    matcherProtectionEnumConvereter[matcherProtectionEnumConvereter["on_chip"] = 4] = "on_chip";
})(matcherProtectionEnumConvereter || (matcherProtectionEnumConvereter = {}));
var attachmentHintEnumConverter;
(function (attachmentHintEnumConverter) {
    attachmentHintEnumConverter[attachmentHintEnumConverter["internal"] = 1] = "internal";
    attachmentHintEnumConverter[attachmentHintEnumConverter["external"] = 2] = "external";
    attachmentHintEnumConverter[attachmentHintEnumConverter["wired"] = 4] = "wired";
    attachmentHintEnumConverter[attachmentHintEnumConverter["wireless"] = 8] = "wireless";
    attachmentHintEnumConverter[attachmentHintEnumConverter["nfc"] = 16] = "nfc";
    attachmentHintEnumConverter[attachmentHintEnumConverter["bluetooth"] = 32] = "bluetooth";
    attachmentHintEnumConverter[attachmentHintEnumConverter["network"] = 64] = "network";
    attachmentHintEnumConverter[attachmentHintEnumConverter["ready"] = 128] = "ready";
    attachmentHintEnumConverter[attachmentHintEnumConverter["wifi_direct"] = 256] = "wifi_direct";
})(attachmentHintEnumConverter || (attachmentHintEnumConverter = {}));
var tcDisplayEnumConverter;
(function (tcDisplayEnumConverter) {
    tcDisplayEnumConverter[tcDisplayEnumConverter["any"] = 1] = "any";
    tcDisplayEnumConverter[tcDisplayEnumConverter["privileged_software"] = 2] = "privileged_software";
    tcDisplayEnumConverter[tcDisplayEnumConverter["tee"] = 4] = "tee";
    tcDisplayEnumConverter[tcDisplayEnumConverter["hardware"] = 8] = "hardware";
    tcDisplayEnumConverter[tcDisplayEnumConverter["remote"] = 16] = "remote";
})(tcDisplayEnumConverter || (tcDisplayEnumConverter = {}));
var authenticationAlgorithmsEnumConverter;
(function (authenticationAlgorithmsEnumConverter) {
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["secp256r1_ecdsa_sha256_raw"] = 1] = "secp256r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["secp256r1_ecdsa_sha256_der"] = 2] = "secp256r1_ecdsa_sha256_der";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pss_sha256_raw"] = 3] = "rsassa_pss_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pss_sha256_der"] = 4] = "rsassa_pss_sha256_der";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["esecp256k1_ecdsa_sha256_raw"] = 5] = "esecp256k1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["secp256k1_ecdsa_sha256_der"] = 6] = "secp256k1_ecdsa_sha256_der";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["sm2_sm3_raw"] = 7] = "sm2_sm3_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsa_emsa_pkcs1_sha256_raw"] = 8] = "rsa_emsa_pkcs1_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsa_emsa_pkcs1_sha256_der"] = 9] = "rsa_emsa_pkcs1_sha256_der";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pss_sha384_raw"] = 10] = "rsassa_pss_sha384_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pss_sha512_raw"] = 11] = "rsassa_pss_sha512_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pkcsv15_sha256_raw"] = 12] = "rsassa_pkcsv15_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pkcsv15_sha384_raw"] = 13] = "rsassa_pkcsv15_sha384_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pkcsv15_sha512_raw"] = 14] = "rsassa_pkcsv15_sha512_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["rsassa_pkcsv15_sha1_raw"] = 15] = "rsassa_pkcsv15_sha1_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["secp384r1_ecdsa_sha384_raw"] = 16] = "secp384r1_ecdsa_sha384_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["secp512r1_ecdsa_sha256_raw"] = 17] = "secp512r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnumConverter[authenticationAlgorithmsEnumConverter["ed25519_eddsa_sha512_raw"] = 18] = "ed25519_eddsa_sha512_raw";
})(authenticationAlgorithmsEnumConverter || (authenticationAlgorithmsEnumConverter = {}));
var publicKeyAlgAndEncodingsEnumConverter;
(function (publicKeyAlgAndEncodingsEnumConverter) {
    publicKeyAlgAndEncodingsEnumConverter[publicKeyAlgAndEncodingsEnumConverter["ecc_x962_raw"] = 256] = "ecc_x962_raw";
    publicKeyAlgAndEncodingsEnumConverter[publicKeyAlgAndEncodingsEnumConverter["ecc_x962_der"] = 257] = "ecc_x962_der";
    publicKeyAlgAndEncodingsEnumConverter[publicKeyAlgAndEncodingsEnumConverter["rsa_2048_raw"] = 258] = "rsa_2048_raw";
    publicKeyAlgAndEncodingsEnumConverter[publicKeyAlgAndEncodingsEnumConverter["rsa_2048_der"] = 259] = "rsa_2048_der";
    publicKeyAlgAndEncodingsEnumConverter[publicKeyAlgAndEncodingsEnumConverter["cose"] = 260] = "cose";
})(publicKeyAlgAndEncodingsEnumConverter || (publicKeyAlgAndEncodingsEnumConverter = {}));
