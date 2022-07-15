"use strict";
exports.__esModule = true;
exports.convertpublicKeyAlgAndEncodingV3toV2 = exports.convertauthenticationAlgorithmV3toV2 = exports.convertOperatingEnv3toV2 = exports.convertIsSecondFactorOnly3toV2 = exports.convertCryptoStrength3toV2 = exports.convertAssertionSchemaV3toV2 = exports.convertTcDisplayV3toV2 = exports.convertAttachmentHintV3toV2 = exports.convertMatcherProtectionV3toV2 = exports.convertKeyProtectionV3toV2 = exports.convertUserVerificationDetailsV3toV2 = exports.convertAttestationTypesV3toV2 = void 0;
var V2V3Map = require("./../Map/mapV2andV3");
//ATTENZIONE capire cosa farne dei valori non trovati nelle conversioni stringa -> numero
function convertAttestationTypesV3toV2(attestationTypes) {
    var temp = new Array();
    for (var _i = 0, attestationTypes_1 = attestationTypes; _i < attestationTypes_1.length; _i++) {
        var obj = attestationTypes_1[_i];
        temp.push(Number(V2V3Map.attestationTypesConverter(obj)));
    }
    return temp;
}
exports.convertAttestationTypesV3toV2 = convertAttestationTypesV3toV2;
function convertUserVerificationDetailsV3toV2(userVerification) {
    return Number(V2V3Map.userVerificationDetailsConverter(userVerification));
}
exports.convertUserVerificationDetailsV3toV2 = convertUserVerificationDetailsV3toV2;
function convertKeyProtectionV3toV2(keyProtection) {
    var keyV3 = 0;
    for (var i = 0; i < keyProtection.length; i++) {
        var temp = (Number(V2V3Map.keyProtectionConverter((keyProtection[i]))));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}
exports.convertKeyProtectionV3toV2 = convertKeyProtectionV3toV2;
function convertMatcherProtectionV3toV2(matcherProtection) {
    var keyV3 = 0;
    for (var i = 0; i < matcherProtection.length; i++) {
        var temp = (Number(V2V3Map.matcherProtectionConverter((matcherProtection[i]))));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}
exports.convertMatcherProtectionV3toV2 = convertMatcherProtectionV3toV2;
function convertAttachmentHintV3toV2(attachmentHint) {
    var keyV3 = 0;
    for (var i = 0; i < attachmentHint.length; i++) {
        var temp = Number(V2V3Map.attachmentHintConverter((attachmentHint[i])));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}
exports.convertAttachmentHintV3toV2 = convertAttachmentHintV3toV2;
function convertTcDisplayV3toV2(tcDisplay) {
    var keyV3 = 0;
    for (var i = 0; i < tcDisplay.length; i++) {
        var temp = (Number(V2V3Map.tcDisplayConverter((tcDisplay[i]))));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}
exports.convertTcDisplayV3toV2 = convertTcDisplayV3toV2;
//in v3 protocolfamily è obbligatorio quindi sicuramente c'è
function convertAssertionSchemaV3toV2(protocolFamily) {
    if (protocolFamily == "u2f")
        return "U2FV1BIN";
    else if (protocolFamily == "fido2")
        return "FIDOV2";
    else //"uaf"
        return "UAFV1TLV";
}
exports.convertAssertionSchemaV3toV2 = convertAssertionSchemaV3toV2;
// CAMPO NON OBBLIGATORIO
function convertCryptoStrength3toV2(cryptoStrength) {
    if (cryptoStrength == undefined)
        return undefined;
    return cryptoStrength;
}
exports.convertCryptoStrength3toV2 = convertCryptoStrength3toV2;
// CAMPO NON OBBLIGATORIO
//per ora lascio settato a true
function convertIsSecondFactorOnly3toV2(uv) {
    if (uv == undefined || uv == false)
        return true;
    else
        return false;
}
exports.convertIsSecondFactorOnly3toV2 = convertIsSecondFactorOnly3toV2;
// CAMPO NON OBBLIGATORIO
function convertOperatingEnv3toV2() {
    return undefined;
}
exports.convertOperatingEnv3toV2 = convertOperatingEnv3toV2;
function convertauthenticationAlgorithmV3toV2(authenticationAlgorithm) {
    var temp = V2V3Map.authenticationAlgorithmsConverter(authenticationAlgorithm);
    if (temp)
        return Number(temp);
    return undefined;
}
exports.convertauthenticationAlgorithmV3toV2 = convertauthenticationAlgorithmV3toV2;
function convertpublicKeyAlgAndEncodingV3toV2(publicKeyAlgAndEncoding) {
    var temp = V2V3Map.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
    if (temp)
        return Number(temp);
    return undefined;
}
exports.convertpublicKeyAlgAndEncodingV3toV2 = convertpublicKeyAlgAndEncodingV3toV2;
