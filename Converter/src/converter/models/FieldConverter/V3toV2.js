"use strict";
exports.__esModule = true;
exports.V3toV2 = void 0;
var V2V3Map = require("./../Map/mapV2andV3");
//ATTENZIONE capire cosa farne dei valori non trovati nelle conversioni stringa -> numero
var V3toV2 = /** @class */ (function () {
    function V3toV2() {
    }
    V3toV2.convertAttestationTypes = function (attestationTypes) {
        var temp = new Array();
        for (var _i = 0, attestationTypes_1 = attestationTypes; _i < attestationTypes_1.length; _i++) {
            var obj = attestationTypes_1[_i];
            temp.push(Number(V2V3Map.V2andV3.attestationTypesConverter(obj)));
        }
        return temp;
    };
    V3toV2.convertUserVerificationDetails = function (userVerification) {
        return Number(V2V3Map.V2andV3.userVerificationDetailsConverter(userVerification));
    };
    V3toV2.convertKeyProtection = function (keyProtection) {
        var keyV3 = 0;
        for (var i = 0; i < keyProtection.length; i++) {
            var temp = (Number(V2V3Map.V2andV3.keyProtectionConverter((keyProtection[i]))));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    };
    V3toV2.convertMatcherProtection = function (matcherProtection) {
        var keyV3 = 0;
        for (var i = 0; i < matcherProtection.length; i++) {
            var temp = (Number(V2V3Map.V2andV3.matcherProtectionConverter((matcherProtection[i]))));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    };
    V3toV2.convertAttachmentHint = function (attachmentHint) {
        var keyV3 = 0;
        for (var i = 0; i < attachmentHint.length; i++) {
            var temp = Number(V2V3Map.V2andV3.attachmentHintConverter((attachmentHint[i])));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    };
    V3toV2.convertTcDisplay = function (tcDisplay) {
        var keyV3 = 0;
        for (var i = 0; i < tcDisplay.length; i++) {
            var temp = (Number(V2V3Map.V2andV3.tcDisplayConverter((tcDisplay[i]))));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    };
    //in v3 protocolfamily è obbligatorio quindi sicuramente c'è
    V3toV2.convertAssertionSchema = function (protocolFamily) {
        if (protocolFamily == "u2f")
            return "U2FV1BIN";
        else if (protocolFamily == "fido2")
            return "FIDOV2";
        else //"uaf"
            return "UAFV1TLV";
    };
    // CAMPO NON OBBLIGATORIO
    V3toV2.convertCryptoStrength = function (cryptoStrength) {
        if (cryptoStrength == undefined)
            return undefined;
        return cryptoStrength;
    };
    // CAMPO NON OBBLIGATORIO
    //per ora lascio settato a true
    V3toV2.convertIsSecondFactorOnly = function (uv) {
        if (uv == undefined || uv == false)
            return true;
        else
            return false;
    };
    // CAMPO NON OBBLIGATORIO
    V3toV2.convertOperatingEnv = function () {
        return undefined;
    };
    V3toV2.convertauthenticationAlgorithm = function (authenticationAlgorithm) {
        var temp = V2V3Map.V2andV3.authenticationAlgorithmsConverter(authenticationAlgorithm);
        if (temp)
            return Number(temp);
        return undefined;
    };
    V3toV2.convertpublicKeyAlgAndEncoding = function (publicKeyAlgAndEncoding) {
        var temp = V2V3Map.V2andV3.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
        if (temp)
            return Number(temp);
        return undefined;
    };
    return V3toV2;
}());
exports.V3toV2 = V3toV2;
