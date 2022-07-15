"use strict";
exports.__esModule = true;
exports.convertpublicKeyAlgAndEncodingV2toV3 = exports.convertauthenticationAlgorithmV2toV3 = exports.convertAuthenticatorGetInfoV2toV3 = exports.convertSchemaV2toV3 = exports.convertTcDisplayV2toV3 = exports.convertAttachmentHintV2toV3 = exports.convertMatcherProtectionV2toV3 = exports.convertKeyProtectionV2toV3 = exports.convertUserVerificationDetailsV2toV3 = exports.convertAttestationTypesV2toV3 = void 0;
var KeysV3 = require("./../Keys/metadataV3");
var V2V3Map = require("./../Map/mapV2andV3");
//funzioni SOLO conversione: il cotrollo dovrà essere fatto in seguito
function convertAttestationTypesV2toV3(attestationTypes) {
    var temp = new Array();
    for (var _i = 0, attestationTypes_1 = attestationTypes; _i < attestationTypes_1.length; _i++) {
        var obj = attestationTypes_1[_i];
        temp.push(String(V2V3Map.attestationTypesConverter(obj)));
    }
    return temp;
}
exports.convertAttestationTypesV2toV3 = convertAttestationTypesV2toV3;
// funzione singola, da iterare per fare la conversione completa
function convertUserVerificationDetailsV2toV3(userVerification) {
    return String(V2V3Map.userVerificationDetailsConverter(userVerification));
}
exports.convertUserVerificationDetailsV2toV3 = convertUserVerificationDetailsV2toV3;
//funzione per ottenere tutti i campi keyprotection
function convertKeyProtectionV2toV3(keyProtection) {
    var keyV3 = new Array();
    var temp = keyProtection;
    /**
     * IDEA:
     *  -numero massimo valori: 16 = 2^4
     *  -uso variabile(exp) inizialmente con valore 4 che diminuisce ad ogni iterazione
     *  -se KeyProtection è minore di 2^exp eseguo sottrazione e chiamo funzione attestationTypesConverter
     *          perché sono sicuro che il valore sia presente
     *  -altrimenti decremento semplicemente exp
     */
    for (var exp = 4; exp >= 0; exp--) {
        if ((Math.pow(2, exp)) <= temp) {
            temp = temp - (Math.pow(2, exp));
            keyV3.push(String(V2V3Map.keyProtectionConverter((Math.pow(2, exp)))));
        }
    }
    if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
        return undefined;
    }
    else
        return keyV3;
}
exports.convertKeyProtectionV2toV3 = convertKeyProtectionV2toV3;
//funzione per ottenere tutti i campi matcherProtection
//non è stato fatto alcun ciclo in quanto essendo i campi mutuamente esclusivi nonostante il contenitore sia un array
function convertMatcherProtectionV2toV3(matcherProtection) {
    var keyV3 = new Array();
    keyV3.push(String(V2V3Map.matcherProtectionConverter((matcherProtection))));
    if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
        return undefined;
    }
    return keyV3;
}
exports.convertMatcherProtectionV2toV3 = convertMatcherProtectionV2toV3;
//funzione per ottenere tutti i campi attachmentHint
function convertAttachmentHintV2toV3(attachmentHint) {
    var keyV3 = new Array();
    var temp = attachmentHint;
    for (var exp = 8; exp >= 0; exp--) {
        if ((Math.pow(2, exp)) <= temp) {
            temp = temp - (Math.pow(2, exp));
            keyV3.push(String(V2V3Map.attachmentHintConverter((Math.pow(2, exp)))));
        }
    }
    if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
        return undefined;
    }
    else
        return keyV3;
}
exports.convertAttachmentHintV2toV3 = convertAttachmentHintV2toV3;
//funzione per ottenere tutti i campi attachmentHint
function convertTcDisplayV2toV3(tcDisplay) {
    var keyV3 = new Array();
    var temp = tcDisplay;
    for (var exp = 4; exp >= 0; exp--) {
        if ((Math.pow(2, exp)) <= temp) {
            temp = temp - (Math.pow(2, exp));
            keyV3.push(String(V2V3Map.tcDisplayConverter((Math.pow(2, exp)))));
        }
    }
    if (keyV3.findIndex(function (element) { return element == undefined; }) != -1)
        return undefined;
    else
        return keyV3;
}
exports.convertTcDisplayV2toV3 = convertTcDisplayV2toV3;
//funzione per ottenere il campo schema
//essendo conversione da MV2 a MV3 il campo schema sarà sempre di valore 3
function convertSchemaV2toV3() {
    return 3;
}
exports.convertSchemaV2toV3 = convertSchemaV2toV3;
//funzione per ottenere il campo AuthenticatorGetInfo
/**
 * ATTENZIONE:
 *      - il campo version avrebbe più valori possibili (es FIDO_2_1,..) in base alla versione CTAP
 *        (maggiorni informazioni qui: https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo)
 *
 *      - U2F_V2 non è mai da solo nel campo version, solitamente è posto insieme a FIDO_2_0
 */
function convertAuthenticatorGetInfoV2toV3(aaguid, assertionScheme, isSecondFactorOnly, firmwareVersion) {
    var version = new Array();
    var aa = aaguid.replace("-", "");
    if (assertionScheme == "FIDOV2") {
        version.push("FIDO_2_0");
    }
    if (assertionScheme == "U2FV1BIN") {
        version.push("U2F_V2");
    }
    if (version.length == 0) {
        return undefined;
    }
    if (isSecondFactorOnly == undefined || isSecondFactorOnly == false)
        return new KeysV3.AuthenticatorGetInfo(version, aa, undefined, new KeysV3.authenticatorOption(undefined, undefined, undefined, undefined, true));
    else
        return new KeysV3.AuthenticatorGetInfo(version, aa, undefined, new KeysV3.authenticatorOption(undefined, undefined, undefined, undefined, false), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, firmwareVersion);
}
exports.convertAuthenticatorGetInfoV2toV3 = convertAuthenticatorGetInfoV2toV3;
// funzione singola per conversione dei codici degli algoritmi
function convertauthenticationAlgorithmV2toV3(authenticationAlgorithm) {
    var temp = V2V3Map.authenticationAlgorithmsConverter(authenticationAlgorithm);
    if (temp)
        return String(temp);
    return undefined;
}
exports.convertauthenticationAlgorithmV2toV3 = convertauthenticationAlgorithmV2toV3;
// funzione singola per conversione dei codici delle chiavicodifica
function convertpublicKeyAlgAndEncodingV2toV3(publicKeyAlgAndEncoding) {
    var temp = V2V3Map.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
    if (temp)
        return String(temp);
    return undefined;
}
exports.convertpublicKeyAlgAndEncodingV2toV3 = convertpublicKeyAlgAndEncodingV2toV3;
