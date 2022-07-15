"use strict";
exports.__esModule = true;
exports.V2toV3 = void 0;
var AuthenticatorGetInfo_1 = require("./../Keys/fields/AuthenticatorGetInfo");
var AuthenticatorOption_1 = require("./../Keys/fields/AuthenticatorOption");
var mapV2andV3_1 = require("./../Map/mapV2andV3");
//funzioni SOLO conversione: il cotrollo dovrà essere fatto in seguito
var V2toV3 = /** @class */ (function () {
    function V2toV3() {
    }
    V2toV3.convertAttestationTypes = function (attestationTypes) {
        var temp = new Array();
        for (var _i = 0, attestationTypes_1 = attestationTypes; _i < attestationTypes_1.length; _i++) {
            var obj = attestationTypes_1[_i];
            temp.push(String(mapV2andV3_1.V2andV3.attestationTypesConverter(obj)));
        }
        return temp;
    };
    // funzione singola, da iterare per fare la conversione completa
    V2toV3.convertUserVerificationDetails = function (userVerification) {
        return String(mapV2andV3_1.V2andV3.userVerificationDetailsConverter(userVerification));
    };
    //funzione per ottenere tutti i campi keyprotection
    V2toV3.convertKeyProtection = function (keyProtection) {
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
                keyV3.push(String(mapV2andV3_1.V2andV3.keyProtectionConverter((Math.pow(2, exp)))));
            }
        }
        if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
            return undefined;
        }
        else
            return keyV3;
    };
    //funzione per ottenere tutti i campi matcherProtection
    //non è stato fatto alcun ciclo in quanto essendo i campi mutuamente esclusivi nonostante il contenitore sia un array
    V2toV3.convertMatcherProtection = function (matcherProtection) {
        var keyV3 = new Array();
        keyV3.push(String(mapV2andV3_1.V2andV3.matcherProtectionConverter((matcherProtection))));
        if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
            return undefined;
        }
        return keyV3;
    };
    //funzione per ottenere tutti i campi attachmentHint
    V2toV3.convertAttachmentHint = function (attachmentHint) {
        var keyV3 = new Array();
        var temp = attachmentHint;
        for (var exp = 8; exp >= 0; exp--) {
            if ((Math.pow(2, exp)) <= temp) {
                temp = temp - (Math.pow(2, exp));
                keyV3.push(String(mapV2andV3_1.V2andV3.attachmentHintConverter((Math.pow(2, exp)))));
            }
        }
        if (keyV3.findIndex(function (element) { return element == undefined; }) != -1) {
            return undefined;
        }
        else
            return keyV3;
    };
    //funzione per ottenere tutti i campi attachmentHint
    V2toV3.convertTcDisplay = function (tcDisplay) {
        var keyV3 = new Array();
        var temp = tcDisplay;
        for (var exp = 4; exp >= 0; exp--) {
            if ((Math.pow(2, exp)) <= temp) {
                temp = temp - (Math.pow(2, exp));
                keyV3.push(String(mapV2andV3_1.V2andV3.tcDisplayConverter((Math.pow(2, exp)))));
            }
        }
        if (keyV3.findIndex(function (element) { return element == undefined; }) != -1)
            return undefined;
        else
            return keyV3;
    };
    //funzione per ottenere il campo schema
    //essendo conversione da MV2 a MV3 il campo schema sarà sempre di valore 3
    V2toV3.convertSchema = function () {
        return 3;
    };
    //funzione per ottenere il campo AuthenticatorGetInfo
    /**
     * ATTENZIONE:
     *      - il campo version avrebbe più valori possibili (es FIDO_2_1,..) in base alla versione CTAP
     *        (maggiorni informazioni qui: https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo)
     *
     *      - U2F_V2 non è mai da solo nel campo version, solitamente è posto insieme a FIDO_2_0
     */
    V2toV3.convertAuthenticatorGetInfo = function (aaguid, assertionScheme, isSecondFactorOnly, firmwareVersion) {
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
            return new AuthenticatorGetInfo_1.AuthenticatorGetInfo(version, aa, undefined, new AuthenticatorOption_1.AuthenticatorOption(undefined, undefined, undefined, undefined, true));
        else
            return new AuthenticatorGetInfo_1.AuthenticatorGetInfo(version, aa, undefined, new AuthenticatorOption_1.AuthenticatorOption(undefined, undefined, undefined, undefined, false), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, firmwareVersion);
    };
    // funzione singola per conversione dei codici degli algoritmi
    V2toV3.convertauthenticationAlgorithm = function (authenticationAlgorithm) {
        var temp = mapV2andV3_1.V2andV3.authenticationAlgorithmsConverter(authenticationAlgorithm);
        if (temp)
            return String(temp);
        return undefined;
    };
    // funzione singola per conversione dei codici delle chiavicodifica
    V2toV3.convertpublicKeyAlgAndEncoding = function (publicKeyAlgAndEncoding) {
        var temp = mapV2andV3_1.V2andV3.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
        if (temp)
            return String(temp);
        return undefined;
    };
    return V2toV3;
}());
exports.V2toV3 = V2toV3;
