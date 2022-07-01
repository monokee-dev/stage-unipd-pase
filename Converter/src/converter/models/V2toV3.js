"use strict";
exports.__esModule = true;
exports.MetadataConverterV2toV3 = void 0;
var V2toV3 = require("./Map/mapV2andV3");
function MetadataConverterV2toV3(mv2) {
    if (!mv2.validateAll())
        throw "Errore: il metadata inserito non rispetta le condizioni per i campi";
    else {
        //return new KeysV3.metadataKeysV3();
    }
}
exports.MetadataConverterV2toV3 = MetadataConverterV2toV3;
function convertAttestationTypesV2toV3(attestationTypes) {
    var temp = new Array();
    for (var _i = 0, attestationTypes_1 = attestationTypes; _i < attestationTypes_1.length; _i++) {
        var obj = attestationTypes_1[_i];
        temp.push(String(V2toV3.attestationTypesMap(obj)));
    }
    return temp;
}
var at;
at = [15880];
console.log(convertAttestationTypesV2toV3(at));
/*
function convertUserVerificationDetailsV2toV3(userVerification:number): string | undefined{
    let temp = new V2toV3.userVerificationDetailsMap();
    return temp.getString(userVerification);
}
function convertKeyProtectionV2toV3(){}
function convertMatcherProtectionV2toV3(){}
function convertAttachmentHintV2toV3(){}
function convertTcDisplayV2toV3(){}
function convertSchemaV2toV3(){}
function convertAuthenticatorGetInfoV2toV3(){}
*/
