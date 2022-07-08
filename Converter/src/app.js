"use strict";
exports.__esModule = true;
var metadataV3_1 = require("./converter/models/Keys/metadataV3");
var fs = require("node:fs");
/* METADATA V2
    let j = JSON.parse(fs.readFileSync("./FIDOV2Keys.txt", 'utf-8'))

let met = new metadataKeysV2(j.description,j.authenticatorVersion, j.upv,j.assertionScheme,j.authenticationAlgorithm,
    j.publicKeyAlgAndEncoding,j.attestationTypes,j.userVerificationDetails,j.isSecondFactorOnly,j.keyProtection,
    j.matcherProtection,j.cryptoStrength,j.attachmentHint,j.tcDisplay,j.attestationRootCertificates,
    j.legalHeader,j.aaid,j.aaguid,j.attestationCertificateKeyIdentifiers, j.alternativeDescriptions,j.protocolFamily,
    j.authenticationAlgorithms,j.publicKeyAlgAndEncodings,j.isKeyRestricted,j.isFreshUserVerificationRequired,j.operatingEnv,
    j.tcDisplayContentType,j.tcDisplayPNGCharacteristics,j.ecdaaTrustAnchors,j.icon,j.supportedExtensions);


let prova = metadataKeysV2.fromV2toV3(met)

let prova2 = metadataKeysV3.fromV3toV2(prova)

console.log(met)
console.log(prova)//mv2 -> mv3
console.log(prova2)//mv2->mv3->mv2
*/
var j = JSON.parse(fs.readFileSync("./FIDOV3Keys.txt", 'utf-8'));
var met = new metadataV3_1.metadataKeysV3(j.description, j.authenticatorVersion, j.upv, j.schema, j.attestationTypes, j.attestationCertificateKeyIdentifiers, j.userVerificationDetails, j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.keyProtection, j.matcherProtection, j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates, j.legalHeader, j.aaid, j.aaguid, j.alternativeDescriptions, j.protocolFamily, j.isKeyRestricted, j.isFreshUserVerificationRequired, j.tcDisplayContentType, j.tcDisplayPNGCharacteristics, j.ecdaaTrustAnchors, j.icon, j.supportedExtensions);
//console.log(met.validateAll())
var prova = metadataV3_1.metadataKeysV3.fromV3toV2(met);
//let prova2 = metadataKeysV2.fromV2toV3(prova)
//console.log(met.validateAll())
//console.log(prova.validateAll())
//console.log(prova2.validateAll())
/*
console.log(met)
console.log(prova)//mv2 -> mv3
console.log(prova2)//mv2->mv3->mv2

*/
console.log(met.attachmentHint);
console.log(prova.attachmentHint);
console.log(prova.validateData("attachmentHintCheck"));
/*
verifica v2

console.log(prova.validateData("aaidCheck"))
console.log(prova.validateData("aaguidCheck"))
console.log(prova.validateData("attestationCertificateKeyIdentifiersCheck"))
console.log(prova.validateData("authenticatorVersionCheck"))
console.log(prova.validateData("protocolFamilyCheck"))
console.log(prova.validateData("upvCheck"))
console.log(prova.validateData("assertionSchemeCheck"))
console.log(prova.validateData("authenticationAlgorithmCheck"))
console.log(prova.validateData("authenticationAlgorithmsCheck"))
console.log(prova.validateData("publicKeyAlgAndEncodingCheck"))
console.log(prova.validateData("publicKeyAlgAndEncodingsCheck"))
console.log(prova.validateData("attestationTypesCheck"))
console.log(prova.validateData("userVerificationDetailsCheck"))
console.log(prova.validateData("keyProtectionCheck"))
console.log(prova.validateData("matcherProtectionCheck"))
console.log(prova.validateData("cryptoStrengthCeck"))
console.log(prova.validateData("operatingEnvCheck"))
console.log(prova.validateData("attachmentHintCheck"))
console.log(prova.validateData("tcDisplayCheck"))
console.log(prova.validateData("tcDisplayContentTypeCheck"))
console.log(prova.validateData("tcDisplayPNGCharacteristicsCheck"))
console.log(prova.validateData("attestationRootCertificatesCheck"))
console.log(prova.validateData("ecdaaTrustAnchorsCheck"))
console.log(prova.validateData("iconCheck"))


*/ 
