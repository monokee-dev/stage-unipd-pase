"use strict";
exports.__esModule = true;
exports.metadataInitializer = void 0;
var fs = require("node:fs");
var MetadataV2_1 = require("./models/Keys/v2/MetadataV2");
var MetadataV3_1 = require("./models/Keys/v3/MetadataV3");
function metadataInitializer(path) {
    var j = JSON.parse(fs.readFileSync(path, 'utf-8'));
    var met;
    if (j.schema == undefined) { //metadata versione 2 in qualto schema in 3 è obbligatorio
        met = new MetadataV2_1.MetadataKeysV2(j.description, j.authenticatorVersion, j.upv, j.assertionScheme, j.authenticationAlgorithm, j.publicKeyAlgAndEncoding, j.attestationTypes, j.userVerificationDetails, j.isSecondFactorOnly, j.keyProtection, j.matcherProtection, j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates, j.legalHeader, j.aaid, j.aaguid, j.attestationCertificateKeyIdentifiers, j.alternativeDescriptions, j.protocolFamily, j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.isKeyRestricted, j.isFreshUserVerificationRequired, j.operatingEnv, j.tcDisplayContentType, j.tcDisplayPNGCharacteristics, j.ecdaaTrustAnchors, j.icon, j.supportedExtensions);
    }
    else { // metadata versione 3
        met = new MetadataV3_1.MetadataKeysV3(j.description, j.authenticatorVersion, j.upv, j.schema, j.attestationTypes, j.attestationCertificateKeyIdentifiers, j.userVerificationDetails, j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.keyProtection, j.matcherProtection, j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates, j.legalHeader, j.aaid, j.aaguid, j.alternativeDescriptions, j.protocolFamily, j.isKeyRestricted, j.isFreshUserVerificationRequired, j.tcDisplayContentType, j.tcDisplayPNGCharacteristics, j.ecdaaTrustAnchors, j.icon, j.supportedExtensions, j.authenticatorGetInfo);
    }
    return met;
}
exports.metadataInitializer = metadataInitializer;
