import * as MV2 from './models/Keys/metadataV2';
import * as MV3 from './models/Keys/metadataV3';
import * as fs from "node:fs";


import { metadataKeysV2 } from "./models/Keys/metadataV2";
import { metadataKeysV3 } from "./models/Keys/metadataV3";

export function metadataInitializer(resource: string, ispath = false): metadataKeysV2 | metadataKeysV3 {
    let j
    if (ispath) {
        j = JSON.parse(fs.readFileSync(require('path').resolve(__dirname, './resources/' + resource), 'utf-8'))
    } else {
        j = JSON.parse(resource)
    }

    let met;

    if (j.schema == undefined) {//metadata versione 2 in qualto schema in 3 è obbligatorio
        met = new metadataKeysV2(j.description, j.authenticatorVersion, j.upv, j.assertionScheme, j.authenticationAlgorithm,
            j.publicKeyAlgAndEncoding, j.attestationTypes, j.userVerificationDetails, j.isSecondFactorOnly, j.keyProtection,
            j.matcherProtection, j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates,
            j.legalHeader, j.aaid, j.aaguid, j.attestationCertificateKeyIdentifiers, j.alternativeDescriptions, j.protocolFamily,
            j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.isKeyRestricted, j.isFreshUserVerificationRequired, j.operatingEnv,
            j.tcDisplayContentType, j.tcDisplayPNGCharacteristics, j.ecdaaTrustAnchors, j.icon, j.supportedExtensions);
    }
    else {// metadata versione 3
        met = new metadataKeysV3(j.description, j.authenticatorVersion, j.upv, j.schema,
            j.attestationTypes, j.attestationCertificateKeyIdentifiers, j.userVerificationDetails,
            j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.keyProtection, j.matcherProtection,
            j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates, j.legalHeader,
            j.aaid, j.aaguid, j.alternativeDescriptions, j.protocolFamily, j.isKeyRestricted,
            j.isFreshUserVerificationRequired, j.tcDisplayContentType, j.tcDisplayPNGCharacteristics,
            j.ecdaaTrustAnchors, j.icon, j.supportedExtensions, j.authenticatorGetInfo)
    }

    return met;
}