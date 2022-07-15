import * as fs from "node:fs";
import { AuthenticatorGetInfo } from "./models/Keys/fields/AuthenticatorGetInfo";
import {ECDAATrustAnchor} from "./models/Keys/fields/ECDAATrustAnchor";
import {UserVerificationDetailsV3} from "./models/Keys/fields/UserVerificationDetails";
import {UserVerificationDetailsV2} from "./models/Keys/fields/UserVerificationDetails";

import { MetadataKeysV2 } from "./models/Keys/v2/MetadataV2";
import { MetadataKeysV3 } from "./models/Keys/v3/MetadataV3";


export function metadataInitializer(path: string): MetadataKeysV2 | MetadataKeysV3 {

    let j = JSON.parse(fs.readFileSync(path, 'utf-8'))

    let met;

    if (j.schema == undefined) {//metadata versione 2 in qualto schema in 3 è obbligatorio

        let usrVD = new Array();
        for(let i=0;i<j.userVerificationDetails.length;i++){
            usrVD.push(UserVerificationDetailsV2.fromJSON(j.userVerificationDetails));
        }

        met = new MetadataKeysV2(j.description, j.authenticatorVersion, j.upv, j.assertionScheme, j.authenticationAlgorithm,
            j.publicKeyAlgAndEncoding, j.attestationTypes, usrVD, j.isSecondFactorOnly, j.keyProtection,
            j.matcherProtection, j.cryptoStrength, j.attachmentHint, j.tcDisplay, j.attestationRootCertificates,
            j.legalHeader, j.aaid, j.aaguid, j.attestationCertificateKeyIdentifiers, j.alternativeDescriptions, j.protocolFamily,
            j.authenticationAlgorithms, j.publicKeyAlgAndEncodings, j.isKeyRestricted, j.isFreshUserVerificationRequired, j.operatingEnv,
            j.tcDisplayContentType, j.tcDisplayPNGCharacteristics, j.ecdaaTrustAnchors, j.icon, j.supportedExtensions);
    }
    else {
        let ecdaaTR = new Array();
        for(let i=0;i<j.ecdaaTrustAnchors.length;i++){
            ecdaaTR.push(ECDAATrustAnchor.fromJSON(j.ecdaaTrustAnchors));
        }

        let usrVD = new Array();
        for(let i=0;i<j.userVerificationDetails.length;i++){
            usrVD.push(UserVerificationDetailsV3.fromJSON(j.userVerificationDetails));
        }

        met = new MetadataKeysV3(
            j.description,
            j.authenticatorVersion,
            j.upv,
            j.schema,
            j.attestationTypes,
            j.attestationCertificateKeyIdentifiers,
            usrVD,
            j.authenticationAlgorithms,
            j.publicKeyAlgAndEncodings,
            j.keyProtection,
            j.matcherProtection,
            j.cryptoStrength,
            j.attachmentHint,
            j.tcDisplay,
            j.attestationRootCertificates,
            j.legalHeader,
            j.aaid,
            j.aaguid,
            j.alternativeDescriptions,
            j.protocolFamily,
            j.isKeyRestricted,
            j.isFreshUserVerificationRequired,
            j.tcDisplayContentType,
            j.tcDisplayPNGCharacteristics,
            ecdaaTR,
            j.icon,
            j.supportedExtensions,
            AuthenticatorGetInfo.fromJSON(j.authenticatorGetInfo)
        )
    }

    return met;
}