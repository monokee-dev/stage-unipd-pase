"use strict";
exports.__esModule = true;
exports.ecdaaTrustAnchor = exports.attestationRootCertificates = exports.tcDisplayPNGCharacteristicsDescriptor = exports.supportedExtensions = exports.userVerificationDetails = exports.metadataKeysV2 = void 0;
var metadataKeysV2 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function metadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm, publicKeyAlgAndEncoding, attestationTypes, userVerificationDetails, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms, publicKeyAlgAndEncodings, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, isSecondFactorOnly, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions) {
        if (authenticatorVersion === void 0) { authenticatorVersion = 0; }
        if (protocolFamily === void 0) { protocolFamily = "uaf"; }
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.upv = Array.from(upv);
        this.assertionScheme = assertionScheme;
        this.authenticationAlgorithm = authenticationAlgorithm;
        this.authenticationAlgorithms = Array.from(authenticationAlgorithms);
        this.publicKeyAlgAndEncoding = publicKeyAlgAndEncoding;
        this.publicKeyAlgAndEncodings = Array.from(publicKeyAlgAndEncodings);
        this.attestationTypes = attestationTypes;
        this.userVerificationDetails = userVerificationDetails;
        this.keyProtection = keyProtection;
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = matcherProtection;
        this.cryptoStrength = cryptoStrength;
        this.operatingEnv = operatingEnv;
        this.attachmentHint = attachmentHint;
        this.isSecondFactorOnly = isSecondFactorOnly;
        this.tcDisplay = tcDisplay;
        this.tcDisplayContentType = tcDisplayContentType;
        this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        this.attestationRootCertificates = attestationRootCertificates;
        this.ecdaaTrustAnchors = Array.from(ecdaaTrustAnchors);
        this.icon = icon;
        this.supportedExtensions = Array.from(supportedExtensions);
    }
    //funzione validazione singolo campo
    metadataKeysV2.prototype.validateData = function () {
        return true;
    };
    //funzione validazione per tutti i campi
    metadataKeysV2.prototype.validateAll = function () {
        // legalHeader non controllato: è una stringa
        if (this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() &&
            this.protocolFamilyCheck() && this.assertionSchemeCheck() && this.authenticationAlgorithmCheck() &&
            this.authenticationAlgorithmsCheck() && this.publicKeyAlgAndEncodingCheck() &&
            this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
            this.keyProtectionCheck() && this.matcherProtectionCheck() && this.operatingEnvCheck() &&
            this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() &&
            this.tcDisplayPNGCharacteristicsCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck() &&
            this.supportedExtensionsCheck()) {
            return true;
        }
        return false;
    };
    //controllo upv
    /*
        jsonParsed[0]["minor"] == 1){
    */
    // controllo cryptoStrength 
    //isSecondFactorOnly non controllato, o bool o undefined
    //capire attestationRootCertificates (da fare, validare certificato, guardare: https://nodejs.org/api/crypto.html#new-x509certificatebuffer)
    //if(this.attestationRootCertificates)
    /**
     * Controlli:
     *          1) che la stringa, se presente sia conforme a quanto riportato qui: https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef
     *          2) che il campo sia presente nel caso protocol family sia settato su "uaf"
     */
    metadataKeysV2.prototype.aaidCheck = function () {
        if (this.aaid != undefined && !RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid))
            return false;
        if (this.protocolFamily == "uaf" && this.aaid == undefined)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example
     *          2) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          3) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     */
    metadataKeysV2.prototype.aaguidCheck = function () {
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                return false;
        }
        if (this.protocolFamily == "fido2" && this.aaguid == undefined)
            return false;
        if (this.protocolFamily == "uaf" && this.aaguid != undefined)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) codificato con stringa esadecimale (tutte le lettere devono esserte in lowercase)
     *          2) il campo deve essere presente se né aaid né aaguid sono presenti
     */
    metadataKeysV2.prototype.attestationCertificateKeyIdentifiersCheck = function () {
        if (this.attestationCertificateKeyIdentifiers != undefined) {
            for (var i = 0; i < this.attestationCertificateKeyIdentifiers.length; i++) {
                if (!RegExp(/^[0-9a-f]$/i).test(this.attestationCertificateKeyIdentifiers[i]))
                    return false;
            }
        }
        return true;
    };
    metadataKeysV2.prototype.protocolFamilyCheck = function () {
        if (this.protocolFamily != undefined && this.protocolFamily != "uaf" && this.protocolFamily != "u2f" && this.protocolFamily != "fido2")
            return false;
        return true;
    };
    metadataKeysV2.prototype.assertionSchemeCheck = function () {
        if (assertionSchemeEnum[this.assertionScheme] == undefined)
            return false;
        return true;
    };
    metadataKeysV2.prototype.authenticationAlgorithmCheck = function () {
        if (this.authenticationAlgorithm < 1 || this.authenticationAlgorithm > 18)
            return false;
        return true;
    };
    metadataKeysV2.prototype.authenticationAlgorithmsCheck = function () {
        if (this.authenticationAlgorithms != undefined) {
            for (var i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (this.authenticationAlgorithms[i] < 1 || this.authenticationAlgorithms[i] > 18)
                    return false;
            }
        }
        return true;
    };
    metadataKeysV2.prototype.publicKeyAlgAndEncodingCheck = function () {
        if (this.publicKeyAlgAndEncoding < 256 || this.publicKeyAlgAndEncoding > 260)
            return false;
        return true;
    };
    metadataKeysV2.prototype.publicKeyAlgAndEncodingsCheck = function () {
        if (this.publicKeyAlgAndEncodings != undefined) {
            for (var i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (this.publicKeyAlgAndEncodings[i] < 256 || this.publicKeyAlgAndEncodings[i] > 260)
                    return false;
            }
        }
        return true;
    };
    metadataKeysV2.prototype.attestationTypesCheck = function () {
        for (var i = 0; i < this.attestationTypes.length; i++) {
            if (this.attestationTypes[i] < 15879 || this.attestationTypes[i] > 15882)
                return false;
        }
        return true;
    };
    metadataKeysV2.prototype.userVerificationDetailsCheck = function () {
        for (var i = 0; i < this.userVerificationDetails.length; i++) {
            if (!this.userVerificationDetails[i].validateData())
                return false;
        }
        return true;
    };
    metadataKeysV2.prototype.keyProtectionCheck = function () {
        if (this.keyProtection < 1 || this.keyProtection > 16)
            return false;
        return true;
    };
    metadataKeysV2.prototype.matcherProtectionCheck = function () {
        if (this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            return false;
        return true;
    };
    metadataKeysV2.prototype.operatingEnvCheck = function () {
        if (this.operatingEnv != undefined) {
            if (operatingEnvEnum[this.operatingEnv] == undefined)
                return false;
        }
        return true;
    };
    metadataKeysV2.prototype.attachmentHintCheck = function () {
        if (this.attachmentHint != (1 && 2 && 4 && 8 && 16 && 32 && 64 && 128 && 256 && 512))
            return false;
        return true;
    };
    metadataKeysV2.prototype.tcDisplayCheck = function () {
        if (this.tcDisplay > 16 || this.tcDisplay < 0) {
            return false;
        }
        return true;
    };
    metadataKeysV2.prototype.tcDisplayContentTypeCheck = function () {
        if (this.tcDisplay != 0 && this.tcDisplayContentType == undefined)
            return false;
        if (this.tcDisplayContentType != undefined) {
            if (tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                return false;
        }
        return true;
    };
    metadataKeysV2.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != 0 && tcDisplayContentTypeEnum[this.tcDisplayContentType] == tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            return false;
        return true;
    };
    metadataKeysV2.prototype.ecdaaTrustAnchorsCheck = function () {
        if (this.ecdaaTrustAnchors != undefined) {
            for (var i = 0; i < this.ecdaaTrustAnchors.length; i++) {
                if (!this.ecdaaTrustAnchors[i].validateData())
                    return false;
            }
        }
        return true;
    };
    metadataKeysV2.prototype.iconCheck = function () {
        if (this.icon != undefined) {
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(this.icon)) {
                return false;
            }
        }
        return true;
    };
    metadataKeysV2.prototype.supportedExtensionsCheck = function () {
        if (this.supportedExtensions != undefined) {
            return false;
        }
        return true;
    };
    return metadataKeysV2;
}());
exports.metadataKeysV2 = metadataKeysV2;
var Version = /** @class */ (function () {
    function Version(ma, mi) {
        this.major = ma;
        this.minor = mi;
    }
    return Version;
}());
var tcDisplayContentTypeEnum;
(function (tcDisplayContentTypeEnum) {
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["application/octet-stream"] = 0] = "application/octet-stream";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["application/postscript"] = 1] = "application/postscript";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["message/external-body"] = 2] = "message/external-body";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["message/rfc822"] = 3] = "message/rfc822";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["audio/basic"] = 4] = "audio/basic";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["image/jpeg"] = 5] = "image/jpeg";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["image/gif"] = 6] = "image/gif";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["image/png"] = 7] = "image/png";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["text/enriched"] = 8] = "text/enriched";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["text/plain"] = 9] = "text/plain";
    tcDisplayContentTypeEnum[tcDisplayContentTypeEnum["text/foo"] = 10] = "text/foo";
})(tcDisplayContentTypeEnum || (tcDisplayContentTypeEnum = {}));
var operatingEnvEnum;
(function (operatingEnvEnum) {
    operatingEnvEnum[operatingEnvEnum["TEEs based on ARM TrustZone HW"] = 0] = "TEEs based on ARM TrustZone HW";
    operatingEnvEnum[operatingEnvEnum["TEE Based on Intel VT HW"] = 1] = "TEE Based on Intel VT HW";
    operatingEnvEnum[operatingEnvEnum["TEE Based on Intel SGX HW"] = 2] = "TEE Based on Intel SGX HW";
    operatingEnvEnum[operatingEnvEnum["TEE Based on Intel ME/TXE HW"] = 3] = "TEE Based on Intel ME/TXE HW";
    operatingEnvEnum[operatingEnvEnum["TEE with GlobalPlatform TEE Protection Profile Certification"] = 4] = "TEE with GlobalPlatform TEE Protection Profile Certification";
    operatingEnvEnum[operatingEnvEnum["Windows 10 Virtualization-based Security"] = 5] = "Windows 10 Virtualization-based Security";
    operatingEnvEnum[operatingEnvEnum["Secure World of AMD PSP (Platform Security coProcessor)"] = 6] = "Secure World of AMD PSP (Platform Security coProcessor)";
    operatingEnvEnum[operatingEnvEnum["Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications"] = 7] = "Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications";
    operatingEnvEnum[operatingEnvEnum["Secure Element (SE)"] = 8] = "Secure Element (SE)";
})(operatingEnvEnum || (operatingEnvEnum = {}));
var assertionSchemeEnum;
(function (assertionSchemeEnum) {
    assertionSchemeEnum[assertionSchemeEnum["U2FV1BIN"] = 0] = "U2FV1BIN";
    assertionSchemeEnum[assertionSchemeEnum["FIDOV2"] = 1] = "FIDOV2";
    assertionSchemeEnum[assertionSchemeEnum["UAFV1TLV"] = 2] = "UAFV1TLV";
})(assertionSchemeEnum || (assertionSchemeEnum = {}));
function a(value) {
    var result = assertionSchemeEnum[value];
    return result;
}
var CodeAccuracyDescriptor = /** @class */ (function () {
    function CodeAccuracyDescriptor(ba, mL, mR, bl) {
        this.base = ba;
        this.minLength = mL;
        this.maxRetries = mR;
        this.blockSlowdown = bl;
    }
    return CodeAccuracyDescriptor;
}());
var BiometricAccuracyDescriptor = /** @class */ (function () {
    function BiometricAccuracyDescriptor(SFR, SFA, mT, mR, bls) {
        this.selfAttestedFRR = SFR;
        this.selfAttestedFAR = SFA;
        this.maxTemplates = mT;
        this.maxRetries = mR;
        this.blockSlowdown = bls;
    }
    return BiometricAccuracyDescriptor;
}());
var PatternAccuracyDescriptor = /** @class */ (function () {
    function PatternAccuracyDescriptor(ba, mL, bl) {
        this.minComplexity = ba;
        this.maxRetries = mL;
        this.blockSlowdown = bl;
    }
    return PatternAccuracyDescriptor;
}());
var VerificationMethodDescriptor = /** @class */ (function () {
    function VerificationMethodDescriptor(uv, c, b, p) {
        if (uv === void 0) { uv = 0; }
        this.userVerification = uv;
        this.caDesc = c;
        this.baDesc = b;
        this.paDesc = p;
    }
    VerificationMethodDescriptor.prototype.validateData = function () {
        if (this.userVerification == 0 || this.userVerification != 1024 || 512 || 256 || 128 || 64 || 32 || 16 || 8 || 4 || 2 || 1)
            return false;
        else
            return true;
    };
    return VerificationMethodDescriptor;
}());
var VerificationMethodANDCombinations = /** @class */ (function () {
    function VerificationMethodANDCombinations(d) {
        this.data = Array.from(d);
    }
    VerificationMethodANDCombinations.prototype.validateData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateData())
                return false;
        }
        return true;
    };
    return VerificationMethodANDCombinations;
}());
var userVerificationDetails = /** @class */ (function () {
    function userVerificationDetails(info) {
        this.data = Array.from(info);
    }
    userVerificationDetails.prototype.validateData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateData())
                return false;
        }
        return true;
    };
    return userVerificationDetails;
}());
exports.userVerificationDetails = userVerificationDetails;
var ExtensionDescriptor = /** @class */ (function () {
    function ExtensionDescriptor(i, f, t, d) {
        this.id = i;
        this.tag = t;
        this.data = d;
        this.fail_if_unknown = f;
    }
    return ExtensionDescriptor;
}());
var supportedExtensions = /** @class */ (function () {
    function supportedExtensions(info) {
        this.data = info;
    }
    return supportedExtensions;
}());
exports.supportedExtensions = supportedExtensions;
var rgbPaletteEntry = /** @class */ (function () {
    function rgbPaletteEntry(r1, g1, b1) {
        if (r1 === void 0) { r1 = 0; }
        if (g1 === void 0) { g1 = 0; }
        if (b1 === void 0) { b1 = 0; }
        this.r = r1;
        this.g = g1;
        this.b = b1;
    }
    rgbPaletteEntry.prototype.validateData = function () {
        if (this.r < 0 || this.r > 255 || this.g < 0 || this.g > 255 || this.b < 0 || this.b > 255) {
            return false;
        }
        else {
            return true;
        }
    };
    return rgbPaletteEntry;
}());
var tcDisplayPNGCharacteristicsDescriptor = /** @class */ (function () {
    function tcDisplayPNGCharacteristicsDescriptor(w, h, b, c, f, i, p) {
        if (w === void 0) { w = 0; }
        if (h === void 0) { h = 0; }
        if (b === void 0) { b = 0; }
        if (c === void 0) { c = 0; }
        if (f === void 0) { f = 0; }
        if (i === void 0) { i = 0; }
        this.width = w;
        this.height = h;
        this.bitDepth = b;
        this.compression = c;
        this.filter = f;
        this.interlace = i;
        this.plte = p;
    }
    return tcDisplayPNGCharacteristicsDescriptor;
}());
exports.tcDisplayPNGCharacteristicsDescriptor = tcDisplayPNGCharacteristicsDescriptor;
var attestationRootCertificates = /** @class */ (function () {
    function attestationRootCertificates(info) {
        this.data = Array.from(info);
    }
    return attestationRootCertificates;
}());
exports.attestationRootCertificates = attestationRootCertificates;
//This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
var ecdaaTrustAnchor = /** @class */ (function () {
    function ecdaaTrustAnchor(x, y, c, s1, s2, g) {
        this.X = x;
        this.Y = y;
        this.c = c;
        this.sx = s1;
        this.sy = s2;
        this.G1Curve = g;
    }
    ecdaaTrustAnchor.prototype.validateData = function () {
        if (G1CurveEnum[this.G1Curve] == undefined)
            return false;
        return true;
    };
    return ecdaaTrustAnchor;
}());
exports.ecdaaTrustAnchor = ecdaaTrustAnchor;
var G1CurveEnum;
(function (G1CurveEnum) {
    G1CurveEnum[G1CurveEnum["BN_P256"] = 0] = "BN_P256";
    G1CurveEnum[G1CurveEnum["BN_P638"] = 1] = "BN_P638";
    G1CurveEnum[G1CurveEnum["BN_ISOP256"] = 2] = "BN_ISOP256";
    G1CurveEnum[G1CurveEnum["BN_ISOP512"] = 3] = "BN_ISOP512";
})(G1CurveEnum || (G1CurveEnum = {}));
