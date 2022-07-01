"use strict";
exports.__esModule = true;
exports.ecdaaTrustAnchor = exports.attestationRootCertificates = exports.tcDisplayPNGCharacteristicsDescriptor = exports.supportedExtensions = exports.userVerificationDetails = exports.metadataKeysV2 = void 0;
var crypto_1 = require("crypto"); // per controllare attestationRootCertificates
var metadataKeysV2 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function metadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm, publicKeyAlgAndEncoding, attestationTypes, userVerificationDetails, isSecondFactorOnly, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms, publicKeyAlgAndEncodings, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions) {
        if (cryptoStrength === void 0) { cryptoStrength = undefined; }
        if (protocolFamily === void 0) { protocolFamily = "uaf"; }
        if (isKeyRestricted === void 0) { isKeyRestricted = true; }
        if (isFreshUserVerificationRequired === void 0) { isFreshUserVerificationRequired = true; }
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        if (attestationCertificateKeyIdentifiers != undefined) {
            this.attestationCertificateKeyIdentifiers = Array.from(attestationCertificateKeyIdentifiers);
        }
        else {
            this.attestationCertificateKeyIdentifiers = undefined;
        }
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.upv = Array.from(upv);
        this.assertionScheme = assertionScheme;
        this.authenticationAlgorithm = authenticationAlgorithm;
        //controllo che authenticationAlgorithms esista per assegnarlo a this.authenticationAlgorithms
        if (authenticationAlgorithms != undefined) {
            this.authenticationAlgorithms = Array.from(authenticationAlgorithms);
        }
        else {
            this.authenticationAlgorithms = undefined;
        }
        this.publicKeyAlgAndEncoding = publicKeyAlgAndEncoding;
        //controllo che publicKeyAlgAndEncodings esista per assegnarlo a this.publicKeyAlgAndEncodings
        if (publicKeyAlgAndEncodings != undefined) {
            this.publicKeyAlgAndEncodings = Array.from(publicKeyAlgAndEncodings);
        }
        else {
            this.publicKeyAlgAndEncodings = undefined;
        }
        this.attestationTypes = Array.from(attestationTypes);
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
        if (ecdaaTrustAnchors != undefined) {
            this.ecdaaTrustAnchors = Array.from(ecdaaTrustAnchors);
        }
        else {
            this.ecdaaTrustAnchors = undefined;
        }
        this.icon = icon;
        //controllo che supportedExtensions esista per assegnarlo a this.supportedExtensions
        if (supportedExtensions != undefined) {
            this.supportedExtensions = Array.from(supportedExtensions);
        }
        else {
            this.supportedExtensions = undefined;
        }
    }
    //funzione validazione singolo campo
    //public validateData(): boolean{
    //    return true;
    //}
    //funzione validazione per tutti i campi
    metadataKeysV2.prototype.validateAll = function () {
        if (this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() && this.authenticatorVersionCheck() &&
            this.protocolFamilyCheck() && this.upvCheck() && this.assertionSchemeCheck() && this.authenticationAlgorithmCheck() &&
            this.authenticationAlgorithmsCheck() && this.publicKeyAlgAndEncodingCheck() &&
            this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
            this.keyProtectionCheck() && this.matcherProtectionCheck() && this.cryptoStrengthCeck() && this.operatingEnvCheck() &&
            this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() &&
            this.tcDisplayPNGCharacteristicsCheck() && this.attestationRootCertificatesCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck()
        // && this.supportedExtensionsCheck() basta che i campi dati siano conformi
        ) {
            return true;
        }
        return false;
    };
    //controllo upv
    /*
        jsonParsed[0]["minor"] == 1){
    */
    /**
     * Campo legalHeader non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "uaf"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "fido2"
     *          3) che la stringa, se presente sia conforme a quanto riportato qui: https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef
     */
    metadataKeysV2.prototype.aaidCheck = function () {
        if (this.protocolFamily == "uaf" && this.aaid == undefined)
            return false;
        if (this.aaid != undefined && (!RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid) || this.protocolFamily == "fido2"))
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     *          3) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example
     */
    metadataKeysV2.prototype.aaguidCheck = function () {
        if (this.protocolFamily == "fido2" && this.aaguid == undefined)
            return false;
        if (this.protocolFamily == "uaf" && this.aaguid != undefined)
            return false;
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) il campo deve essere presente se né aaid né aaguid sono presenti
     *          2) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    metadataKeysV2.prototype.attestationCertificateKeyIdentifiersCheck = function () {
        if (this.aaid == undefined && this.aaguid == undefined && this.attestationCertificateKeyIdentifiers == undefined)
            return false;
        if (this.attestationCertificateKeyIdentifiers != undefined) {
            for (var i = 0; i < this.attestationCertificateKeyIdentifiers.length; i++) {
                if (!RegExp(/^[0-9a-f]+$/).test(this.attestationCertificateKeyIdentifiers[i]))
                    return false;
            }
        }
        return true;
    };
    /**
     * Campo description non controllato:
     *          1) perché è obbligatorio (controllato nel costruttore)
     *          2) perché è una stringa
     */
    /**
     * Campo alternativeDescriptions non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */
    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    metadataKeysV2.prototype.authenticatorVersionCheck = function () {
        if (this.authenticatorVersion < 0 || this.authenticatorVersion > 65535)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) se si usa metadata statement per u2f deve esserci obbligatoriamente il campo "u2f", se si usa FIDO 2.0/WebAuthentication Authenticator il campo deve essere "fido2"
     */
    metadataKeysV2.prototype.protocolFamilyCheck = function () {
        if (this.protocolFamily != undefined && this.protocolFamily != "uaf" && this.protocolFamily != "u2f" && this.protocolFamily != "fido2")
            return false;
        if (this.protocolFamily != "fido2" && this.assertionScheme == "FIDOV2")
            return false;
        if (this.protocolFamily != "u2f" && this.assertionScheme == "U2FV1BIN")
            return false;
        if ((this.protocolFamily != "uaf" && this.protocolFamily != undefined) && this.assertionScheme == "UAFV1TLV")
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     */
    metadataKeysV2.prototype.upvCheck = function () {
        for (var i = 0; i < this.upv.length; i++) {
            if (this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo stringa sia presente in assertionSchemeEnum (quidi che sia un tra U2FV1BIN, FIDOV2 e UAFV1TLV)
     */
    metadataKeysV2.prototype.assertionSchemeCheck = function () {
        if (assertionSchemeEnum[this.assertionScheme] == undefined)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    metadataKeysV2.prototype.authenticationAlgorithmCheck = function () {
        if (this.authenticationAlgorithm < 1 || this.authenticationAlgorithm > 18)
            return false;
        if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    metadataKeysV2.prototype.authenticationAlgorithmsCheck = function () {
        if (this.authenticationAlgorithms != undefined) {
            for (var i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (this.authenticationAlgorithms[i] < 1 || this.authenticationAlgorithms[i] > 18)
                    return false;
                if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 256 e 260
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    metadataKeysV2.prototype.publicKeyAlgAndEncodingCheck = function () {
        if (this.publicKeyAlgAndEncoding < 256 || this.publicKeyAlgAndEncoding > 260)
            return false;
        if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 256 e 260
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    metadataKeysV2.prototype.publicKeyAlgAndEncodingsCheck = function () {
        if (this.publicKeyAlgAndEncodings != undefined) {
            for (var i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (this.publicKeyAlgAndEncodings[i] < 256 || this.publicKeyAlgAndEncodings[i] > 260)
                    return false;
                if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 15879(0x3E07) e 15882(0x3E0A)
     */
    metadataKeysV2.prototype.attestationTypesCheck = function () {
        for (var i = 0; i < this.attestationTypes.length; i++) {
            if (this.attestationTypes[i] < 15879 || this.attestationTypes[i] > 15882)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#idl-def-VerificationMethodDescriptor)
     */
    metadataKeysV2.prototype.userVerificationDetailsCheck = function () {
        for (var i = 0; i < this.userVerificationDetails.length; i++) {
            if (!this.userVerificationDetails[i].validateData())
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types)
     */
    metadataKeysV2.prototype.keyProtectionCheck = function () {
        if (this.keyProtection < 1 || this.keyProtection > 24) // 16 + 8 -> 24, massimo num raggiungibile (This flag MUST be set in conjunction with one of the other KEY_PROTECTION flags...)
            return false;
        if (this.keyProtection == (1 || 2 || 4 || 6 || 8 || 10 || 11 || 17 || 18 || 20 || 24))
            return true;
        else
            return false;
    };
    /**
     * Campo isKeyRestricted non controllato:
     *          1) perché è opzionale (se non viene specificato è true)
     *          2) perché è un booleano
     */
    /**
     * Campo isFreshUserVerificationRequired non controllato:
     *          1) perché è opzionale (se non viene specificato è true)
     *          2) perché è un booleano
     */
    /**
     * Controlli:
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types)
     */
    metadataKeysV2.prototype.matcherProtectionCheck = function () {
        if (this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     */
    metadataKeysV2.prototype.cryptoStrengthCeck = function () {
        if (this.cryptoStrength != undefined) {
            if (this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo stringa sia presente in operatingEnvEnum
     */
    metadataKeysV2.prototype.operatingEnvCheck = function () {
        if (this.operatingEnv != undefined) {
            if (operatingEnvEnum[this.operatingEnv] == undefined)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    //idea alla base: dato il valore di this.attachmentHint tolgo il valore i, a partire da 256, fino a 1, 
    //per capire se sono stati utilizzati o meno i campi critici (internal->1 , external->2)
    metadataKeysV2.prototype.attachmentHintCheck = function () {
        var counter = 0;
        var i = 256;
        var tot = this.attachmentHint;
        if (tot == 1) //superfluo
            return true;
        while (i > 0) {
            if ((i == 1 && counter >= 1) || (i == 2 && counter == 0))
                return false;
            if (tot >= i) {
                tot = tot - i;
                counter += 1;
            }
            i = i / 2;
        }
        return true;
    };
    /**
     * Campo isSecondFactorOnly non controllato:
     *          1) perché è un booleano obbligatorio
     */
    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti secondo: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#transaction-confirmation-display-types
     */
    metadataKeysV2.prototype.tcDisplayCheck = function () {
        if (this.tcDisplay == (6 || 10 || 12)) {
            return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo sia anche tcDisplay (non 0)
     *          2) che il campo presenti un valore tra quelli presentu in tcDisplayContentTypeEnum
     */
    metadataKeysV2.prototype.tcDisplayContentTypeCheck = function () {
        if (this.tcDisplay != 0 && this.tcDisplayContentType == undefined)
            return false;
        if (this.tcDisplayContentType != undefined) {
            if (tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non 0) e tcDisplayContentType (deve essere image/png)
     */
    metadataKeysV2.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != 0 && tcDisplayContentTypeEnum[this.tcDisplayContentType] == tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1)
     *
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case.
     */
    metadataKeysV2.prototype.attestationRootCertificatesCheck = function () {
        for (var i = 0; i < this.attestationRootCertificates.length; i++) {
            var testCert = new crypto_1.X509Certificate(this.attestationRootCertificates[i]);
            if (testCert.ca) {
                // caso 1 CA o intermediate ca
                if (testCert.verify(testCert.publicKey)) {
                    console.log("attestationRootCertificate[" + i + "]" + ": root CA");
                }
                else {
                    console.log("attestationRootCertificate[" + i + "]" + ": intermediate CA");
                }
            }
            //this can be achieved by either specifying the AAID or AAGUID in the attestation certificate
            else {
                // using the extension id-fido-gen-ce-aaid { 1 3 6 1 4 1 45724 1 1 1 }
                if (this.aaid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(function (element) { return element == "1.3.6.1.4.1.45724.1.1.1"; }) != undefined)
                    return false;
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if (this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(function (element) { return element == "1.3.6.1.4.1.45724.1.1.4"; }) != undefined)
                    return false;
                // or by using the attestationCertificateKeyIdentifier method => ???
                //console.debug(testCert);
                console.log("attestationRootCertificate[" + i + "]" + ": leaf");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Se e solo se AttestationTypes include ATTESTATION_ECDAA (15881) ecdaaTrustAnchors deve essere presente
     *          2) Validazione campo G1Curve di  EcdaaTrustAnchor
     */
    metadataKeysV2.prototype.ecdaaTrustAnchorsCheck = function () {
        var temp = this.attestationTypes.find(function (element) { return element == 15881; });
        if ((temp != undefined && this.ecdaaTrustAnchors == undefined) || (temp == undefined && this.ecdaaTrustAnchors != undefined))
            return false;
        if (this.ecdaaTrustAnchors != undefined) {
            for (var i = 0; i < this.ecdaaTrustAnchors.length; i++) {
                if (!this.ecdaaTrustAnchors[i].validateData())
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) formato con cui sono inserite le immagini tramite regular expression
     */
    metadataKeysV2.prototype.iconCheck = function () {
        if (this.icon != undefined) {
            var temp = this.icon;
            if (this.icon.indexOf("data:") != -1) {
                temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64") + 7), "");
            }
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)) {
                return false;
            }
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
//nome completo curve sarebbe "TPM_ECC_BN_...." e "ECC_BN_...."
var G1CurveEnum;
(function (G1CurveEnum) {
    G1CurveEnum[G1CurveEnum["BN_P256"] = 0] = "BN_P256";
    G1CurveEnum[G1CurveEnum["BN_P638"] = 1] = "BN_P638";
    G1CurveEnum[G1CurveEnum["BN_ISOP256"] = 2] = "BN_ISOP256";
    G1CurveEnum[G1CurveEnum["BN_ISOP512"] = 3] = "BN_ISOP512";
})(G1CurveEnum || (G1CurveEnum = {}));
