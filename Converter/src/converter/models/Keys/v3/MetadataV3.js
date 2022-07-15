"use strict";
exports.__esModule = true;
exports.MetadataKeysV3 = void 0;
var crypto_1 = require("crypto"); // per controllare attestationRootCertificates
var error_1 = require("../../Error/error");
var V3toV2_1 = require("../../FieldConverter/V3toV2");
var MetadataV2_1 = require("../v2/MetadataV2");
var usefulFunction_1 = require("../../FieldConverter/usefulFunction");
var enums_1 = require("./../fields/enums");
var MetadataKeysV3 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function MetadataKeysV3(description, authenticatorVersion, upv, schema, attestationTypes, attestationCertificateKeyIdentifiers, userVerificationDetails, authenticationAlgorithms, publicKeyAlgAndEncodings, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, alternativeDescriptions, protocolFamily, isKeyRestricted, isFreshUserVerificationRequired, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions, authenticatorGetInfo) {
        if (cryptoStrength === void 0) { cryptoStrength = undefined; }
        if (protocolFamily === void 0) { protocolFamily = "uaf"; }
        if (isKeyRestricted === void 0) { isKeyRestricted = true; }
        if (isFreshUserVerificationRequired === void 0) { isFreshUserVerificationRequired = true; }
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.schema = schema;
        this.upv = Array.from(upv);
        this.authenticationAlgorithms = Array.from(authenticationAlgorithms);
        this.publicKeyAlgAndEncodings = Array.from(publicKeyAlgAndEncodings);
        this.attestationTypes = Array.from(attestationTypes);
        this.userVerificationDetails = userVerificationDetails;
        this.keyProtection = Array.from(keyProtection);
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = Array.from(matcherProtection);
        this.cryptoStrength = cryptoStrength;
        this.attachmentHint = attachmentHint;
        if (tcDisplay != undefined) {
            this.tcDisplay = Array.from(tcDisplay);
        }
        else {
            this.tcDisplay = undefined;
        }
        this.tcDisplayContentType = tcDisplayContentType;
        if (tcDisplayPNGCharacteristics != undefined) {
            this.tcDisplayPNGCharacteristics = Array.from(tcDisplayPNGCharacteristics);
        }
        else {
            this.tcDisplayPNGCharacteristics = undefined;
        }
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
        this.authenticatorGetInfo = authenticatorGetInfo;
    }
    //medodo statico per generazione metadata V2
    MetadataKeysV3.fromV3toV2 = function (m) {
        var result;
        if (!m.validateAll())
            throw "Errore, metadata versione 3 non valido";
        else {
            //conversioni + campi essenziali
            var legalHeader = m.legalHeader != undefined ? m.legalHeader : "https://fidoalliance.org/metadata/metadata-statement-legal-header/";
            var aaid = m.aaid != undefined ? m.aaid : undefined;
            var aaguid = m.aaguid != undefined ? m.aaguid : undefined;
            ;
            var attestationCertificateKeyIdentifiers = m.attestationCertificateKeyIdentifiers != undefined ? Array.from(m.attestationCertificateKeyIdentifiers) : undefined;
            var description = m.description;
            var alternativeDescriptions = m.alternativeDescriptions != undefined ? m.alternativeDescriptions : undefined;
            var authenticatorVersion = m.authenticatorVersion;
            var protocolFamily = m.protocolFamily;
            var upv = Array.from(m.upv);
            var assertionScheme = V3toV2_1.V3toV2.convertAssertionSchema(m.protocolFamily);
            // prendere primo elemento array di algoritmi per inserirlo nl campo corretto (quello singolo del metadata v2)
            var authenticationAlgorithm = m.authenticationAlgorithms[0] != undefined ? V3toV2_1.V3toV2.convertauthenticationAlgorithm(m.authenticationAlgorithms[0]) : undefined;
            //array con elemento in meno (posizionato nel campo precedente)
            var tempAlg = Array.from(m.authenticationAlgorithms.slice(1));
            var authenticationAlgorithms = void 0;
            if (tempAlg.length != 0) {
                authenticationAlgorithms = new Array();
                for (var i = 0; i < tempAlg.length; i++)
                    authenticationAlgorithms.push(V3toV2_1.V3toV2.convertauthenticationAlgorithm(tempAlg[i]));
            }
            else {
                authenticationAlgorithms = undefined;
            }
            // stesssa cosa per publicKeyAlgAndEncoding
            var publicKeyAlgAndEncoding = m.publicKeyAlgAndEncodings != undefined ? V3toV2_1.V3toV2.convertpublicKeyAlgAndEncoding(m.publicKeyAlgAndEncodings[0]) : undefined;
            var tempEnc = Array.from(m.publicKeyAlgAndEncodings.slice(1));
            var publicKeyAlgAndEncodings = void 0;
            if (tempEnc.length != 0) {
                publicKeyAlgAndEncodings = new Array();
                for (var i = 0; i < tempEnc.length; i++)
                    publicKeyAlgAndEncodings.push(V3toV2_1.V3toV2.convertpublicKeyAlgAndEncoding(tempEnc[i]));
            }
            else {
                publicKeyAlgAndEncodings = undefined;
            }
            var attestationTypes = void 0;
            var tempAttType = V3toV2_1.V3toV2.convertAttestationTypes(m.attestationTypes);
            if (tempAttType != undefined)
                attestationTypes = Array.from(tempAttType);
            var userVerificationDetails = Array();
            for (var i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails.push(m.userVerificationDetails[i]);
                if (!(m.userVerificationDetails[i])) {
                    for (var l = 0; l < m.userVerificationDetails[i].data.length; l++) {
                        var numEX = m.userVerificationDetails[i].data[l].userVerification;
                        userVerificationDetails[i].data[l].userVerification = V3toV2_1.V3toV2.convertUserVerificationDetails(m.userVerificationDetails[i].data[l].userVerification);
                    }
                }
            }
            var keyProtection = V3toV2_1.V3toV2.convertKeyProtection(m.keyProtection);
            var isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            var isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            var matcherProtection = V3toV2_1.V3toV2.convertMatcherProtection(m.matcherProtection);
            var cryptoStrength = V3toV2_1.V3toV2.convertCryptoStrength(m.cryptoStrength);
            var operatingEnv = V3toV2_1.V3toV2.convertOperatingEnv();
            var attachmentHint = V3toV2_1.V3toV2.convertAttachmentHint(m.attachmentHint);
            var isSecondFactorOnly = V3toV2_1.V3toV2.convertIsSecondFactorOnly(undefined);
            if (m.authenticatorGetInfo != undefined) {
                if (m.authenticatorGetInfo.options != undefined) {
                    if (m.authenticatorGetInfo.options.uv != undefined) {
                        isSecondFactorOnly = V3toV2_1.V3toV2.convertIsSecondFactorOnly(m.authenticatorGetInfo.options.uv);
                    }
                }
            }
            var tcDisplay = void 0;
            if (m.tcDisplay != undefined)
                tcDisplay = V3toV2_1.V3toV2.convertTcDisplay(m.tcDisplay);
            else
                tcDisplay = undefined;
            var tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            var tcDisplayPNGCharacteristics = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined;
            var attestationRootCertificates = Array.from(m.attestationRootCertificates);
            var ecdaaTrustAnchors = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            var icon = m.icon != undefined ? m.icon : undefined;
            var supportedExtensions = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            result = new MetadataV2_1.MetadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm != undefined ? authenticationAlgorithm : 0, publicKeyAlgAndEncoding != undefined ? publicKeyAlgAndEncoding : 0, attestationTypes != undefined ? attestationTypes : new Array(), userVerificationDetails, isSecondFactorOnly, keyProtection != undefined ? keyProtection : 0, matcherProtection != undefined ? matcherProtection : 0, cryptoStrength != undefined ? cryptoStrength : 0, attachmentHint != undefined ? attachmentHint : 0, tcDisplay != undefined ? tcDisplay : 0, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms != undefined ? authenticationAlgorithms : undefined, publicKeyAlgAndEncodings != undefined ? publicKeyAlgAndEncodings : undefined, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions);
        }
        return result;
    };
    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    MetadataKeysV3.prototype.validateData = function (str) {
        switch (enums_1.V3FunctionName[str]) {
            case 1:
                return this.aaidCheck();
            case 2:
                return this.aaguidCheck();
            case 3:
                return this.attestationCertificateKeyIdentifiersCheck();
            case 4:
                return this.authenticatorVersionCheck();
            case 5:
                return this.protocolFamilyCheck();
            case 6:
                return this.schemaCheck();
            case 7:
                return this.upvCheck();
            case 8:
                return this.authenticationAlgorithmsCheck();
            case 9:
                return this.publicKeyAlgAndEncodingsCheck();
            case 10:
                return this.attestationTypesCheck();
            case 11:
                return this.userVerificationDetailsCheck();
            case 12:
                return this.keyProtectionCheck();
            case 13:
                return this.matcherProtectionCheck();
            case 14:
                return this.cryptoStrengthCeck();
            case 15:
                return this.attachmentHintCheck();
            case 16:
                return this.tcDisplayCheck();
            case 17:
                return this.tcDisplayContentTypeCheck();
            case 18:
                return this.tcDisplayPNGCharacteristicsCheck();
            case 19:
                return this.attestationRootCertificatesCheck();
            case 20:
                return this.ecdaaTrustAnchorsCheck();
            case 21:
                return this.iconCheck();
            case 22:
                return this.authenticatorGetInfoCheck();
            //case 23:
            //      return this.supportedExtensionsCheck();
            //      
        }
        throw "La stringa " + str + " non è una funzione di controllo";
    };
    //funzione validazione per tutti i campi
    MetadataKeysV3.prototype.validateAll = function () {
        if (this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() && this.authenticatorVersionCheck() &&
            this.protocolFamilyCheck() && this.schemaCheck() && this.upvCheck() &&
            this.authenticationAlgorithmsCheck() &&
            this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
            this.keyProtectionCheck() && this.matcherProtectionCheck() && this.cryptoStrengthCeck() &&
            this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() &&
            this.tcDisplayPNGCharacteristicsCheck() && this.attestationRootCertificatesCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck()
            //&& this.supportedExtensionsCheck()
            && this.authenticatorGetInfoCheck()) {
            return true;
        }
        return false;
    };
    /**
     * Campo legalHeader non controllato:
     *          1) è obbligatorio ci sia (controllo nel costruttore)
     *          2) perché è una stringa
     */
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "uaf"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "fido2"
     *          3) che la stringa, se presente sia conforme a quanto riportato qui: https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef
     */
    MetadataKeysV3.prototype.aaidCheck = function () {
        if (this.protocolFamily == "uaf" && this.aaid == undefined)
            throw new error_1.MetadataKeyError("Errore valore aaid");
        //no distinzione upper-lower case
        if (this.aaid != undefined && (!RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid) || this.protocolFamily == "fido2"))
            throw new error_1.MetadataKeyError("Errore valore aaid");
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     *          3) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example
     */
    MetadataKeysV3.prototype.aaguidCheck = function () {
        if ((this.protocolFamily == "fido2" && this.aaguid == undefined) || (this.protocolFamily == "uaf" && this.aaguid != undefined))
            throw new error_1.MetadataKeyError("Errore valore aaguid");
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                throw new error_1.MetadataKeyError("Errore valore aaguid");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    MetadataKeysV3.prototype.attestationCertificateKeyIdentifiersCheck = function () {
        if (this.attestationCertificateKeyIdentifiers != undefined) {
            for (var i = 0; i < this.attestationCertificateKeyIdentifiers.length; i++) {
                if (!RegExp(/^[0-9a-f]+$/).test(this.attestationCertificateKeyIdentifiers[i]))
                    throw new error_1.MetadataKeyError("Errore valore attestationCertificateKeyIdentifiers in posizione: " + i + ". ");
            }
        }
        return true;
    };
    /**
     * Campo description non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */
    /**
     * Campo alternativeDescriptions non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */
    /**
     * Conrtolli:
     *          1) essendo il campo unsigned long:  0 <= authenticatorVersion <= 4294967295
     *          2) controllo uguaglianza firmwareVersion non svolto perché non sempre è vero
     */
    MetadataKeysV3.prototype.authenticatorVersionCheck = function () {
        if (this.authenticatorVersion < 0 || this.authenticatorVersion > 4294967295)
            throw new error_1.MetadataKeyError("Errore valore authenticatorVersion");
        if (this.authenticatorGetInfo != undefined && (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.firmwareVersion != undefined && this.authenticatorGetInfo.firmwareVersion != this.authenticatorVersion))
            throw new error_1.MetadataKeyError("Errore valore authenticatorVersion");
        return true;
    };
    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) controllo corrispondenza con campo "version" di authenticatorgetinfo
     */
    MetadataKeysV3.prototype.protocolFamilyCheck = function () {
        if (this.protocolFamily == undefined)
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        if (enums_1.protocolFamilyEnum[this.protocolFamily] == undefined)
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        if (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.version != undefined) {
            if (this.protocolFamily == "fido2" && (this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_1"; }) == undefined &&
                this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_0"; }) == undefined &&
                this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_1_PRE"; }) == undefined))
                throw new error_1.MetadataKeyError("Errore valore protocolFamily");
            if (this.protocolFamily == "u2f" && (this.authenticatorGetInfo.version.find(function (element) { return element == "U2F_V2"; }) == undefined))
                throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        }
        return true;
    };
    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    MetadataKeysV3.prototype.schemaCheck = function () {
        if (this.schema < 0 || this.schema > 65535)
            throw new error_1.MetadataKeyError("Errore valore Schema");
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     *          2) controlli specifici non effettuati sulla versione nei casi UAF, U2F e FIDO2/CTAP2
     */
    MetadataKeysV3.prototype.upvCheck = function () {
        for (var i = 0; i < this.upv.length; i++) {
            if (this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                throw new error_1.MetadataKeyError("Errore valore upv in posizione: " + i + ". ");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che secp256r1_ecdsa_sha256_raw
     */
    MetadataKeysV3.prototype.authenticationAlgorithmsCheck = function () {
        if (this.authenticationAlgorithms != undefined) {
            for (var i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (enums_1.authenticationAlgorithmsEnum[this.authenticationAlgorithms[i]] == undefined)
                    throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ");
                if (this.protocolFamily == "u2f" && this.authenticationAlgorithms[i] != "secp256r1_ecdsa_sha256_raw")
                    throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che ecc_x962_raw
     */
    MetadataKeysV3.prototype.publicKeyAlgAndEncodingsCheck = function () {
        if (this.publicKeyAlgAndEncodings != undefined) {
            for (var i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (enums_1.publicKeyAlgAndEncodingsEnum[this.publicKeyAlgAndEncodings[i]] == undefined) {
                    throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ");
                }
                if (this.protocolFamily == "u2f" && this.publicKeyAlgAndEncodings[i] != "ecc_x962_raw") {
                    throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ");
                }
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi stringa siano basic_full, basic_surrogate, ecdaa oppure attca
     */
    MetadataKeysV3.prototype.attestationTypesCheck = function () {
        for (var i = 0; i < this.attestationTypes.length; i++) {
            if (enums_1.attestationTypesEnum[this.attestationTypes[i]] == undefined)
                throw new error_1.MetadataKeyError("Errore valore attestationTypes");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
     */
    MetadataKeysV3.prototype.userVerificationDetailsCheck = function () {
        for (var i = 0; i < this.userVerificationDetails.length; i++) {
            if (!(this.userVerificationDetails[i])) {
                for (var l = 0; l < this.userVerificationDetails[i].data.length; l++) {
                    if (!this.userVerificationDetails[i].data[l].validateInternalData())
                        throw new error_1.MetadataKeyError("Errore valore userVerificationDetails");
                }
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campi (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types)
     */
    MetadataKeysV3.prototype.keyProtectionCheck = function () {
        for (var i = 0; i < this.keyProtection.length; i++) {
            if (enums_1.keyProtectionEnum[this.keyProtection[i]] == undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
        }
        if (this.keyProtection.find(function (element) { return element == "software"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element == "hardware"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
            if (this.keyProtection.find(function (element) { return element == "tee"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
            if (this.keyProtection.find(function (element) { return element == "secure_element"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
        }
        if (this.keyProtection.find(function (element) { return element == "tee"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element == "secure_element"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
        }
        //(remote_handle) MUST be set in conjunction with one of the other KEY_PROTECTION flags 
        if (this.keyProtection.find(function (element) { return element == "remote_handle"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element != "remote_handle"; }) == undefined)
                throw new error_1.MetadataKeyError("Errore valore keyProtection");
        }
        return true;
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types)
     */
    MetadataKeysV3.prototype.matcherProtectionCheck = function () {
        for (var i = 0; i < this.matcherProtection.length; i++) {
            if (enums_1.matcherProtectionEnum[this.matcherProtection[i]] == undefined)
                throw new error_1.MetadataKeyError("Errore valore matcherProtection");
        }
        if (this.matcherProtection.find(function (element) { return element == "software"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element == "tee"; }) != undefined || this.matcherProtection.find(function (element) { return element == "on_chip"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore matcherProtection");
        }
        if (this.matcherProtection.find(function (element) { return element == "tee"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element == "on_chip"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore matcherProtection");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     */
    MetadataKeysV3.prototype.cryptoStrengthCeck = function () {
        if (this.cryptoStrength != undefined) {
            if (this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                throw new error_1.MetadataKeyError("Errore valore cryptoStrength");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    MetadataKeysV3.prototype.attachmentHintCheck = function () {
        for (var i = 0; i < this.attachmentHint.length; i++) {
            if (enums_1.attachmentHintEnum[this.attachmentHint[i]] == undefined)
                throw new error_1.MetadataKeyError("Errore valore attachmentHint");
        }
        //se c'è elemento internal insieme ad un altro elemento differente --> errore
        if (this.attachmentHint.find(function (element) { return element == "internal"; }) != undefined) {
            if (this.attachmentHint.find(function (element) { return element != "internal"; }) != undefined)
                throw new error_1.MetadataKeyError("Errore valore attachmentHint");
        }
        //se si ha elemento external senza altri elementi si ha errore (il controllo su internal non è stato fatto in quanto fatto dall'if precedente)
        if (this.attachmentHint.find(function (element) { return element == "external"; }) != undefined) {
            if (this.attachmentHint.find(function (element) { return element != "external"; }) == undefined)
                throw new error_1.MetadataKeyError("Errore valore attachmentHint");
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
     *          2) campo undefined -> the authenticator does not support a transaction confirmation display
     */
    MetadataKeysV3.prototype.tcDisplayCheck = function () {
        if (this.tcDisplay != undefined) {
            for (var i = 0; i < this.tcDisplay.length; i++) {
                if (enums_1.tcDisplayEnum[this.tcDisplay[i]] == undefined)
                    throw new error_1.MetadataKeyError("Errore valore tcDisplay");
            }
            if (this.tcDisplay.find(function (element) { return element == "privileged_software"; }) != undefined) {
                if (this.tcDisplay.find(function (element) { return element == "tee"; }) != undefined || this.tcDisplay.find(function (element) { return element == "hardware"; }) != undefined)
                    throw new error_1.MetadataKeyError("Errore valore tcDisplay");
            }
            if (this.tcDisplay.find(function (element) { return element == "tee"; }) != undefined) {
                if (this.tcDisplay.find(function (element) { return element == "hardware"; }) != undefined)
                    throw new error_1.MetadataKeyError("Errore valore tcDisplay");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo sia anche tcDisplay (non undefined)
     *          2) che il campo presenti un valore tra quelli presentu in tcDisplayContentTypeEnum
     */
    MetadataKeysV3.prototype.tcDisplayContentTypeCheck = function () {
        if ((this.tcDisplay != undefined && this.tcDisplay.length >= 1) && this.tcDisplayContentType == undefined)
            throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        if (this.tcDisplayContentType != undefined && (this.tcDisplay != undefined && this.tcDisplay.length >= 1)) {
            if (enums_1.tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non undefined) e tcDisplayContentType (deve essere image/png)
     */
    MetadataKeysV3.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != undefined && enums_1.tcDisplayContentTypeEnum[this.tcDisplayContentType] == enums_1.tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            throw new error_1.MetadataKeyError("Errore valore tcDisplayPNGCharacteristics");
        return true;
    };
    /**
     * Controlli:
     *          1)
     *
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case.
     */
    MetadataKeysV3.prototype.attestationRootCertificatesCheck = function () {
        for (var i = 0; i < this.attestationRootCertificates.length; i++) {
            var testCert = new crypto_1.X509Certificate((0, usefulFunction_1.convertAttestationRootCertificates)(this.attestationRootCertificates[i]));
            if (testCert.ca) {
                // caso 1 CA o intermediate ca
                if (testCert.verify(testCert.publicKey)) {
                    //console.log("attestationRootCertificate[" + i + "]" + ": root CA");
                }
                else {
                    //console.log("attestationRootCertificate[" + i + "]" + ": intermediate CA");
                }
            }
            //this can be achieved by either specifying the AAID or AAGUID in the attestation certificate
            else {
                // using the extension id-fido-gen-ce-aaid { 1 3 6 1 4 1 45724 1 1 1 }
                if (this.aaid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(function (element) { return element == "1.3.6.1.4.1.45724.1.1.1"; }) != undefined)
                    throw new error_1.MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ");
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if (this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(function (element) { return element == "1.3.6.1.4.1.45724.1.1.4"; }) != undefined)
                    throw new error_1.MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ");
                // or by using the attestationCertificateKeyIdentifier method => ??? TODO
                //console.debug(testCert);
                //console.log("attestationRootCertificate[" + i + "]" + ": leaf");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Se e solo se AttestationTypes include ATTESTATION_ECDAA (15881) ecdaaTrustAnchors deve essere presente
     *          2) Validazione campo G1Curve di  EcdaaTrustAnchor
     */
    MetadataKeysV3.prototype.ecdaaTrustAnchorsCheck = function () {
        var temp = this.attestationTypes.find(function (element) { return element == "ecdaa"; });
        if (temp != undefined && this.ecdaaTrustAnchors == undefined || temp == undefined && this.ecdaaTrustAnchors != undefined)
            throw new error_1.MetadataKeyError("Errore valore ecdaaTrustAnchors");
        if (this.ecdaaTrustAnchors != undefined) {
            for (var i = 0; i < this.ecdaaTrustAnchors.length; i++) {
                if (!this.ecdaaTrustAnchors[i].validateInternalData())
                    throw new error_1.MetadataKeyError("Errore valore ecdaaTrustAnchors in posizione: " + i + ". ");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) formato con cui sono inserite le immagini tramite regular expression
     */
    MetadataKeysV3.prototype.iconCheck = function () {
        if (this.icon != undefined) {
            var temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64") + 7), "");
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)) {
                throw new error_1.MetadataKeyError("Errore valore icon");
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che gli oggetti nell'array siamo di tipo ExtensionDescriptor
     */
    //    private supportedExtensionsCheck(): boolean{
    //        return true;
    //    }
    /**
     * Controlli:
     *          1) Verifica correttezza campi
     *          2) se presente c'è controllo in protocol family
     */
    MetadataKeysV3.prototype.authenticatorGetInfoCheck = function () {
        if (this.authenticatorGetInfo !== undefined) {
            return this.authenticatorGetInfo.validateInternalData();
        }
        // FIXME: not sure if this should be throwing an exception or returning a false
        return false;
    };
    return MetadataKeysV3;
}());
exports.MetadataKeysV3 = MetadataKeysV3;
