"use strict";
exports.__esModule = true;
exports.ecdaaTrustAnchor = exports.attestationRootCertificates = exports.tcDisplayPNGCharacteristicsDescriptor = exports.supportedExtensions = exports.userVerificationDetails = exports.AuthenticatorGetInfo = exports.metadataKeysV3 = void 0;
var crypto_1 = require("crypto"); // per controllare attestationRootCertificates
var metadataV2_1 = require("./metadataV2");
var usefulFunction_1 = require("../FieldConverter/usefulFunction");
var V3toV2_1 = require("../FieldConverter/V3toV2");
var metadataKeysV3 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function metadataKeysV3(description, authenticatorVersion, upv, schema, attestationTypes, attestationCertificateKeyIdentifiers, userVerificationDetails, authenticationAlgorithms, publicKeyAlgAndEncodings, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, alternativeDescriptions, protocolFamily, isKeyRestricted, isFreshUserVerificationRequired, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions) {
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
    }
    //medodo statico per generazione metadata V2
    metadataKeysV3.fromV3toV2 = function (m) {
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
            var assertionScheme = (0, V3toV2_1.convertAssertionSchemaV3toV2)(m.protocolFamily);
            // prendere primo elemento array di algoritmi per inserirlo nl campo corretto (quello singolo del metadata v2)
            var authenticationAlgorithm = m.authenticationAlgorithms[0] != undefined ? (0, V3toV2_1.convertauthenticationAlgorithmV3toV2)(m.authenticationAlgorithms[0]) : undefined;
            //array con elemento in meno (posizionato nel campo precedente)
            var tempAlg = Array.from(m.authenticationAlgorithms.slice(1));
            var authenticationAlgorithms = void 0;
            if (tempAlg.length != 0) {
                authenticationAlgorithms = new Array();
                for (var i = 0; i < tempAlg.length; i++)
                    authenticationAlgorithms.push((0, V3toV2_1.convertauthenticationAlgorithmV3toV2)(tempAlg[i]));
            }
            else {
                authenticationAlgorithms = undefined;
            }
            // stesssa cosa per publicKeyAlgAndEncoding
            var publicKeyAlgAndEncoding = m.publicKeyAlgAndEncodings != undefined ? (0, V3toV2_1.convertpublicKeyAlgAndEncodingV3toV2)(m.publicKeyAlgAndEncodings[0]) : undefined;
            var tempEnc = Array.from(m.publicKeyAlgAndEncodings.slice(1));
            var publicKeyAlgAndEncodings = void 0;
            if (tempEnc.length != 0) {
                publicKeyAlgAndEncodings = new Array();
                for (var i = 0; i < tempEnc.length; i++)
                    publicKeyAlgAndEncodings.push((0, V3toV2_1.convertpublicKeyAlgAndEncodingV3toV2)(tempEnc[i]));
            }
            else {
                publicKeyAlgAndEncodings = undefined;
            }
            var attestationTypes = void 0;
            var tempAttType = (0, V3toV2_1.convertAttestationTypesV3toV2)(m.attestationTypes);
            if (tempAttType != undefined)
                attestationTypes = Array.from(tempAttType);
            var userVerificationDetails_1 = Array();
            for (var i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails_1.push(m.userVerificationDetails[i]);
                if (!(m.userVerificationDetails[i])) {
                    for (var l = 0; l < m.userVerificationDetails[i].data.length; l++) {
                        var numEX = m.userVerificationDetails[i].data[l].userVerification;
                        userVerificationDetails_1[i].data[l].userVerification = (0, V3toV2_1.convertUserVerificationDetailsV3toV2)(m.userVerificationDetails[i].data[l].userVerification);
                    }
                }
            }
            var keyProtection = (0, V3toV2_1.convertKeyProtectionV3toV2)(m.keyProtection);
            var isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            var isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            var matcherProtection = (0, V3toV2_1.convertMatcherProtectionV3toV2)(m.matcherProtection);
            var cryptoStrength = (0, V3toV2_1.convertCryptoStrength3toV2)(m.cryptoStrength);
            var operatingEnv = (0, V3toV2_1.convertOperatingEnv3toV2)();
            var attachmentHint = (0, V3toV2_1.convertAttachmentHintV3toV2)(m.attachmentHint);
            var isSecondFactorOnly = (0, V3toV2_1.convertIsSecondFactorOnly3toV2)();
            var tcDisplay = void 0;
            if (m.tcDisplay != undefined)
                tcDisplay = (0, V3toV2_1.convertTcDisplayV3toV2)(m.tcDisplay);
            else
                tcDisplay = undefined;
            var tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            var tcDisplayPNGCharacteristics = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined;
            var attestationRootCertificates_1 = Array.from(m.attestationRootCertificates);
            var ecdaaTrustAnchors = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            var icon = m.icon != undefined ? m.icon : undefined;
            var supportedExtensions_1 = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            result = new metadataV2_1.metadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm != undefined ? authenticationAlgorithm : 0, publicKeyAlgAndEncoding != undefined ? publicKeyAlgAndEncoding : 0, attestationTypes != undefined ? attestationTypes : new Array(), userVerificationDetails_1, isSecondFactorOnly, keyProtection != undefined ? keyProtection : 0, matcherProtection != undefined ? matcherProtection : 0, cryptoStrength, attachmentHint != undefined ? attachmentHint : 0, tcDisplay != undefined ? tcDisplay : 0, attestationRootCertificates_1, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms != undefined ? authenticationAlgorithms : undefined, publicKeyAlgAndEncodings != undefined ? publicKeyAlgAndEncodings : undefined, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions_1);
        }
        return result;
    };
    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    metadataKeysV3.prototype.validateData = function (str) {
        switch (V3FunctionName[str]) {
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
    metadataKeysV3.prototype.validateAll = function () {
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
    //controllo upv
    /*
        jsonParsed[0]["minor"] == 1){
    */
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
    metadataKeysV3.prototype.aaidCheck = function () {
        if (this.protocolFamily == "uaf" && this.aaid == undefined)
            return false;
        //no distinzione upper-lower case
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
    metadataKeysV3.prototype.aaguidCheck = function () {
        if ((this.protocolFamily == "fido2" && this.aaguid == undefined) || (this.protocolFamily == "uaf" && this.aaguid != undefined))
            return false;
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    metadataKeysV3.prototype.attestationCertificateKeyIdentifiersCheck = function () {
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
    metadataKeysV3.prototype.authenticatorVersionCheck = function () {
        if (this.authenticatorVersion < 0 || this.authenticatorVersion > 4294967295)
            return false;
        if (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.firmwareVersion != this.authenticatorVersion)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) controllo corrispondenza con campo "version" di authenticatorgetinfo
     */
    metadataKeysV3.prototype.protocolFamilyCheck = function () {
        if (this.protocolFamily == undefined)
            return false;
        if (protocolFamilyEnum[this.protocolFamily] == undefined)
            return false;
        if (this.authenticatorGetInfo != undefined) {
            if (this.protocolFamily == "fido2" && (this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_1"; }) == undefined &&
                this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_0"; }) == undefined &&
                this.authenticatorGetInfo.version.find(function (element) { return element == "FIDO_2_1_PRE"; }) == undefined))
                return false;
            if (this.protocolFamily == "u2f" && (this.authenticatorGetInfo.version.find(function (element) { return element == "U2F_V2"; }) == undefined))
                return false;
        }
        return true;
    };
    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    metadataKeysV3.prototype.schemaCheck = function () {
        if (this.schema < 0 || this.schema > 65535)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     *          2) controlli specifici non effettuati sulla versione nei casi UAF, U2F e FIDO2/CTAP2
     */
    metadataKeysV3.prototype.upvCheck = function () {
        for (var i = 0; i < this.upv.length; i++) {
            if (this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che secp256r1_ecdsa_sha256_raw
     */
    metadataKeysV3.prototype.authenticationAlgorithmsCheck = function () {
        if (this.authenticationAlgorithms != undefined) {
            for (var i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (authenticationAlgorithmsEnum[this.authenticationAlgorithms[i]] == undefined)
                    return false;
                if (this.protocolFamily == "u2f" && this.authenticationAlgorithms[i] != "secp256r1_ecdsa_sha256_raw")
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che ecc_x962_raw
     */
    metadataKeysV3.prototype.publicKeyAlgAndEncodingsCheck = function () {
        if (this.publicKeyAlgAndEncodings != undefined) {
            for (var i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (publicKeyAlgAndEncodingsEnum[this.publicKeyAlgAndEncodings[i]] == undefined)
                    return false;
                if (this.protocolFamily == "u2f" && this.publicKeyAlgAndEncodings[i] != "ecc_x962_raw")
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi stringa siano basic_full, basic_surrogate, ecdaa oppure attca
     */
    metadataKeysV3.prototype.attestationTypesCheck = function () {
        for (var i = 0; i < this.attestationTypes.length; i++) {
            if (attestationTypesEnum[this.attestationTypes[i]] == undefined)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
     */
    metadataKeysV3.prototype.userVerificationDetailsCheck = function () {
        for (var i = 0; i < this.userVerificationDetails.length; i++) {
            if (!(this.userVerificationDetails[i])) {
                for (var l = 0; l < this.userVerificationDetails[i].data.length; l++) {
                    if (!this.userVerificationDetails[i].data[l].validateInternalData())
                        return false;
                }
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campi (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types)
     */
    metadataKeysV3.prototype.keyProtectionCheck = function () {
        for (var i = 0; i < this.keyProtection.length; i++) {
            if (keyProtectionEnum[this.keyProtection[i]] == undefined)
                return false;
        }
        if (this.keyProtection.find(function (element) { return element == "software"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element == "hardware"; }) != undefined)
                return false;
            if (this.keyProtection.find(function (element) { return element == "tee"; }) != undefined)
                return false;
            if (this.keyProtection.find(function (element) { return element == "secure_element"; }) != undefined)
                return false;
        }
        if (this.keyProtection.find(function (element) { return element == "tee"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element == "secure_element"; }) != undefined)
                return false;
        }
        //(remote_handle) MUST be set in conjunction with one of the other KEY_PROTECTION flags 
        if (this.keyProtection.find(function (element) { return element == "remote_handle"; }) != undefined) {
            if (this.keyProtection.find(function (element) { return element != "remote_handle"; }) == undefined)
                return false;
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
    metadataKeysV3.prototype.matcherProtectionCheck = function () {
        for (var i = 0; i < this.matcherProtection.length; i++) {
            if (matcherProtectionEnum[this.matcherProtection[i]] == undefined)
                return false;
        }
        if (this.matcherProtection.find(function (element) { return element == "software"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element == "tee"; }) != undefined || this.matcherProtection.find(function (element) { return element == "on_chip"; }) != undefined)
                return false;
        }
        if (this.matcherProtection.find(function (element) { return element == "tee"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element == "on_chip"; }) != undefined)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     */
    metadataKeysV3.prototype.cryptoStrengthCeck = function () {
        if (this.cryptoStrength != undefined) {
            if (this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    metadataKeysV3.prototype.attachmentHintCheck = function () {
        for (var i = 0; i < this.matcherProtection.length; i++) {
            if (attachmentHintEnum[this.attachmentHint[i]] == undefined)
                return false;
        }
        //se c'è elemento internal insieme ad un altro elemento differente --> errore
        if (this.matcherProtection.find(function (element) { return element == "internal"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element != "internal"; }) != undefined)
                return false;
        }
        //se si ha elemento external senza altri elementi si ha errore (il controllo su internal non è stato fatto in quanto fatto dall'if precedente)
        if (this.matcherProtection.find(function (element) { return element == "external"; }) != undefined) {
            if (this.matcherProtection.find(function (element) { return element != "external"; }) == undefined)
                return false;
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
    metadataKeysV3.prototype.tcDisplayCheck = function () {
        if (this.tcDisplay != undefined) {
            for (var i = 0; i < this.tcDisplay.length; i++) {
                if (tcDisplayEnum[this.tcDisplay[i]] == undefined)
                    return false;
            }
            if (this.tcDisplay.find(function (element) { return element == "privileged_software"; }) != undefined) {
                if (this.tcDisplay.find(function (element) { return element == "tee"; }) != undefined || this.tcDisplay.find(function (element) { return element == "hardware"; }) != undefined)
                    return false;
            }
            if (this.tcDisplay.find(function (element) { return element == "tee"; }) != undefined) {
                if (this.tcDisplay.find(function (element) { return element == "hardware"; }) != undefined)
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo sia anche tcDisplay (non undefined)
     *          2) che il campo presenti un valore tra quelli presentu in tcDisplayContentTypeEnum
     */
    metadataKeysV3.prototype.tcDisplayContentTypeCheck = function () {
        if ((this.tcDisplay != undefined && this.tcDisplay.length >= 1) && this.tcDisplayContentType == undefined)
            return false;
        if (this.tcDisplayContentType != undefined && (this.tcDisplay != undefined && this.tcDisplay.length >= 1)) {
            if (tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                return false;
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non undefined) e tcDisplayContentType (deve essere image/png)
     */
    metadataKeysV3.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != undefined && tcDisplayContentTypeEnum[this.tcDisplayContentType] == tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            return false;
        return true;
    };
    /**
     * Controlli:
     *          1)
     *
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case.
     */
    metadataKeysV3.prototype.attestationRootCertificatesCheck = function () {
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
                    return false;
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if (this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(function (element) { return element == "1.3.6.1.4.1.45724.1.1.4"; }) != undefined)
                    return false;
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
    metadataKeysV3.prototype.ecdaaTrustAnchorsCheck = function () {
        var temp = this.attestationTypes.find(function (element) { return element == "ecdaa"; });
        if (temp != undefined && this.ecdaaTrustAnchors == undefined || temp == undefined && this.ecdaaTrustAnchors != undefined)
            return false;
        if (this.ecdaaTrustAnchors != undefined) {
            for (var i = 0; i < this.ecdaaTrustAnchors.length; i++) {
                if (!this.ecdaaTrustAnchors[i].validateInternalData())
                    return false;
            }
        }
        return true;
    };
    /**
     * Controlli:
     *          1) formato con cui sono inserite le immagini tramite regular expression
     */
    metadataKeysV3.prototype.iconCheck = function () {
        if (this.icon != undefined) {
            var temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64") + 7), "");
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)) {
                return false;
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
    metadataKeysV3.prototype.authenticatorGetInfoCheck = function () {
        if (this.authenticatorGetInfo != undefined)
            return this.authenticatorGetInfo.validateInternalData();
        return true;
    };
    return metadataKeysV3;
}());
exports.metadataKeysV3 = metadataKeysV3;
var Version = /** @class */ (function () {
    function Version(ma, mi) {
        this.major = ma;
        this.minor = mi;
    }
    return Version;
}());
var AuthenticatorGetInfo = /** @class */ (function () {
    function AuthenticatorGetInfo(ver, aag, ext, opt, maxM, pin, maxCc, maxCIi, tra, alg, maxA, def, fir, maxS, force, minP, maxCbl, maxRpin, pref, uvM, certif, remaining, vendor) {
        this.version = Array.from(ver);
        if (ext != undefined) {
            this.extensions = Array.from(ext);
        }
        this.aaguid = aag;
        this.options = opt;
        this.maxMsgSize = maxM;
        this.pinUvAuthProtocols = pin;
        this.maxCredentialCountInList = maxCc;
        this.maxCredentialIdLength = maxCIi;
        this.transports = tra;
        this.algorithms = alg;
        this.maxSerializedLargeBlobArray = maxS;
        this.forcePINChange = force;
        this.minPINLength = minP;
        this.firmwareVersion = fir;
        this.maxCredBlobLength = maxCbl;
        this.maxRPIDsForSetMinPINLength = maxRpin;
        this.preferredPlatformUvAttempts = pref;
        this.uvModality = uvM;
        this.certifications = certif;
        this.remainingDiscoverableCredentials = remaining;
        this.vendorPrototypeConfigCommands = vendor;
        this.maxAuthenticatorConfigLength = maxA;
        this.defaultCredProtect = def;
    }
    AuthenticatorGetInfo.prototype.validateInternalData = function () {
        //se i valori non sono tra quelli consentiti
        if (this.version.find(function (element) { return element == "FIDO_2_0"; }) == undefined && this.version.find(function (element) { return element == "U2F_V2"; }) == undefined && this.version.find(function (element) { return element == "FIDO_2_1"; }) == undefined &&
            this.version.find(function (element) { return element == "FIDO_2_1_PRE"; }) == undefined)
            return false;
        //non è possibile che come valore ci sia soltanto U2F_V2 senza almeno FIDO_2_0, perché "FIDO UAF and FIDO U2F authenticators do not support authenticatorGetInfo" (https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
        if (this.version.find(function (element) { return element == "U2F_V2"; }) != undefined && this.version.find(function (element) { return element == "FIDO_2_0"; }) == undefined)
            return false;
        //se extension no ha un valore tra quelli consentiti
        if (this.extensions != undefined && this.extensions.find(function (element) { return element == "credProtect"; }) == undefined && this.extensions.find(function (element) { return element == "credBlob"; }) == undefined &&
            this.extensions.find(function (element) { return element == "credProtect"; }) == undefined && this.extensions.find(function (element) { return element == "largeBlobKey"; }) == undefined &&
            this.extensions.find(function (element) { return element == "minPinLength"; }) == undefined && this.extensions.find(function (element) { return element == "hmac-secret"; }))
            return false;
        if (!RegExp(/^[0-9a-f]+$/).test(this.aaguid))
            return false;
        if (this.maxMsgSize != undefined && this.maxMsgSize < 0)
            return false;
        if (this.pinUvAuthProtocols != undefined) {
            for (var i = 0; i < this.pinUvAuthProtocols.length; i++) {
                if (this.pinUvAuthProtocols[i] < 0)
                    return false;
            }
        }
        if (this.maxCredentialCountInList != undefined && this.maxCredentialCountInList < 0)
            return false;
        if (this.maxCredentialIdLength != undefined && this.maxCredentialIdLength < 0)
            return false;
        if (this.transports != undefined && this.transports.find(function (element) { return element == "usb"; }) == undefined && this.transports.find(function (element) { return element == "nfc"; }) == undefined &&
            this.transports.find(function (element) { return element == "ble"; }) == undefined && this.transports.find(function (element) { return element == "internal"; }) == undefined)
            return false;
        if (this.maxSerializedLargeBlobArray != undefined && this.maxSerializedLargeBlobArray < 0)
            return false;
        if (this.minPINLength != undefined && this.minPINLength < 0)
            return false;
        if (this.firmwareVersion != undefined && this.firmwareVersion < 0)
            return false;
        if (this.maxCredBlobLength != undefined && this.maxCredBlobLength < 0)
            return false;
        if (this.maxRPIDsForSetMinPINLength != undefined && this.maxRPIDsForSetMinPINLength < 0)
            return false;
        if (this.preferredPlatformUvAttempts != undefined && this.preferredPlatformUvAttempts < 0)
            return false;
        if (this.certifications != undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2"; }) == undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIPS-CMVP-3"; }) == undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2-PHY"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIPS-CMVP-3-PHY"; }) == undefined && this.certifications.find(function (element) { return element == "CC-EAL"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIDO"; }) == undefined)
            return false;
        if (this.remainingDiscoverableCredentials != undefined && this.remainingDiscoverableCredentials < 0)
            return false;
        if (this.vendorPrototypeConfigCommands != undefined) {
            for (var i = 0; i < this.vendorPrototypeConfigCommands.length; i++) {
                if (this.vendorPrototypeConfigCommands[i] < 0)
                    return false;
            }
        }
        return true;
    };
    return AuthenticatorGetInfo;
}());
exports.AuthenticatorGetInfo = AuthenticatorGetInfo;
//controlli da fare
var authenticatorOption = /** @class */ (function () {
    function authenticatorOption(p, r, c, up, uv, uvT, no, la, ep, bio, user, uvBio, auth, uva, cred, crede, setM, make, alw) {
        if (p === void 0) { p = false; }
        if (r === void 0) { r = false; }
        if (c === void 0) { c = null; }
        if (up === void 0) { up = true; }
        if (uv === void 0) { uv = null; }
        this.plat = p;
        this.rk = r;
        this.clientPin = c;
        this.up = up;
        this.uv = uv;
        this.pinUvAuthToken = uvT;
        this.noMcGaPermissionsWithClientPin = no;
        this.largeBlobs = la;
        this.ep = ep;
        this.bioEnroll = bio;
        this.userVerificationMgmtPreview = user;
        this.uvBioEnroll = uvBio;
        this.authnrCfg = auth;
        this.uvAcfg = uva;
        this.credMgmt = cred;
        this.credentialMgmtPreview = crede;
        this.setMinPINLength = setM;
        this.makeCredUvNotRqd = make;
        this.alwaysUv = alw;
    }
    return authenticatorOption;
}());
var algorithmAuthenticatorGetInfo = /** @class */ (function () {
    function algorithmAuthenticatorGetInfo(type, alg) {
        this.type = type;
        this.alg = alg;
    }
    return algorithmAuthenticatorGetInfo;
}());
var V3FunctionName;
(function (V3FunctionName) {
    V3FunctionName[V3FunctionName["aaidCheck"] = 1] = "aaidCheck";
    V3FunctionName[V3FunctionName["aaguidCheck"] = 2] = "aaguidCheck";
    V3FunctionName[V3FunctionName["attestationCertificateKeyIdentifiersCheck"] = 3] = "attestationCertificateKeyIdentifiersCheck";
    V3FunctionName[V3FunctionName["authenticatorVersionCheck"] = 4] = "authenticatorVersionCheck";
    V3FunctionName[V3FunctionName["protocolFamilyCheck"] = 5] = "protocolFamilyCheck";
    V3FunctionName[V3FunctionName["schemaCheck"] = 6] = "schemaCheck";
    V3FunctionName[V3FunctionName["upvCheck"] = 7] = "upvCheck";
    V3FunctionName[V3FunctionName["authenticationAlgorithmsCheck"] = 8] = "authenticationAlgorithmsCheck";
    V3FunctionName[V3FunctionName["publicKeyAlgAndEncodingsCheck"] = 9] = "publicKeyAlgAndEncodingsCheck";
    V3FunctionName[V3FunctionName["attestationTypesCheck"] = 10] = "attestationTypesCheck";
    V3FunctionName[V3FunctionName["userVerificationDetailsCheck"] = 11] = "userVerificationDetailsCheck";
    V3FunctionName[V3FunctionName["keyProtectionCheck"] = 12] = "keyProtectionCheck";
    V3FunctionName[V3FunctionName["matcherProtectionCheck"] = 13] = "matcherProtectionCheck";
    V3FunctionName[V3FunctionName["cryptoStrengthCeck"] = 14] = "cryptoStrengthCeck";
    V3FunctionName[V3FunctionName["attachmentHintCheck"] = 15] = "attachmentHintCheck";
    V3FunctionName[V3FunctionName["tcDisplayCheck"] = 16] = "tcDisplayCheck";
    V3FunctionName[V3FunctionName["tcDisplayContentTypeCheck"] = 17] = "tcDisplayContentTypeCheck";
    V3FunctionName[V3FunctionName["tcDisplayPNGCharacteristicsCheck"] = 18] = "tcDisplayPNGCharacteristicsCheck";
    V3FunctionName[V3FunctionName["attestationRootCertificatesCheck"] = 19] = "attestationRootCertificatesCheck";
    V3FunctionName[V3FunctionName["ecdaaTrustAnchorsCheck"] = 20] = "ecdaaTrustAnchorsCheck";
    V3FunctionName[V3FunctionName["iconCheck"] = 21] = "iconCheck";
    V3FunctionName[V3FunctionName["authenticatorGetInfoCheck"] = 22] = "authenticatorGetInfoCheck";
    //supportedExtensionsCheck = 23,
})(V3FunctionName || (V3FunctionName = {}));
var tcDisplayEnum;
(function (tcDisplayEnum) {
    tcDisplayEnum[tcDisplayEnum["any"] = 0] = "any";
    tcDisplayEnum[tcDisplayEnum["privileged_software"] = 1] = "privileged_software";
    tcDisplayEnum[tcDisplayEnum["tee"] = 2] = "tee";
    tcDisplayEnum[tcDisplayEnum["hardware"] = 3] = "hardware";
    tcDisplayEnum[tcDisplayEnum["remote"] = 4] = "remote";
})(tcDisplayEnum || (tcDisplayEnum = {}));
var attachmentHintEnum;
(function (attachmentHintEnum) {
    attachmentHintEnum[attachmentHintEnum["internal"] = 0] = "internal";
    attachmentHintEnum[attachmentHintEnum["external"] = 1] = "external";
    attachmentHintEnum[attachmentHintEnum["wired"] = 2] = "wired";
    attachmentHintEnum[attachmentHintEnum["wireless"] = 3] = "wireless";
    attachmentHintEnum[attachmentHintEnum["nfc"] = 4] = "nfc";
    attachmentHintEnum[attachmentHintEnum["bluetooth"] = 5] = "bluetooth";
    attachmentHintEnum[attachmentHintEnum["network"] = 6] = "network";
    attachmentHintEnum[attachmentHintEnum["ready"] = 7] = "ready";
    attachmentHintEnum[attachmentHintEnum["wifi_direct"] = 8] = "wifi_direct";
})(attachmentHintEnum || (attachmentHintEnum = {}));
var matcherProtectionEnum;
(function (matcherProtectionEnum) {
    matcherProtectionEnum[matcherProtectionEnum["software"] = 0] = "software";
    matcherProtectionEnum[matcherProtectionEnum["tee"] = 1] = "tee";
    matcherProtectionEnum[matcherProtectionEnum["on_chip"] = 2] = "on_chip";
})(matcherProtectionEnum || (matcherProtectionEnum = {}));
var keyProtectionEnum;
(function (keyProtectionEnum) {
    keyProtectionEnum[keyProtectionEnum["software"] = 0] = "software";
    keyProtectionEnum[keyProtectionEnum["hardware"] = 1] = "hardware";
    keyProtectionEnum[keyProtectionEnum["tee"] = 2] = "tee";
    keyProtectionEnum[keyProtectionEnum["secure_element"] = 3] = "secure_element";
    keyProtectionEnum[keyProtectionEnum["remote_handle"] = 4] = "remote_handle";
})(keyProtectionEnum || (keyProtectionEnum = {}));
var protocolFamilyEnum;
(function (protocolFamilyEnum) {
    protocolFamilyEnum[protocolFamilyEnum["uaf"] = 0] = "uaf";
    protocolFamilyEnum[protocolFamilyEnum["u2f"] = 1] = "u2f";
    protocolFamilyEnum[protocolFamilyEnum["fido2"] = 2] = "fido2";
})(protocolFamilyEnum || (protocolFamilyEnum = {}));
//errore documentazione: 0x000B == 0x003 (solo nome tra virgolette)
var authenticationAlgorithmsEnum;
(function (authenticationAlgorithmsEnum) {
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp256r1_ecdsa_sha256_raw"] = 0] = "secp256r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp256r1_ecdsa_sha256_der"] = 1] = "secp256r1_ecdsa_sha256_der";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pss_sha256_raw"] = 2] = "rsassa_pss_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pss_sha256_der"] = 3] = "rsassa_pss_sha256_der";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp256k1_ecdsa_sha256_raw"] = 4] = "secp256k1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp256k1_ecdsa_sha256_der"] = 5] = "secp256k1_ecdsa_sha256_der";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["sm2_sm3_raw"] = 6] = "sm2_sm3_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsa_emsa_pkcs1_sha256_raw"] = 7] = "rsa_emsa_pkcs1_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsa_emsa_pkcs1_sha256_der"] = 8] = "rsa_emsa_pkcs1_sha256_der";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pss_sha384_raw"] = 9] = "rsassa_pss_sha384_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pss_sha512_raw"] = 10] = "rsassa_pss_sha512_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pkcsv15_sha256_raw"] = 11] = "rsassa_pkcsv15_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pkcsv15_sha384_raw"] = 12] = "rsassa_pkcsv15_sha384_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pkcsv15_sha512_raw"] = 13] = "rsassa_pkcsv15_sha512_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["rsassa_pkcsv15_sha1_raw"] = 14] = "rsassa_pkcsv15_sha1_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp384r1_ecdsa_sha384_raw"] = 15] = "secp384r1_ecdsa_sha384_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["secp512r1_ecdsa_sha256_raw"] = 16] = "secp512r1_ecdsa_sha256_raw";
    authenticationAlgorithmsEnum[authenticationAlgorithmsEnum["ed25519_eddsa_sha512_raw"] = 17] = "ed25519_eddsa_sha512_raw";
})(authenticationAlgorithmsEnum || (authenticationAlgorithmsEnum = {}));
var publicKeyAlgAndEncodingsEnum;
(function (publicKeyAlgAndEncodingsEnum) {
    publicKeyAlgAndEncodingsEnum[publicKeyAlgAndEncodingsEnum["ecc_x962_raw"] = 0] = "ecc_x962_raw";
    publicKeyAlgAndEncodingsEnum[publicKeyAlgAndEncodingsEnum["ecc_x962_der"] = 1] = "ecc_x962_der";
    publicKeyAlgAndEncodingsEnum[publicKeyAlgAndEncodingsEnum["rsa_2048_raw"] = 2] = "rsa_2048_raw";
    publicKeyAlgAndEncodingsEnum[publicKeyAlgAndEncodingsEnum["rsa_2048_der"] = 3] = "rsa_2048_der";
    publicKeyAlgAndEncodingsEnum[publicKeyAlgAndEncodingsEnum["cose"] = 4] = "cose";
})(publicKeyAlgAndEncodingsEnum || (publicKeyAlgAndEncodingsEnum = {}));
var attestationTypesEnum;
(function (attestationTypesEnum) {
    attestationTypesEnum[attestationTypesEnum["basic_full"] = 0] = "basic_full";
    attestationTypesEnum[attestationTypesEnum["basic_surrogate"] = 1] = "basic_surrogate";
    attestationTypesEnum[attestationTypesEnum["ecdaa"] = 2] = "ecdaa";
    attestationTypesEnum[attestationTypesEnum["attca"] = 3] = "attca";
})(attestationTypesEnum || (attestationTypesEnum = {}));
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
var VerificationMethodDescriptorUserVerificationMethodEnum;
(function (VerificationMethodDescriptorUserVerificationMethodEnum) {
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["error"] = 0] = "error";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["presence_internal"] = 1] = "presence_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["fingerprint_internal"] = 2] = "fingerprint_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["passcode_internal"] = 3] = "passcode_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["voiceprint_internal"] = 4] = "voiceprint_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["faceprint_internal"] = 5] = "faceprint_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["location_internal"] = 6] = "location_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["eyeprint_internal"] = 7] = "eyeprint_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["pattern_internal"] = 8] = "pattern_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["handprint_internal"] = 9] = "handprint_internal";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["none"] = 10] = "none";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["all"] = 11] = "all";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["passcode_external"] = 12] = "passcode_external";
    VerificationMethodDescriptorUserVerificationMethodEnum[VerificationMethodDescriptorUserVerificationMethodEnum["pattern_external"] = 13] = "pattern_external";
})(VerificationMethodDescriptorUserVerificationMethodEnum || (VerificationMethodDescriptorUserVerificationMethodEnum = {}));
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
        this.userVerification = uv;
        this.caDesc = c;
        this.baDesc = b;
        this.paDesc = p;
    }
    VerificationMethodDescriptor.prototype.validateInternalData = function () {
        if (VerificationMethodDescriptorUserVerificationMethodEnum[this.userVerification] == undefined)
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
    VerificationMethodANDCombinations.prototype.validateInternalData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
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
    userVerificationDetails.prototype.validateInternalData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
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
    rgbPaletteEntry.prototype.validateInternalData = function () {
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
    ecdaaTrustAnchor.prototype.validateInternalData = function () {
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
