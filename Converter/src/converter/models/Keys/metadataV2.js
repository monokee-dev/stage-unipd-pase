"use strict";
exports.__esModule = true;
exports.ecdaaTrustAnchor = exports.attestationRootCertificates = exports.tcDisplayPNGCharacteristicsDescriptor = exports.supportedExtensions = exports.userVerificationDetails = exports.metadataKeysV2 = void 0;
var crypto_1 = require("crypto"); // per controllare attestationRootCertificates
var metadataV3_1 = require("./metadataV3");
var conversion = require("./../FieldConverter/V2toV3");
var usefulFunction_1 = require("../FieldConverter/usefulFunction");
var error_1 = require("../Error/error");
var metadataKeysV2 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function metadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm, publicKeyAlgAndEncoding, attestationTypes, userVerificationDetails, isSecondFactorOnly, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms, publicKeyAlgAndEncodings, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions) {
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
        this.userVerificationDetails = Array.from(userVerificationDetails);
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
    metadataKeysV2.fromV2toV3 = function (m) {
        var result;
        if (!m.validateAll())
            throw "Errore, metadata versione 2 non valido";
        else {
            var legalHeader = m.legalHeader != undefined ? m.legalHeader : "https://fidoalliance.org/metadata/metadata-statement-legal-header/";
            var aaid = m.aaid != undefined ? m.aaid : undefined;
            var aaguid = m.aaguid != undefined ? m.aaguid : undefined;
            var attestationCertificateKeyIdentifiers = m.attestationCertificateKeyIdentifiers != undefined ? Array.from(m.attestationCertificateKeyIdentifiers) : undefined; //
            var description = m.description;
            var alternativeDescriptions = m.alternativeDescriptions != undefined ? m.alternativeDescriptions : undefined;
            var authenticatorVersion = m.authenticatorVersion; // semplice uguaglianza in quanto c'è conversione unsigned int -> unsigned long
            //in v2 protocolFamily non è obbligatorio -> per ottenere il campo viene utilizzato assertionscheme
            var protocolFamily = void 0;
            if (m.protocolFamily != undefined) {
                protocolFamily = m.protocolFamily;
            }
            else {
                if (m.assertionScheme == "U2FV1BIN")
                    protocolFamily = "u2f";
                else if (m.assertionScheme == "FIDOV2")
                    protocolFamily = "fido2";
                else //UAFV1TLV
                    protocolFamily = "u2f";
            }
            var upv = Array.from(m.upv);
            //authenticationAlgorithms: array ricavato da elementi presenti in m.authenticationAlgorithms e/o valore singolo ricavato da m.authenticationAlgorithm 
            var authenticationAlgorithms = new Array();
            var tempAuthAlg = conversion.convertauthenticationAlgorithmV2toV3(m.authenticationAlgorithm);
            if (tempAuthAlg != undefined)
                authenticationAlgorithms.push(tempAuthAlg);
            //se l'array in m non è vuoto:
            if (m.authenticationAlgorithms != undefined) {
                //aggiungo alla variabile authenticationAlgorithms gli elementi presenti nell'array dell'oggetto
                for (var i = 0; i < m.authenticationAlgorithms.length; i++) {
                    var temp = conversion.convertauthenticationAlgorithmV2toV3(m.authenticationAlgorithms[i]);
                    if (temp != undefined)
                        authenticationAlgorithms.push(temp);
                }
            }
            var publicKeyAlgAndEncodings = new Array();
            var PubKey = conversion.convertpublicKeyAlgAndEncodingV2toV3(m.publicKeyAlgAndEncoding);
            if (PubKey != undefined) {
                publicKeyAlgAndEncodings.push(PubKey);
            }
            if (m.publicKeyAlgAndEncodings != undefined) {
                for (var i = 0; i < m.publicKeyAlgAndEncodings.length; i++) {
                    var temp = conversion.convertpublicKeyAlgAndEncodingV2toV3(m.publicKeyAlgAndEncodings[i]);
                    if (temp != undefined)
                        publicKeyAlgAndEncodings.push(temp);
                }
            }
            var attestationTypes = conversion.convertAttestationTypesV2toV3(m.attestationTypes);
            var userVerificationDetails_1 = Array();
            for (var i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails_1.push(m.userVerificationDetails[i]);
                if (!(m.userVerificationDetails[i])) {
                    for (var l = 0; l < m.userVerificationDetails[i].data.length; l++) {
                        var numEX = m.userVerificationDetails[i].data[l].userVerification;
                        userVerificationDetails_1[i].data[l].userVerification = conversion.convertUserVerificationDetailsV2toV3(m.userVerificationDetails[i].data[l].userVerification);
                    }
                }
            }
            var keyProtection = conversion.convertKeyProtectionV2toV3(m.keyProtection);
            var isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            var isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            var matcherProtection = conversion.convertMatcherProtectionV2toV3(m.matcherProtection);
            var cryptoStrength = m.cryptoStrength != undefined ? m.cryptoStrength : undefined;
            var attachmentHint = conversion.convertAttachmentHintV2toV3(m.attachmentHint);
            var tcDisplay = conversion.convertTcDisplayV2toV3(m.tcDisplay);
            var tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            var tcDisplayPNGCharacteristics = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined; //?
            var attestationRootCertificates_1 = Array.from(m.attestationRootCertificates);
            var ecdaaTrustAnchors = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            var icon = m.icon != undefined ? m.icon : undefined;
            var supportedExtensions_1 = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            var schema = conversion.convertSchemaV2toV3();
            var authenticatorgetinfo = void 0;
            if (m.aaguid == undefined) {
                if (m.assertionScheme == "FIDOV2")
                    throw "Errore, campo assertionScheme presente con valore FidoV2, perciò authenticatorgetinfo è obbligatorio: il campo aaguid non è presente";
                else
                    authenticatorgetinfo = undefined;
            }
            else
                authenticatorgetinfo = conversion.convertAuthenticatorGetInfoV2toV3(m.aaguid, m.assertionScheme);
            //ATTENZIONE controllare i vari campi all'interno del costruttore: i campi dati undefined che sono obbligatori dovrebbero essere inseriti con operatore ternario
            result = new metadataV3_1.metadataKeysV3(description, authenticatorVersion, upv, schema, attestationTypes != undefined ? attestationTypes : new Array(), attestationCertificateKeyIdentifiers, userVerificationDetails_1 != undefined ? userVerificationDetails_1 : new Array(), authenticationAlgorithms, Array.from(publicKeyAlgAndEncodings), keyProtection != undefined ? keyProtection : new Array(), matcherProtection != undefined ? matcherProtection : new Array(), cryptoStrength, attachmentHint != undefined ? attachmentHint : new Array(), tcDisplay, attestationRootCertificates_1, legalHeader, aaid, aaguid, alternativeDescriptions, protocolFamily, isKeyRestricted, isFreshUserVerificationRequired, tcDisplayContentType, tcDisplayPNGCharacteristics != undefined ? tcDisplayPNGCharacteristics : undefined, ecdaaTrustAnchors, icon, supportedExtensions_1);
        }
        return result;
    };
    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    metadataKeysV2.prototype.validateData = function (str) {
        switch (V2FunctionName[str]) {
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
                return this.upvCheck();
            case 7:
                return this.assertionSchemeCheck();
            case 8:
                return this.authenticationAlgorithmCheck();
            case 9:
                return this.authenticationAlgorithmsCheck();
            case 10:
                return this.publicKeyAlgAndEncodingCheck();
            case 11:
                return this.publicKeyAlgAndEncodingsCheck();
            case 12:
                return this.attestationTypesCheck();
            case 13:
                return this.userVerificationDetailsCheck();
            case 14:
                return this.keyProtectionCheck();
            case 15:
                return this.matcherProtectionCheck();
            case 16:
                return this.cryptoStrengthCeck();
            case 17:
                return this.operatingEnvCheck();
            case 18:
                return this.attachmentHintCheck();
            case 19:
                return this.tcDisplayCheck();
            case 20:
                return this.tcDisplayContentTypeCheck();
            case 21:
                return this.tcDisplayPNGCharacteristicsCheck();
            case 22:
                return this.attestationRootCertificatesCheck();
            case 23:
                return this.ecdaaTrustAnchorsCheck();
            case 24:
                return this.iconCheck();
            //case 25:
            //    return this.supportedExtensionsCheck();
            //    
        }
        throw "La stringa " + str + " non è una funzione di controllo";
    };
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
            throw new error_1.MetadataKeyError("Errore valore aaid");
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
    metadataKeysV2.prototype.aaguidCheck = function () {
        if (this.protocolFamily == "fido2" && this.aaguid == undefined)
            throw new error_1.MetadataKeyError("Errore valore aaguid");
        if (this.protocolFamily == "uaf" && this.aaguid != undefined)
            throw new error_1.MetadataKeyError("Errore valore aaguid");
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                throw new error_1.MetadataKeyError("Errore valore aaguid");
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
            throw new error_1.MetadataKeyError("Errore valore attestationCertificateKeyIdentifiers");
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
            throw new error_1.MetadataKeyError("Errore valore authenticatorVersion");
        return true;
    };
    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) se si usa metadata statement per u2f deve esserci obbligatoriamente il campo "u2f", se si usa FIDO 2.0/WebAuthentication Authenticator il campo deve essere "fido2"
     */
    metadataKeysV2.prototype.protocolFamilyCheck = function () {
        if (this.protocolFamily != undefined && this.protocolFamily != "uaf" && this.protocolFamily != "u2f" && this.protocolFamily != "fido2")
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        if (this.protocolFamily != "fido2" && this.assertionScheme == "FIDOV2")
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        if (this.protocolFamily != "u2f" && this.assertionScheme == "U2FV1BIN")
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        if ((this.protocolFamily != "uaf" && this.protocolFamily != undefined) && this.assertionScheme == "UAFV1TLV")
            throw new error_1.MetadataKeyError("Errore valore protocolFamily");
        return true;
    };
    /**
     * Controlli:
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     */
    metadataKeysV2.prototype.upvCheck = function () {
        for (var i = 0; i < this.upv.length; i++) {
            if (this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                throw new error_1.MetadataKeyError("Errore valore upv in posizione: " + i + ". ");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo stringa sia presente in assertionSchemeEnum (quidi che sia un tra U2FV1BIN, FIDOV2 e UAFV1TLV)
     */
    metadataKeysV2.prototype.assertionSchemeCheck = function () {
        if (assertionSchemeEnum[this.assertionScheme] == undefined)
            throw new error_1.MetadataKeyError("Errore valore assertionScheme");
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    metadataKeysV2.prototype.authenticationAlgorithmCheck = function () {
        if (this.authenticationAlgorithm < 1 || this.authenticationAlgorithm > 18)
            throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithm");
        if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
            throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithm");
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
                    throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ");
                if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
                    throw new error_1.MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ");
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
        if (this.publicKeyAlgAndEncoding <= 255 || this.publicKeyAlgAndEncoding >= 261) {
            throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncoding");
        }
        if (this.assertionScheme == "U2FV1BIN" && this.publicKeyAlgAndEncoding != 256) { // supporta solo il primo algoritmo
            throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncoding");
        }
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
                    throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ");
                if (this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
                    throw new error_1.MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ");
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
                throw new error_1.MetadataKeyError("Errore valore attestationTypes in posizione: " + i + ". ");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#idl-def-VerificationMethodDescriptor)
     */
    metadataKeysV2.prototype.userVerificationDetailsCheck = function () {
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types)
     */
    metadataKeysV2.prototype.keyProtectionCheck = function () {
        if (this.keyProtection <= 0 || this.keyProtection >= 25) { // 16 + 8 -> 24, massimo num raggiungibile (This flag MUST be set in conjunction with one of the other KEY_PROTECTION flags...)
            throw new error_1.MetadataKeyError("Errore valore keyProtection");
        }
        if (this.keyProtection != 1 && this.keyProtection != 2 && this.keyProtection != 4 && this.keyProtection != 6 &&
            this.keyProtection != 8 && this.keyProtection != 10 && this.keyProtection != 11 &&
            this.keyProtection != 17 && this.keyProtection != 18 && this.keyProtection != 20 && this.keyProtection != 24) {
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types)
     */
    metadataKeysV2.prototype.matcherProtectionCheck = function () {
        if (this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            throw new error_1.MetadataKeyError("Errore valore matcherProtection");
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     *       ATTENZIONE:   Se non si sa deve essere posta ad unknown (siccome cryptostrength è unsigned short per convenzione è posta a 0)
     */
    metadataKeysV2.prototype.cryptoStrengthCeck = function () {
        if (this.cryptoStrength != undefined) {
            if (this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                throw new error_1.MetadataKeyError("Errore valore cryptoStrength");
        }
        if (this.cryptoStrength == undefined)
            throw new error_1.MetadataKeyError("Errore valore cryptoStrength");
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo stringa sia presente in operatingEnvEnum
     */
    metadataKeysV2.prototype.operatingEnvCheck = function () {
        if (this.operatingEnv != undefined) {
            if (operatingEnvEnum[this.operatingEnv] == undefined)
                throw new error_1.MetadataKeyError("Errore valore operatingEnv");
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
            if ((i == 1 && counter >= 1 && tot != 0) || (i == 2 && counter == 0)) {
                throw new error_1.MetadataKeyError("Errore valore attachmentHint");
            }
            if (tot >= i) {
                tot = tot - i;
                counter += 1;
            }
            if (i == 1) {
                i = 0;
            }
            else {
                i = i / 2;
            }
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
        if (this.tcDisplay == 6 || this.tcDisplay == 10 || this.tcDisplay == 12) {
            throw new error_1.MetadataKeyError("Errore valore tcDisplay");
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
            throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        if (this.tcDisplayContentType != undefined) {
            if (tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non 0) e tcDisplayContentType (deve essere image/png)
     */
    metadataKeysV2.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != 0 && tcDisplayContentTypeEnum[this.tcDisplayContentType] == tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            throw new error_1.MetadataKeyError("Errore valore tcDisplayPNGCharacteristics");
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
                // or by using the attestationCertificateKeyIdentifier method => ???  TODO
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
    metadataKeysV2.prototype.ecdaaTrustAnchorsCheck = function () {
        var temp = this.attestationTypes.find(function (element) { return element == 15881; });
        if ((temp != undefined && this.ecdaaTrustAnchors == undefined) || (temp == undefined && this.ecdaaTrustAnchors != undefined))
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
    metadataKeysV2.prototype.iconCheck = function () {
        if (this.icon != undefined) {
            var temp = this.icon;
            if (this.icon.indexOf("data:") != -1) {
                temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64") + 7), "");
            }
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)) {
                throw new error_1.MetadataKeyError("Errore valore icon");
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
var V2FunctionName;
(function (V2FunctionName) {
    V2FunctionName[V2FunctionName["aaid"] = 1] = "aaid";
    V2FunctionName[V2FunctionName["aaguid"] = 2] = "aaguid";
    V2FunctionName[V2FunctionName["attestationCertificateKeyIdentifiers"] = 3] = "attestationCertificateKeyIdentifiers";
    V2FunctionName[V2FunctionName["authenticatorVersion"] = 4] = "authenticatorVersion";
    V2FunctionName[V2FunctionName["protocolFamily"] = 5] = "protocolFamily";
    V2FunctionName[V2FunctionName["upv"] = 6] = "upv";
    V2FunctionName[V2FunctionName["assertionScheme"] = 7] = "assertionScheme";
    V2FunctionName[V2FunctionName["authenticationAlgorithm"] = 8] = "authenticationAlgorithm";
    V2FunctionName[V2FunctionName["authenticationAlgorithms"] = 9] = "authenticationAlgorithms";
    V2FunctionName[V2FunctionName["publicKeyAlgAndEncoding"] = 10] = "publicKeyAlgAndEncoding";
    V2FunctionName[V2FunctionName["publicKeyAlgAndEncodings"] = 11] = "publicKeyAlgAndEncodings";
    V2FunctionName[V2FunctionName["attestationTypes"] = 12] = "attestationTypes";
    V2FunctionName[V2FunctionName["userVerificationDetails"] = 13] = "userVerificationDetails";
    V2FunctionName[V2FunctionName["keyProtection"] = 14] = "keyProtection";
    V2FunctionName[V2FunctionName["matcherProtection"] = 15] = "matcherProtection";
    V2FunctionName[V2FunctionName["cryptoStrengthCeck"] = 16] = "cryptoStrengthCeck";
    V2FunctionName[V2FunctionName["operatingEnv"] = 17] = "operatingEnv";
    V2FunctionName[V2FunctionName["attachmentHint"] = 18] = "attachmentHint";
    V2FunctionName[V2FunctionName["tcDisplay"] = 19] = "tcDisplay";
    V2FunctionName[V2FunctionName["tcDisplayContentType"] = 20] = "tcDisplayContentType";
    V2FunctionName[V2FunctionName["tcDisplayPNGCharacteristics"] = 21] = "tcDisplayPNGCharacteristics";
    V2FunctionName[V2FunctionName["attestationRootCertificates"] = 22] = "attestationRootCertificates";
    V2FunctionName[V2FunctionName["ecdaaTrustAnchors"] = 23] = "ecdaaTrustAnchors";
    V2FunctionName[V2FunctionName["icon"] = 24] = "icon";
    //supportedExtensions = 25,   
})(V2FunctionName || (V2FunctionName = {}));
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
    VerificationMethodDescriptor.prototype.validateInternalData = function () {
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
//nome completo curve sarebbe "TPM_ECC_BN_...." e "ECC_BN_...."
var G1CurveEnum;
(function (G1CurveEnum) {
    G1CurveEnum[G1CurveEnum["BN_P256"] = 0] = "BN_P256";
    G1CurveEnum[G1CurveEnum["BN_P638"] = 1] = "BN_P638";
    G1CurveEnum[G1CurveEnum["BN_ISOP256"] = 2] = "BN_ISOP256";
    G1CurveEnum[G1CurveEnum["BN_ISOP512"] = 3] = "BN_ISOP512";
})(G1CurveEnum || (G1CurveEnum = {}));
