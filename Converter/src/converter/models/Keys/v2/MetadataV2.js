"use strict";
exports.__esModule = true;
exports.MetadataKeysV2 = void 0;
var crypto_1 = require("crypto"); // per controllare attestationRootCertificates
var conversion = require("../../FieldConverter/V2toV3");
var usefulFunction_1 = require("../../FieldConverter/usefulFunction");
var error_1 = require("../../Error/error");
var MetadataV3_1 = require("../v3/MetadataV3");
var Enum = require("./../fields/enums");
var MetadataKeysV2 = /** @class */ (function () {
    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    function MetadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm, publicKeyAlgAndEncoding, attestationTypes, userVerificationDetails, isSecondFactorOnly, keyProtection, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, alternativeDescriptions, protocolFamily, authenticationAlgorithms, publicKeyAlgAndEncodings, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType, tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions) {
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
    MetadataKeysV2.fromV2toV3 = function (m) {
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
            var tempAuthAlg = conversion.V2toV3.convertauthenticationAlgorithm(m.authenticationAlgorithm);
            if (tempAuthAlg != undefined)
                authenticationAlgorithms.push(tempAuthAlg);
            //se l'array in m non è vuoto:
            if (m.authenticationAlgorithms != undefined) {
                //aggiungo alla variabile authenticationAlgorithms gli elementi presenti nell'array dell'oggetto
                for (var i = 0; i < m.authenticationAlgorithms.length; i++) {
                    var temp = conversion.V2toV3.convertauthenticationAlgorithm(m.authenticationAlgorithms[i]);
                    if (temp != undefined)
                        authenticationAlgorithms.push(temp);
                }
            }
            var publicKeyAlgAndEncodings = new Array();
            var PubKey = conversion.V2toV3.convertpublicKeyAlgAndEncoding(m.publicKeyAlgAndEncoding);
            if (PubKey != undefined) {
                publicKeyAlgAndEncodings.push(PubKey);
            }
            if (m.publicKeyAlgAndEncodings != undefined) {
                for (var i = 0; i < m.publicKeyAlgAndEncodings.length; i++) {
                    var temp = conversion.V2toV3.convertpublicKeyAlgAndEncoding(m.publicKeyAlgAndEncodings[i]);
                    if (temp != undefined)
                        publicKeyAlgAndEncodings.push(temp);
                }
            }
            var attestationTypes = conversion.V2toV3.convertAttestationTypes(m.attestationTypes);
            var userVerificationDetails = Array();
            for (var i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails.push(m.userVerificationDetails[i]);
                if (!(m.userVerificationDetails[i])) {
                    for (var l = 0; l < m.userVerificationDetails[i].data.length; l++) {
                        var numEX = m.userVerificationDetails[i].data[l].userVerification;
                        userVerificationDetails[i].data[l].userVerification = conversion.V2toV3.convertUserVerificationDetails(m.userVerificationDetails[i].data[l].userVerification);
                    }
                }
            }
            var keyProtection = conversion.V2toV3.convertKeyProtection(m.keyProtection);
            var isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            var isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            var matcherProtection = conversion.V2toV3.convertMatcherProtection(m.matcherProtection);
            var cryptoStrength = m.cryptoStrength != undefined ? m.cryptoStrength : undefined;
            var attachmentHint = conversion.V2toV3.convertAttachmentHint(m.attachmentHint);
            var tcDisplay = conversion.V2toV3.convertTcDisplay(m.tcDisplay);
            var tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            var tcDisplayPNGCharacteristics = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined; //?
            var attestationRootCertificates = Array.from(m.attestationRootCertificates);
            var ecdaaTrustAnchors = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            var icon = m.icon != undefined ? m.icon : undefined;
            var supportedExtensions = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            var schema = conversion.V2toV3.convertSchema();
            var authenticatorGetInfo = void 0;
            if (m.aaguid == undefined) {
                if (m.assertionScheme == "FIDOV2") {
                    throw "Errore, campo assertionScheme presente con valore FidoV2, perciò authenticatorGetInfo è obbligatorio: il campo aaguid non è presente";
                }
                else {
                    authenticatorGetInfo = undefined;
                }
            }
            else {
                authenticatorGetInfo = conversion.V2toV3.convertAuthenticatorGetInfo(m.aaguid, m.assertionScheme, m.isSecondFactorOnly, m.authenticatorVersion);
            }
            //ATTENZIONE controllare i vari campi all'interno del costruttore: i campi dati undefined che sono obbligatori dovrebbero essere inseriti con operatore ternario
            result = new MetadataV3_1.MetadataKeysV3(description, authenticatorVersion, upv, schema, attestationTypes != undefined ? attestationTypes : new Array(), attestationCertificateKeyIdentifiers, userVerificationDetails != undefined ? userVerificationDetails : new Array(), authenticationAlgorithms, Array.from(publicKeyAlgAndEncodings), keyProtection != undefined ? keyProtection : new Array(), matcherProtection != undefined ? matcherProtection : new Array(), cryptoStrength, attachmentHint != undefined ? attachmentHint : new Array(), tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, alternativeDescriptions, protocolFamily, isKeyRestricted, isFreshUserVerificationRequired, tcDisplayContentType, tcDisplayPNGCharacteristics != undefined ? tcDisplayPNGCharacteristics : undefined, ecdaaTrustAnchors, icon, supportedExtensions, authenticatorGetInfo);
        }
        return result;
    };
    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    MetadataKeysV2.prototype.validateData = function (str) {
        switch (Enum.V2FunctionName[str]) {
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
    MetadataKeysV2.prototype.validateAll = function () {
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
    MetadataKeysV2.prototype.aaidCheck = function () {
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
    MetadataKeysV2.prototype.aaguidCheck = function () {
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
    MetadataKeysV2.prototype.attestationCertificateKeyIdentifiersCheck = function () {
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
    MetadataKeysV2.prototype.authenticatorVersionCheck = function () {
        if (this.authenticatorVersion < 0 || this.authenticatorVersion > 65535) {
            throw new error_1.MetadataKeyError("Errore valore authenticatorVersion");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) se si usa metadata statement per u2f deve esserci obbligatoriamente il campo "u2f", se si usa FIDO 2.0/WebAuthentication Authenticator il campo deve essere "fido2"
     */
    MetadataKeysV2.prototype.protocolFamilyCheck = function () {
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
    MetadataKeysV2.prototype.upvCheck = function () {
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
    MetadataKeysV2.prototype.assertionSchemeCheck = function () {
        if (Enum.assertionSchemeEnum[this.assertionScheme] == undefined)
            throw new error_1.MetadataKeyError("Errore valore assertionScheme");
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    MetadataKeysV2.prototype.authenticationAlgorithmCheck = function () {
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
    MetadataKeysV2.prototype.authenticationAlgorithmsCheck = function () {
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
    MetadataKeysV2.prototype.publicKeyAlgAndEncodingCheck = function () {
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
    MetadataKeysV2.prototype.publicKeyAlgAndEncodingsCheck = function () {
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
    MetadataKeysV2.prototype.attestationTypesCheck = function () {
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
    MetadataKeysV2.prototype.userVerificationDetailsCheck = function () {
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
    MetadataKeysV2.prototype.keyProtectionCheck = function () {
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
    MetadataKeysV2.prototype.matcherProtectionCheck = function () {
        if (this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            throw new error_1.MetadataKeyError("Errore valore matcherProtection");
        return true;
    };
    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     *       ATTENZIONE:   Se non si sa deve essere posta ad unknown (siccome cryptostrength è unsigned short per convenzione è posta a 0)
     */
    MetadataKeysV2.prototype.cryptoStrengthCeck = function () {
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
    MetadataKeysV2.prototype.operatingEnvCheck = function () {
        if (this.operatingEnv != undefined) {
            if (Enum.operatingEnvEnum[this.operatingEnv] == undefined)
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
    MetadataKeysV2.prototype.attachmentHintCheck = function () {
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
    MetadataKeysV2.prototype.tcDisplayCheck = function () {
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
    MetadataKeysV2.prototype.tcDisplayContentTypeCheck = function () {
        if (this.tcDisplay != 0 && this.tcDisplayContentType == undefined)
            throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        if (this.tcDisplayContentType != undefined) {
            if (Enum.tcDisplayContentTypeEnum[this.tcDisplayContentType] == undefined)
                throw new error_1.MetadataKeyError("Errore valore tcDisplayContentType");
        }
        return true;
    };
    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non 0) e tcDisplayContentType (deve essere image/png)
     */
    MetadataKeysV2.prototype.tcDisplayPNGCharacteristicsCheck = function () {
        if (this.tcDisplay != 0 && Enum.tcDisplayContentTypeEnum[this.tcDisplayContentType] == Enum.tcDisplayContentTypeEnum["image/png"] && this.tcDisplayPNGCharacteristics == undefined)
            throw new error_1.MetadataKeyError("Errore valore tcDisplayPNGCharacteristics");
        return true;
    };
    /**
     * Controlli:
     *          1)
     *
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case.
     */
    MetadataKeysV2.prototype.attestationRootCertificatesCheck = function () {
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
    MetadataKeysV2.prototype.ecdaaTrustAnchorsCheck = function () {
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
    MetadataKeysV2.prototype.iconCheck = function () {
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
    return MetadataKeysV2;
}());
exports.MetadataKeysV2 = MetadataKeysV2;
