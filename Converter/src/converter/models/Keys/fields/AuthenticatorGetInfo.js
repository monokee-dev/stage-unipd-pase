"use strict";
exports.__esModule = true;
exports.AuthenticatorGetInfo = void 0;
var error_1 = require("./../../Error/error");
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
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: version");
        //non è possibile che come valore ci sia soltanto U2F_V2 senza almeno FIDO_2_0, perché "FIDO UAF and FIDO U2F authenticators do not support authenticatorGetInfo" (https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
        if (this.version.find(function (element) { return element == "U2F_V2"; }) != undefined && this.version.find(function (element) { return element == "FIDO_2_0"; }) == undefined)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: version");
        //se extension no ha un valore tra quelli consentiti
        if (this.extensions != undefined && this.extensions.find(function (element) { return element == "credProtect"; }) == undefined && this.extensions.find(function (element) { return element == "credBlob"; }) == undefined &&
            this.extensions.find(function (element) { return element == "credProtect"; }) == undefined && this.extensions.find(function (element) { return element == "largeBlobKey"; }) == undefined &&
            this.extensions.find(function (element) { return element == "minPinLength"; }) == undefined && this.extensions.find(function (element) { return element == "hmac-secret"; }))
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: extensions");
        if (!RegExp(/^[0-9a-f]+$/).test(this.aaguid))
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: aaguid");
        if (this.maxMsgSize != undefined && this.maxMsgSize < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxMsgSize");
        if (this.pinUvAuthProtocols != undefined) {
            for (var i = 0; i < this.pinUvAuthProtocols.length; i++) {
                if (this.pinUvAuthProtocols[i] < 0)
                    throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: pinUvAuthProtocols in posizione: " + i);
            }
        }
        if (this.maxCredentialCountInList != undefined && this.maxCredentialCountInList < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxCredentialCountInList");
        if (this.maxCredentialIdLength != undefined && this.maxCredentialIdLength < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxCredentialIdLength");
        if (this.transports != undefined && this.transports.find(function (element) { return element == "usb"; }) == undefined && this.transports.find(function (element) { return element == "nfc"; }) == undefined &&
            this.transports.find(function (element) { return element == "ble"; }) == undefined && this.transports.find(function (element) { return element == "internal"; }) == undefined)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: transports");
        if (this.maxSerializedLargeBlobArray != undefined && this.maxSerializedLargeBlobArray < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxSerializedLargeBlobArray");
        if (this.minPINLength != undefined && this.minPINLength < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: minPINLength");
        if (this.firmwareVersion != undefined && this.firmwareVersion < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: firmwareVersion");
        if (this.maxCredBlobLength != undefined && this.maxCredBlobLength < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxCredBlobLength");
        if (this.maxRPIDsForSetMinPINLength != undefined && this.maxRPIDsForSetMinPINLength < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: maxRPIDsForSetMinPINLength");
        if (this.preferredPlatformUvAttempts != undefined && this.preferredPlatformUvAttempts < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: preferredPlatformUvAttempts");
        if (this.certifications != undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2"; }) == undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIPS-CMVP-3"; }) == undefined && this.certifications.find(function (element) { return element == "FIPS-CMVP-2-PHY"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIPS-CMVP-3-PHY"; }) == undefined && this.certifications.find(function (element) { return element == "CC-EAL"; }) == undefined &&
            this.certifications.find(function (element) { return element == "FIDO"; }) == undefined)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: certifications");
        if (this.remainingDiscoverableCredentials != undefined && this.remainingDiscoverableCredentials < 0)
            throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: remainingDiscoverableCredentials");
        if (this.vendorPrototypeConfigCommands != undefined) {
            for (var i = 0; i < this.vendorPrototypeConfigCommands.length; i++) {
                if (this.vendorPrototypeConfigCommands[i] < 0)
                    throw new error_1.MetadataKeyError("Errore valore authenticatorGetInfo: vendorPrototypeConfigCommands in posizione: " + i);
            }
        }
        return true;
    };
    return AuthenticatorGetInfo;
}());
exports.AuthenticatorGetInfo = AuthenticatorGetInfo;
