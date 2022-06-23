"use strict";
exports.__esModule = true;
exports.supportedExtensionsV2 = exports.tcDisplayV2 = exports.attachmentHintV2 = exports.matcherProtectionV2 = exports.keyProtectionV2 = exports.userVerificationDetailsV2 = exports.attestationTypesV2 = void 0;
var attestationTypesV2 = /** @class */ (function () {
    function attestationTypesV2(info) {
        this.data = Array.from(info);
    }
    attestationTypesV2.prototype.validateData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (this.data[i] < 15879 || this.data[i] > 15882)
                throw "campo attestationTypes non valido";
            else if (i == this.data.length - 1)
                return true;
        }
    };
    return attestationTypesV2;
}());
exports.attestationTypesV2 = attestationTypesV2;
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
            throw "campo VerificationMethodDescriptor: userVerification non valido";
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
            this.data[i].validateData();
        }
    };
    return VerificationMethodANDCombinations;
}());
var userVerificationDetailsV2 = /** @class */ (function () {
    function userVerificationDetailsV2(info) {
        this.data = Array.from(info);
    }
    userVerificationDetailsV2.prototype.validateData = function () {
        for (var i = 0; i < this.data.length; i++) {
            this.data[i].validateData();
        }
    };
    return userVerificationDetailsV2;
}());
exports.userVerificationDetailsV2 = userVerificationDetailsV2;
var keyProtectionV2 = /** @class */ (function () {
    function keyProtectionV2() {
    }
    return keyProtectionV2;
}());
exports.keyProtectionV2 = keyProtectionV2;
var matcherProtectionV2 = /** @class */ (function () {
    function matcherProtectionV2() {
    }
    return matcherProtectionV2;
}());
exports.matcherProtectionV2 = matcherProtectionV2;
var attachmentHintV2 = /** @class */ (function () {
    function attachmentHintV2() {
    }
    return attachmentHintV2;
}());
exports.attachmentHintV2 = attachmentHintV2;
var tcDisplayV2 = /** @class */ (function () {
    function tcDisplayV2() {
    }
    return tcDisplayV2;
}());
exports.tcDisplayV2 = tcDisplayV2;
var supportedExtensionsV2 = /** @class */ (function () {
    function supportedExtensionsV2() {
    }
    return supportedExtensionsV2;
}());
exports.supportedExtensionsV2 = supportedExtensionsV2;
