"use strict";
exports.__esModule = true;
exports.BiometricAccuracyDescriptor = void 0;
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
exports.BiometricAccuracyDescriptor = BiometricAccuracyDescriptor;
