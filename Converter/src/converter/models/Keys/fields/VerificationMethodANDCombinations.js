"use strict";
exports.__esModule = true;
exports.VerificationMethodANDCombinationsV2 = exports.VerificationMethodANDCombinationsV3 = void 0;
var VerificationMethodANDCombinationsV3 = /** @class */ (function () {
    function VerificationMethodANDCombinationsV3(d) {
        this.data = Array.from(d);
    }
    VerificationMethodANDCombinationsV3.prototype.validateInternalData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    };
    return VerificationMethodANDCombinationsV3;
}());
exports.VerificationMethodANDCombinationsV3 = VerificationMethodANDCombinationsV3;
var VerificationMethodANDCombinationsV2 = /** @class */ (function () {
    function VerificationMethodANDCombinationsV2(d) {
        this.data = Array.from(d);
    }
    VerificationMethodANDCombinationsV2.prototype.validateInternalData = function () {
        for (var i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    };
    return VerificationMethodANDCombinationsV2;
}());
exports.VerificationMethodANDCombinationsV2 = VerificationMethodANDCombinationsV2;
