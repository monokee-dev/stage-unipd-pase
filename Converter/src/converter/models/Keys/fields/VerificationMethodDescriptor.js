"use strict";
exports.__esModule = true;
exports.VerificationMethodDescriptorV2 = exports.VerificationMethodDescriptorV3 = void 0;
var enums_1 = require("./enums");
var VerificationMethodDescriptorV3 = /** @class */ (function () {
    function VerificationMethodDescriptorV3(uv, c, b, p) {
        this.userVerification = uv;
        this.caDesc = c;
        this.baDesc = b;
        this.paDesc = p;
    }
    VerificationMethodDescriptorV3.prototype.validateInternalData = function () {
        if (enums_1.VerificationMethodDescriptorUserVerificationMethodEnum[this.userVerification] == undefined)
            return false;
        else
            return true;
    };
    return VerificationMethodDescriptorV3;
}());
exports.VerificationMethodDescriptorV3 = VerificationMethodDescriptorV3;
var VerificationMethodDescriptorV2 = /** @class */ (function () {
    function VerificationMethodDescriptorV2(uv, c, b, p) {
        if (uv === void 0) { uv = 0; }
        this.userVerification = uv;
        this.caDesc = c;
        this.baDesc = b;
        this.paDesc = p;
    }
    VerificationMethodDescriptorV2.prototype.validateInternalData = function () {
        if (this.userVerification == 0 || this.userVerification != 1024 || 512 || 256 || 128 || 64 || 32 || 16 || 8 || 4 || 2 || 1)
            return false;
        else
            return true;
    };
    return VerificationMethodDescriptorV2;
}());
exports.VerificationMethodDescriptorV2 = VerificationMethodDescriptorV2;
