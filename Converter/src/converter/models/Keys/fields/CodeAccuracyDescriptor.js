"use strict";
exports.__esModule = true;
exports.CodeAccuracyDescriptor = void 0;
var CodeAccuracyDescriptor = /** @class */ (function () {
    function CodeAccuracyDescriptor(ba, mL, mR, bl) {
        this.base = ba;
        this.minLength = mL;
        this.maxRetries = mR;
        this.blockSlowdown = bl;
    }
    return CodeAccuracyDescriptor;
}());
exports.CodeAccuracyDescriptor = CodeAccuracyDescriptor;
