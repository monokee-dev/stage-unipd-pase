"use strict";
exports.__esModule = true;
exports.PatternAccuracyDescriptor = void 0;
var PatternAccuracyDescriptor = /** @class */ (function () {
    function PatternAccuracyDescriptor(ba, mL, bl) {
        this.minComplexity = ba;
        this.maxRetries = mL;
        this.blockSlowdown = bl;
    }
    return PatternAccuracyDescriptor;
}());
exports.PatternAccuracyDescriptor = PatternAccuracyDescriptor;
