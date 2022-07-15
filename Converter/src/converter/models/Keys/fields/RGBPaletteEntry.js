"use strict";
exports.__esModule = true;
exports.RGBPaletteEntry = void 0;
var RGBPaletteEntry = /** @class */ (function () {
    function RGBPaletteEntry(r1, g1, b1) {
        if (r1 === void 0) { r1 = 0; }
        if (g1 === void 0) { g1 = 0; }
        if (b1 === void 0) { b1 = 0; }
        this.r = r1;
        this.g = g1;
        this.b = b1;
    }
    RGBPaletteEntry.prototype.validateInternalData = function () {
        if (this.r < 0 || this.r > 255 || this.g < 0 || this.g > 255 || this.b < 0 || this.b > 255) {
            return false;
        }
        else {
            return true;
        }
    };
    return RGBPaletteEntry;
}());
exports.RGBPaletteEntry = RGBPaletteEntry;
