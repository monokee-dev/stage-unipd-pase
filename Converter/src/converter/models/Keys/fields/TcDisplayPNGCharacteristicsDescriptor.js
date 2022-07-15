"use strict";
exports.__esModule = true;
exports.TcDisplayPNGCharacteristicsDescriptor = void 0;
var TcDisplayPNGCharacteristicsDescriptor = /** @class */ (function () {
    function TcDisplayPNGCharacteristicsDescriptor(w, h, b, c, f, i, p) {
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
        this.plte = p != undefined ? Array.from(p) : undefined;
    }
    return TcDisplayPNGCharacteristicsDescriptor;
}());
exports.TcDisplayPNGCharacteristicsDescriptor = TcDisplayPNGCharacteristicsDescriptor;
