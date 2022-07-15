"use strict";
exports.__esModule = true;
exports.ECDAATrustAnchor = void 0;
var enums_1 = require("./enums");
//This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
var ECDAATrustAnchor = /** @class */ (function () {
    function ECDAATrustAnchor(x, y, c, s1, s2, g) {
        this.X = x;
        this.Y = y;
        this.c = c;
        this.sx = s1;
        this.sy = s2;
        this.G1Curve = g;
    }
    ECDAATrustAnchor.prototype.validateInternalData = function () {
        if (enums_1.G1CurveEnum[this.G1Curve] == undefined)
            return false;
        return true;
    };
    return ECDAATrustAnchor;
}());
exports.ECDAATrustAnchor = ECDAATrustAnchor;
