"use strict";
exports.__esModule = true;
exports.ExtensionDescriptor = void 0;
var ExtensionDescriptor = /** @class */ (function () {
    function ExtensionDescriptor(i, f, t, d) {
        this.id = i;
        this.tag = t;
        this.data = d;
        this.fail_if_unknown = f;
    }
    return ExtensionDescriptor;
}());
exports.ExtensionDescriptor = ExtensionDescriptor;
