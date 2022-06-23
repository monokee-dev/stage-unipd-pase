"use strict";
exports.__esModule = true;
exports.Converter = void 0;
var metadatav3_1 = require("./models/metadatav3");
var keys;
(function (keys) {
    keys[keys["T"] = 0] = "T";
    keys[keys["A"] = 1] = "A";
    keys[keys["B"] = 2] = "B";
})(keys || (keys = {}));
var Converter = /** @class */ (function () {
    function Converter() {
    }
    Converter.prototype.convert = function (metadata) {
        var result = new metadatav3_1.MetadataV3();
        result.id = metadata.id;
        return result;
    };
    return Converter;
}());
exports.Converter = Converter;
