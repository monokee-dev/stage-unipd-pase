"use strict";
exports.__esModule = true;
var initializer_1 = require("./converter/initializer");
var metadata1 = (0, initializer_1.metadataInitializer)("./FIDOV2Keys.txt");
//let metadata2;
/*
if(metadata1 instanceof metadataKeysV2)
    metadata2 = metadataKeysV2.fromV2toV3(metadata1);
else
    metadata2 = metadataKeysV3.fromV3toV2(metadata1);

let metadataStringify = JSON.stringify(metadata1);
let metadataReParse = JSON.parse(metadataStringify);
console.log(metadataReParse)
*/
console.log(metadata1.validateAll());
