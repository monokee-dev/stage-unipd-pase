"use strict";
//import * as dotenv from 'dotenv';
exports.__esModule = true;
var MV2 = require("./converter/models/Keys/v2/MetadataV2");
var initializer_1 = require("./converter/initializer");
var metadata1 = (0, initializer_1.metadataInitializer)("./../resources/FIDOV3Keys.txt");
var metadata2;
var metadata3;
if (metadata1 instanceof MV2.MetadataKeysV2) {
    //metadata2 = metadataKeysV2.fromV2toV3(metadata1)
    //metadata3 = metadataKeysV3.fromV3toV2(metadata2)
}
else {
    //metadata2 = metadataKeysV3.fromV3toV2(metadata1)
    //metadata3 = metadataKeysV2.fromV2toV3(metadata2)
    console.log(metadata1.validateData("authenticatorGetInfo"));
}
//    console.log(JSON.stringify(metadata1));
//    console.log(JSON.stringify(metadata2))
//    console.log(JSON.stringify(metadata3))
//    console.log(metadata1)
//    console.log(metadata2)
//    console.log(metadata3)
