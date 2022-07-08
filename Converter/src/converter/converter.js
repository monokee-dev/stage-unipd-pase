"use strict";
exports.__esModule = true;
var fs = require("node:fs");
var j = JSON.stringify(fs.readFileSync("./FIDOV2Keys.txt"));
console.log(j);
