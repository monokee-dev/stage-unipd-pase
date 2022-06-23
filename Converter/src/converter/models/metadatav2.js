"use strict";
exports.__esModule = true;
var fs = require("node:fs");
var y = fs.readFileSync("./Keys/FIDOV2Keys.txt", 'utf8');
//console.log(y);
/*
let x: string = "[{\"major\": 1,\"minor\": 0},{\"major\": 1, \"minor\": 1 }]";

let j = JSON.parse(x);

function a():boolean{
    if(j[0]["minor"] == 1){
        return false;
    }
    return true;
}

console.log(a());
*/
var x = "7c0903708b87115b0B422def3138c3c864e44573";
function attestationCertificateKeyIdentifiersCheck(s) {
    if (!RegExp(/^[0-9a-f]+$/).test(s))
        return false;
    return true;
}
console.log(attestationCertificateKeyIdentifiersCheck(x));
