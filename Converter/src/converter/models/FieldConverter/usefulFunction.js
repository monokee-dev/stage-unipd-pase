"use strict";
exports.__esModule = true;
exports.convertAttestationRootCertificates = void 0;
//modifica certificati per permetterne la verifica
function convertAttestationRootCertificates(attestationRootCertificate) {
    //controllo
    var temp = "-----BEGIN CERTIFICATE-----\n" + attestationRootCertificate + "\n-----END CERTIFICATE-----";
    return temp;
}
exports.convertAttestationRootCertificates = convertAttestationRootCertificates;
