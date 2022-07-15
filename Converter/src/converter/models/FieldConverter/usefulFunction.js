"use strict";
exports.__esModule = true;
exports.convertAttestationRootCertificates = void 0;
//modifica certificati per permetterne la verifica
function convertAttestationRootCertificates(attestationRootCertificate) {
    //controllo 
    if (attestationRootCertificate.indexOf("-----BEGIN CERTIFICATE-----") == 0 && attestationRootCertificate.indexOf("\n-----END CERTIFICATE-----") == (attestationRootCertificate.length - 26)) {
        return attestationRootCertificate;
    }
    var temp = "-----BEGIN CERTIFICATE-----\n" + attestationRootCertificate + "\n-----END CERTIFICATE-----";
    return temp;
}
exports.convertAttestationRootCertificates = convertAttestationRootCertificates;
