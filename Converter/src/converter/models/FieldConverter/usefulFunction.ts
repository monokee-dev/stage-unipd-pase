//modifica certificati per permetterne la verifica
export function convertAttestationRootCertificates(attestationRootCertificate: string): string {
    //controllo 
    if(attestationRootCertificate.indexOf("-----BEGIN CERTIFICATE-----") == 0 && attestationRootCertificate.indexOf("\n-----END CERTIFICATE-----") == (attestationRootCertificate.length - 26)){
        return attestationRootCertificate;
    }
    let temp = "-----BEGIN CERTIFICATE-----\n" + attestationRootCertificate + "\n-----END CERTIFICATE-----";
    return temp;
}