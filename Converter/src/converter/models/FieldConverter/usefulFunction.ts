//modifica certificati per permetterne la verifica
export function convertAttestationRootCertificates(attestationRootCertificate: string): string {
    //controllo TODO
    let temp = "-----BEGIN CERTIFICATE-----\n" + attestationRootCertificate + "\n-----END CERTIFICATE-----";
    return temp;
}