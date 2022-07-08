//modifica certificati per permetterne la verifica
export function convertAttestationRootCertificates(attestationRootCertificate: string): string {
    let temp = "-----BEGIN CERTIFICATE-----\n" + attestationRootCertificate + "\n-----END CERTIFICATE-----";
    return temp;
}