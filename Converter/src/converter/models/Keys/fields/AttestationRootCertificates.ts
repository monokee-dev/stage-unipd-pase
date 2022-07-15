export class AttestationRootCertificates {
    constructor(info: string[]) {
        this.data = Array.from(info);
    }
    public data: string[];
}