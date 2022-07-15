class BiometricAccuracyDescriptor {
    constructor(SFR?: boolean, SFA?: boolean, mT?: number, mR?: number, bls?: number) {
        this.selfAttestedFRR = SFR!;
        this.selfAttestedFAR = SFA!;
        this.maxTemplates = mT!;
        this.maxRetries = mR!;
        this.blockSlowdown = bls!;
    }
    public selfAttestedFRR: boolean;
    public selfAttestedFAR: boolean;
    public maxTemplates: number;
    public maxRetries: number;
    public blockSlowdown: number;
}