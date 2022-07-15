class VerificationMethodDescriptor {
    constructor(uv: string, c?: CodeAccuracyDescriptor, b?: BiometricAccuracyDescriptor, p?: PatternAccuracyDescriptor) {
        this.userVerification = uv;
        this.caDesc = c!;
        this.baDesc = b!;
        this.paDesc = p!;
    }
    public userVerification: string;
    public caDesc: CodeAccuracyDescriptor | undefined;
    public baDesc: BiometricAccuracyDescriptor | undefined;
    public paDesc: PatternAccuracyDescriptor | undefined;

    public validateInternalData(): boolean {
        if (VerificationMethodDescriptorUserVerificationMethodEnum[this.userVerification as keyof typeof VerificationMethodDescriptorUserVerificationMethodEnum] == undefined)
            return false;
        else
            return true;
    }
}