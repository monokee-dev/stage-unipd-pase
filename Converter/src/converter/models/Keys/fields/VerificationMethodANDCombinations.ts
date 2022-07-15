class VerificationMethodANDCombinations {
    constructor(d: VerificationMethodDescriptor[]) {
        this.data = Array.from(d);
    }
    public data: VerificationMethodDescriptor[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}