class UserVerificationDetails {
    constructor(info: VerificationMethodANDCombinations[]) {
        this.data = Array.from(info);
    }
    public data: VerificationMethodANDCombinations[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}