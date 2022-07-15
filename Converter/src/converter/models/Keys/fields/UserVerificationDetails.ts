import { VerificationMethodANDCombinationsV2, VerificationMethodANDCombinationsV3 } from "./VerificationMethodANDCombinations";

export class UserVerificationDetailsV3 {
    constructor(info: VerificationMethodANDCombinationsV3[]) {
        this.data = Array.from(info);
    }
    public data: VerificationMethodANDCombinationsV3[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}


export class UserVerificationDetailsV2 {
    constructor(info: VerificationMethodANDCombinationsV2[]) {
        this.data = Array.from(info);
    }
    public data: VerificationMethodANDCombinationsV2[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}