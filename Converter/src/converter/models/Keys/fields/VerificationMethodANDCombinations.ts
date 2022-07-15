import { VerificationMethodDescriptorV2, VerificationMethodDescriptorV3 } from "./VerificationMethodDescriptor";

export class VerificationMethodANDCombinationsV3 {
    constructor(d: VerificationMethodDescriptorV3[]) {
        this.data = Array.from(d);
    }
    public data: VerificationMethodDescriptorV3[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}

export class VerificationMethodANDCombinationsV2 {
    constructor(d: VerificationMethodDescriptorV2[]) {
        this.data = Array.from(d);
    }
    public data: VerificationMethodDescriptorV2[];
    public validateInternalData(): boolean {
        for (let i = 0; i < this.data.length; i++) {
            if (!this.data[i].validateInternalData())
                return false;
        }
        return true;
    }
}