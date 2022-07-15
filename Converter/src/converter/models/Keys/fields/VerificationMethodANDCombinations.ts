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

    public static fromJSON(json: { [id: string] : any; }): VerificationMethodANDCombinationsV3 {
        let temp = Array();
        for(let i=0; i<json.VerificationMethodANDCombinationsV3.length; i++)
            temp.push(VerificationMethodANDCombinationsV3.fromJSON(json.plte));

        return new VerificationMethodANDCombinationsV3(
            temp
        )
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

    public static fromJSON(json: { [id: string] : any; }): VerificationMethodANDCombinationsV2 {
        let temp = Array();
        for(let i=0; i<json.VerificationMethodANDCombinationsV2.length; i++)
            temp.push(VerificationMethodANDCombinationsV2.fromJSON(json.plte));

        return new VerificationMethodANDCombinationsV2(
            temp
        )
    }
}