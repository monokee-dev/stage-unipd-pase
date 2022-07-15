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

    public static fromJSON(json: { [id: string] : any; }): UserVerificationDetailsV3 {

        let temp = Array();
        for(let i=0; i<json.userVerificationDetails.length; i++)
            temp.push(VerificationMethodANDCombinationsV3.fromJSON(json.plte));

        return new UserVerificationDetailsV3(
            temp
        )
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

    public static fromJSON(json: { [id: string] : any; }): UserVerificationDetailsV2 {
        let temp = Array();
        for(let i=0; i<json.userVerificationDetails.length; i++)
            temp.push(VerificationMethodANDCombinationsV2.fromJSON(json.plte));

        return new UserVerificationDetailsV2(
            temp
        )
    }
}