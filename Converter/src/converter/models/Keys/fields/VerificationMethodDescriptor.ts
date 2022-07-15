import { BiometricAccuracyDescriptor } from "./BiometricAccuracyDescriptor";
import { CodeAccuracyDescriptor } from "./CodeAccuracyDescriptor";
import { VerificationMethodDescriptorUserVerificationMethodEnum } from "./enums";
import { PatternAccuracyDescriptor } from "./PatternAccuracyDescriptor";

export class VerificationMethodDescriptorV3 {
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

export class VerificationMethodDescriptorV2{
    constructor(uv: number = 0, c?:CodeAccuracyDescriptor, b?:BiometricAccuracyDescriptor, p?:PatternAccuracyDescriptor){
        this.userVerification=uv;
        this.caDesc=c!;
        this.baDesc=b!;
        this.paDesc=p!;
    }
    public userVerification: number;
    public caDesc: CodeAccuracyDescriptor | undefined;
    public baDesc: BiometricAccuracyDescriptor | undefined;
    public paDesc: PatternAccuracyDescriptor | undefined;

    public validateInternalData(): boolean{
        if(this.userVerification == 0 || this.userVerification != 1024||512||256||128||64||32||16||8||4||2||1)
            return false;
        else
            return true;
    }
}