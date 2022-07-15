export class Version {
    constructor(ma: number, mi: number) {
        this.major = ma;
        this.minor = mi;
    }
    readonly major: number;
    readonly minor: number;
}