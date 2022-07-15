import { G1CurveEnum } from "./enums";

//This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
export class ECDAATrustAnchor {
    constructor(x: string, y: string, c: string, s1: string, s2: string, g: string) {
        this.X = x;
        this.Y = y;
        this.c = c;
        this.sx = s1;
        this.sy = s2;
        this.G1Curve = g;
    }

    public X: string;
    public Y: string;
    public c: string;
    public sx: string;
    public sy: string;
    public G1Curve: string;

    public validateInternalData(): boolean {
        if (G1CurveEnum[this.G1Curve as keyof typeof G1CurveEnum] == undefined)
            return false;

        return true;
    }
}