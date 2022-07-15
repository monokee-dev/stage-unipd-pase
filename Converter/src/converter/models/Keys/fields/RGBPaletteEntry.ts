export class RGBPaletteEntry {

    constructor(r1: number = 0, g1: number = 0, b1: number = 0) {
        this.r = r1;
        this.g = g1;
        this.b = b1;
    }
    public r: number;
    public g: number;
    public b: number;

    public validateInternalData(): boolean {
        if (this.r < 0 || this.r > 255 || this.g < 0 || this.g > 255 || this.b < 0 || this.b > 255) {
            return false;
        }
        else {
            return true;
        }
    }
}