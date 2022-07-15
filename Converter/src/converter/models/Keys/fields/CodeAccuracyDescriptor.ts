class CodeAccuracyDescriptor {
    constructor(ba: number, mL: number, mR?: number, bl?: number) {
        this.base = ba;
        this.minLength = mL;
        this.maxRetries = mR!;
        this.blockSlowdown = bl!;
    }
    public base: number;
    public minLength: number;
    public maxRetries: number;
    public blockSlowdown: number;
}