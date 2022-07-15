class PatternAccuracyDescriptor {
    constructor(ba: number, mL?: number, bl?: number) {
        this.minComplexity = ba;
        this.maxRetries = mL!;
        this.blockSlowdown = bl!;

    }
    public minComplexity: number;
    public maxRetries: number;
    public blockSlowdown: number;
}