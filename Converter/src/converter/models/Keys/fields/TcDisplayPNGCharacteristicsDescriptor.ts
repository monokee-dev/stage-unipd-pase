class TcDisplayPNGCharacteristicsDescriptor {

    constructor(w: number = 0, h: number = 0, b: number = 0, c: number = 0, f: number = 0, i: number = 0, p?: RGBPaletteEntry[]) {
        this.width = w;
        this.height = h;
        this.bitDepth = b;
        this.compression = c;
        this.filter = f;
        this.interlace = i;
        this.plte = p;
    }
    public width: number;
    public height: number;
    public bitDepth: number;
    public compression: number;
    public filter: number;
    public interlace: number;
    public plte: RGBPaletteEntry[] | undefined;
}