class ExtensionDescriptor {
    constructor(i: string, f: boolean, t?: number, d?: string) {
        this.id = i;
        this.tag = t!;
        this.data = d!;
        this.fail_if_unknown = f;
    }
    public id: string;
    public tag: number;
    public data: string;
    public fail_if_unknown: boolean;
}