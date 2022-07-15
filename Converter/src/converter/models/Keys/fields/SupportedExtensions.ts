import { ExtensionDescriptor } from "./ExtensionDescriptor";

export class SupportedExtensions {
    constructor(info: ExtensionDescriptor) {
        this.data = info;
    }
    public data: ExtensionDescriptor;

    public static fromJSON(json: { [id: string] : any; }): SupportedExtensions {
        return new SupportedExtensions(
            ExtensionDescriptor.fromJSON(json.data)
        )
    }

}