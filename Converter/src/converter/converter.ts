import { MetadataV2 } from "./models/metadatav2";
import { MetadataV3 } from "./models/metadatav3";

enum keys {
    T,
    A,
    B
}

export class Converter {
    constructor() {
    }

    static convert(metadata: MetadataV2): MetadataV3 {
        let result = new MetadataV3()
        result.id = metadata.id
        return result
    }
}