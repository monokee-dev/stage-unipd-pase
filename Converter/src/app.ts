import * as dotenv from 'dotenv'

import  * as MV2  from './converter/models/Keys/metadataV2';
import  * as MV3  from './converter/models/Keys/metadataV3';

import { metadataInitializer } from './converter/converter'
import { metadataKeysV2 } from './converter/models/Keys/metadataV2';
import { metadataKeysV3 } from './converter/models/Keys/metadataV3';




    let metadata1 = metadataInitializer("./FIDOV3Keys.txt");
    //let metadata2;
    /*
    if(metadata1 instanceof metadataKeysV2)
        metadata2 = metadataKeysV2.fromV2toV3(metadata1);
    else
        metadata2 = metadataKeysV3.fromV3toV2(metadata1);
    
    let metadataStringify = JSON.stringify(metadata1);
    let metadataReParse = JSON.parse(metadataStringify);
    console.log(metadataReParse)
    */

    console.log(metadata1.validateAll())