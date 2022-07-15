//import * as dotenv from 'dotenv';

import  * as MV2  from './converter/models/Keys/v2/MetadataV2';

import { metadataInitializer } from './converter/initializer';



    let metadata1 = metadataInitializer("./../resources/FIDOV3Keys.txt");
    let metadata2;
    let metadata3;
    
    if(metadata1 instanceof MV2.MetadataKeysV2){
        //metadata2 = metadataKeysV2.fromV2toV3(metadata1)
        //metadata3 = metadataKeysV3.fromV3toV2(metadata2)
    }
    else{
        //metadata2 = metadataKeysV3.fromV3toV2(metadata1)
        //metadata3 = metadataKeysV2.fromV2toV3(metadata2)
        console.log(metadata1.validateData("authenticatorGetInfo"))
    }
    
    
//    console.log(JSON.stringify(metadata1));
//    console.log(JSON.stringify(metadata2))
//    console.log(JSON.stringify(metadata3))

//    console.log(metadata1)
//    console.log(metadata2)
//    console.log(metadata3)
