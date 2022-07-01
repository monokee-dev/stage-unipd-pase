import * as KeysV2 from "./Keys/metadataV2"
import * as KeysV3 from "./Keys/metadataV3"
import * as V2toV3 from "./Map/mapV2andV3"
import * as fs from 'node:fs';

/*
export function MetadataConverterV2toV3(mv2: KeysV2.metadataKeysV2){
    if(!mv2.validateAll())
        throw "Errore: il metadata inserito non rispetta le condizioni per i campi";
    else{
        //return new KeysV3.metadataKeysV3();
    }
}
*/

function convertAttestationTypesV2toV3(attestationTypes:number[]):string[] | undefined{
    var temp: string[] = new Array();
    for(var obj of attestationTypes){
        temp.push(String(V2toV3.attestationTypesConverter(obj)));
    }
    return temp;
}

// funzione singola, da iterare per fare la conversione completa
function convertUserVerificationDetailsV2toV3(userVerification:number): string | undefined{
    return String(V2toV3.userVerificationDetailsConverter(userVerification));
}

//todo
function convertKeyProtectionV2toV3(keyProtection: number): string[] | undefined{
    return undefined;
}

//todo
function convertMatcherProtectionV2toV3(matcherProtection: number): string[] | undefined{
    return undefined;
}

//todo
function convertAttachmentHintV2toV3(attachmentHint: number): string[] | undefined{
    return undefined;
}

//todo
function convertTcDisplayV2toV3(tcDisplay: number): string[] | undefined{
    return undefined;
}

//todo
function convertSchemaV2toV3(){}

//todo
function convertAuthenticatorGetInfoV2toV3(){}
