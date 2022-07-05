import * as KeysV2 from "./Keys/metadataV2"
import * as KeysV3 from "./Keys/metadataV3"
import * as V2toV3 from "./Map/mapV2andV3"
import * as fs from 'node:fs';
import { getFunctionName } from "inversify/lib/utils/serialization";

//PRIMA di convertire i metadata eseguire il controllo di validità (validateAll())
/*
export function MetadataConverterV2toV3(mv2: KeysV2.metadataKeysV2){
    if(!mv2.validateAll())
        throw "Errore: il metadata inserito non rispetta le condizioni per i campi";
    else{
        //return new KeysV3.metadataKeysV3();
    }
}
*/

//funzioni SOLO conversione: il cotrollo dovrà essere fatto in seguito

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

//funzione per ottenere tutti i campi keyprotection
function convertKeyProtectionV2toV3(keyProtection: number): string[] | undefined{
    let keyV3: string[] = new Array();
    let temp:number = keyProtection;
    /**
     * IDEA:
     *  -numero massimo valori: 16 = 2^4
     *  -uso variabile(exp) inizialmente con valore 4 che diminuisce ad ogni iterazione
     *  -se KeyProtection è minore di 2^exp eseguo sottrazione e chiamo funzione attestationTypesConverter
     *          perché sono sicuro che il valore sia presente
     *  -altrimenti decremento semplicemente exp
     */
    for(let exp = 4; exp >= 0; exp--){
        if((2**exp) <= temp){
            temp = temp - (2**exp);
            keyV3.push(String(V2toV3.keyProtectionConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    else
        return keyV3;
}

//funzione per ottenere tutti i campi matcherProtection
function convertMatcherProtectionV2toV3(matcherProtection: number): string[] | undefined{
    let keyV3: string[] = new Array();
    
    keyV3.push(String(V2toV3.matcherProtectionConverter((matcherProtection))))
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    return keyV3;
}

//funzione per ottenere tutti i campi attachmentHint
function convertAttachmentHintV2toV3(attachmentHint: number): string[] | undefined{
    let keyV3: string[] = new Array();
    let temp:number = attachmentHint;

    for(let exp = 8; exp >= 0; exp--){
        if((2**exp) <= temp){
            temp = temp - (2**exp);
            keyV3.push(String(V2toV3.attachmentHintConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    else
        return keyV3;
}

//funzione per ottenere tutti i campi attachmentHint
function convertTcDisplayV2toV3(tcDisplay: number): string[] | undefined{
    let keyV3: string[] = new Array();
    let temp:number = tcDisplay;
 
    for(let exp = 4; exp >= 0; exp--){
        if((2**exp) <= temp){
            temp = temp - (2**exp);
            keyV3.push(String(V2toV3.tcDisplayConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 )
        return undefined;
    else
        return keyV3;
}

//funzione per ottenere il campo schema
//essendo conversione da MV2 a MV3 il campo schema sarà sempre di valore 3
function convertSchemaV2toV3(): number{
    return 3;
}

//funzione per ottenere il campo AuthenticatorGetInfo
function convertAuthenticatorGetInfoV2toV3(aaguid:string, assertionScheme:string): KeysV3.AuthenticatorGetInfo | undefined{
    let version: string[] = new Array();
    let aa: string = aaguid.replace("-","");
    if(assertionScheme=="FIDOV2"){
        version.push("FIDO_2_0");
    }
    if(assertionScheme=="U2FV1BIN"){
        version.push("U2F_V2")
    }
    if(version.length == 0){
        return undefined;
    }
    return new KeysV3.AuthenticatorGetInfo(version, aa);
}

console.log(convertTcDisplayV2toV3(17))
