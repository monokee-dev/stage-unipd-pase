import * as KeysV3 from "./../Keys/metadataV3"
import * as V2V3Map from "./../Map/mapV2andV3"

//funzioni SOLO conversione: il cotrollo dovrà essere fatto in seguito
export class V2toV3 {
    public static convertAttestationTypes(attestationTypes:number[]):string[] | undefined{
        var temp: string[] = new Array();
        for(var obj of attestationTypes){
            temp.push(String(V2V3Map.attestationTypesConverter(obj)));
        }
        return temp;
    }
    
}

// funzione singola, da iterare per fare la conversione completa
export function convertUserVerificationDetailsV2toV3(userVerification:number): string | undefined{
    return String(V2V3Map.userVerificationDetailsConverter(userVerification));
}

//funzione per ottenere tutti i campi keyprotection
export function convertKeyProtectionV2toV3(keyProtection: number): string[] | undefined{
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
            keyV3.push(String(V2V3Map.keyProtectionConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    else
        return keyV3;
}

//funzione per ottenere tutti i campi matcherProtection
//non è stato fatto alcun ciclo in quanto essendo i campi mutuamente esclusivi nonostante il contenitore sia un array
export function convertMatcherProtectionV2toV3(matcherProtection: number): string[] | undefined{
    let keyV3: string[] = new Array();
    
    keyV3.push(String(V2V3Map.matcherProtectionConverter((matcherProtection))))
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    return keyV3;
}

//funzione per ottenere tutti i campi attachmentHint
export function convertAttachmentHintV2toV3(attachmentHint: number): string[] | undefined{
    let keyV3: string[] = new Array();
    let temp:number = attachmentHint;

    for(let exp = 8; exp >= 0; exp--){
        if((2**exp) <= temp){
            temp = temp - (2**exp);
            keyV3.push(String(V2V3Map.attachmentHintConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 ){
        return undefined;
    }
    else
        return keyV3;
}

//funzione per ottenere tutti i campi attachmentHint
export function convertTcDisplayV2toV3(tcDisplay: number): string[] | undefined{
    let keyV3: string[] = new Array();
    let temp:number = tcDisplay;
 
    for(let exp = 4; exp >= 0; exp--){
        if((2**exp) <= temp){
            temp = temp - (2**exp);
            keyV3.push(String(V2V3Map.tcDisplayConverter((2**exp))));
        }
    }
    if(keyV3.findIndex(element => element == undefined) != -1 )
        return undefined;
    else
        return keyV3;
}

//funzione per ottenere il campo schema
//essendo conversione da MV2 a MV3 il campo schema sarà sempre di valore 3
export function convertSchemaV2toV3(): number{
    return 3;
}

//funzione per ottenere il campo AuthenticatorGetInfo
/**
 * ATTENZIONE:
 *      - il campo version avrebbe più valori possibili (es FIDO_2_1,..) in base alla versione CTAP
 *        (maggiorni informazioni qui: https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo) 
 * 
 *      - U2F_V2 non è mai da solo nel campo version, solitamente è posto insieme a FIDO_2_0
 */
export function convertAuthenticatorGetInfoV2toV3(aaguid:string, assertionScheme:string, isSecondFactorOnly: boolean | undefined, firmwareVersion: number | undefined): KeysV3.AuthenticatorGetInfo | undefined{
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

    if(isSecondFactorOnly == undefined || isSecondFactorOnly == false)
        return new KeysV3.AuthenticatorGetInfo(version, aa,undefined,new KeysV3.authenticatorOption(undefined,undefined,undefined,undefined,true));
    else
        return new KeysV3.AuthenticatorGetInfo(version, aa,undefined,new KeysV3.authenticatorOption(undefined,undefined,undefined,undefined,false),undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined,firmwareVersion);  
}

// funzione singola per conversione dei codici degli algoritmi
export function convertauthenticationAlgorithmV2toV3(authenticationAlgorithm:number): string | undefined{
    let temp = V2V3Map.authenticationAlgorithmsConverter(authenticationAlgorithm)
    if(temp)
        return String(temp)
    return undefined;
}

// funzione singola per conversione dei codici delle chiavicodifica
export function convertpublicKeyAlgAndEncodingV2toV3(publicKeyAlgAndEncoding:number): string | undefined{
    let temp = V2V3Map.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding)
    if(temp)
        return String(temp)
    return undefined;
}
