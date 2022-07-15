import * as KeysV3 from "./../Keys/metadataV3"
import * as V2V3Map from "./../Map/mapV2andV3"

//ATTENZIONE capire cosa farne dei valori non trovati nelle conversioni stringa -> numero

export function convertAttestationTypesV3toV2(attestationTypes:string[]): number[] | undefined{
    var temp: number[] = new Array();
    for(var obj of attestationTypes){
        temp.push(Number(V2V3Map.attestationTypesConverter(obj)));
    }
    return temp;
}


export function convertUserVerificationDetailsV3toV2(userVerification:string): number | undefined{
    return Number(V2V3Map.userVerificationDetailsConverter(userVerification));
}


export function convertKeyProtectionV3toV2(keyProtection: string[]): number | undefined{
    let keyV3: number=0;
    for(let i=0; i<keyProtection.length; i++){
        let temp = (Number(V2V3Map.keyProtectionConverter((keyProtection[i]))));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}


export function convertMatcherProtectionV3toV2(matcherProtection: string[]): number | undefined{
    let keyV3: number=0;
    for(let i=0; i<matcherProtection.length; i++){
        let temp = (Number(V2V3Map.matcherProtectionConverter((matcherProtection[i]))));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}


export function convertAttachmentHintV3toV2(attachmentHint: string[]): number | undefined{
    let keyV3: number=0;
    for(let i=0; i<attachmentHint.length; i++){
        let temp = Number(V2V3Map.attachmentHintConverter((attachmentHint[i])));
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}


export function convertTcDisplayV3toV2(tcDisplay: string[]): number | undefined{
    let keyV3: number=0;
    for(let i=0; i<tcDisplay.length; i++){
        let temp = (Number(V2V3Map.tcDisplayConverter((tcDisplay[i]))));   
        keyV3 = keyV3 + temp;
    }
    return keyV3;
}

//in v3 protocolfamily è obbligatorio quindi sicuramente c'è
export function convertAssertionSchemaV3toV2(protocolFamily: string): string{
    if(protocolFamily == "u2f")
        return "U2FV1BIN"
    else if(protocolFamily == "fido2")
        return "FIDOV2"
    else//"uaf"
        return "UAFV1TLV";
}

// CAMPO NON OBBLIGATORIO
export function convertCryptoStrength3toV2(cryptoStrength:number | undefined): number | undefined {
    if(cryptoStrength == undefined)
        return undefined;
    return cryptoStrength;
}


// CAMPO NON OBBLIGATORIO
//per ora lascio settato a true
export function convertIsSecondFactorOnly3toV2(uv: boolean | undefined): boolean{
    if(uv == undefined || uv == false)
        return true;
    else
        return false;
}

// CAMPO NON OBBLIGATORIO
export function convertOperatingEnv3toV2(): undefined {
    return undefined;
}


export function convertauthenticationAlgorithmV3toV2(authenticationAlgorithm:string): number | undefined{
    let temp = V2V3Map.authenticationAlgorithmsConverter(authenticationAlgorithm);
    if(temp)
        return Number(temp)
    return undefined;
}

export function convertpublicKeyAlgAndEncodingV3toV2(publicKeyAlgAndEncoding:string): number | undefined{
    let temp = V2V3Map.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
    if(temp)
        return Number(temp)
    return undefined;
}
