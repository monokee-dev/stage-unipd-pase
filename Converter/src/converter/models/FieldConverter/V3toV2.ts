import * as V2V3Map from "./../Map/mapV2andV3"

//ATTENZIONE capire cosa farne dei valori non trovati nelle conversioni stringa -> numero

export class V3toV2 {
    
    public static convertAttestationTypes(attestationTypes:string[]): number[] | undefined{
        var temp: number[] = new Array();
        for(var obj of attestationTypes){
            temp.push(Number(V2V3Map.V2andV3.attestationTypesConverter(obj)));
        }
        return temp;
    }


    public static convertUserVerificationDetails(userVerification:string): number | undefined{
        return Number(V2V3Map.V2andV3.userVerificationDetailsConverter(userVerification));
    }


    public static convertKeyProtection(keyProtection: string[]): number | undefined{
        let keyV3: number=0;
        for(let i=0; i<keyProtection.length; i++){
            let temp = (Number(V2V3Map.V2andV3.keyProtectionConverter((keyProtection[i]))));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    }


    public static convertMatcherProtection(matcherProtection: string[]): number | undefined{
        let keyV3: number=0;
        for(let i=0; i<matcherProtection.length; i++){
            let temp = (Number(V2V3Map.V2andV3.matcherProtectionConverter((matcherProtection[i]))));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    }


    public static convertAttachmentHint(attachmentHint: string[]): number | undefined{
        let keyV3: number=0;
        for(let i=0; i<attachmentHint.length; i++){
            let temp = Number(V2V3Map.V2andV3.attachmentHintConverter((attachmentHint[i])));
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    }


    public static convertTcDisplay(tcDisplay: string[]): number | undefined{
        let keyV3: number=0;
        for(let i=0; i<tcDisplay.length; i++){
            let temp = (Number(V2V3Map.V2andV3.tcDisplayConverter((tcDisplay[i]))));   
            keyV3 = keyV3 + temp;
        }
        return keyV3;
    }

    //in v3 protocolfamily è obbligatorio quindi sicuramente c'è
    public static convertAssertionSchema(protocolFamily: string): string{
        if(protocolFamily == "u2f")
            return "U2FV1BIN"
        else if(protocolFamily == "fido2")
            return "FIDOV2"
        else//"uaf"
            return "UAFV1TLV";
    }

    // CAMPO NON OBBLIGATORIO
    public static convertCryptoStrength(cryptoStrength:number | undefined): number | undefined {
        if(cryptoStrength == undefined)
            return undefined;
        return cryptoStrength;
    }


    // CAMPO NON OBBLIGATORIO
    //per ora lascio settato a true
    public static convertIsSecondFactorOnly(uv: boolean | undefined): boolean{
        if(uv == undefined || uv == false)
            return true;
        else
            return false;
    }

    // CAMPO NON OBBLIGATORIO
    public static convertOperatingEnv(): undefined {
        return undefined;
    }


    public static convertauthenticationAlgorithm(authenticationAlgorithm:string): number | undefined{
        let temp = V2V3Map.V2andV3.authenticationAlgorithmsConverter(authenticationAlgorithm);
        if(temp)
            return Number(temp)
        return undefined;
    }

    public static convertpublicKeyAlgAndEncoding(publicKeyAlgAndEncoding:string): number | undefined{
        let temp = V2V3Map.V2andV3.publicKeyAlgAndEncodingsConverter(publicKeyAlgAndEncoding);
        if(temp)
            return Number(temp)
        return undefined;
    }
}