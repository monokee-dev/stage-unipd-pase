import { X509Certificate } from 'crypto'; // per controllare attestationRootCertificates

export class metadataKeysV2{

    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    constructor(description:string, authenticatorVersion:number, upv:Version[], assertionScheme:string, authenticationAlgorithm:number, 
        publicKeyAlgAndEncoding:number, attestationTypes:number[], userVerificationDetails: VerificationMethodANDCombinations[], isSecondFactorOnly:boolean,
        keyProtection: number, matcherProtection: number, cryptoStrength:number | undefined = undefined, attachmentHint: number, tcDisplay: number, 
        attestationRootCertificates:string[], legalHeader?:string, aaid?:string, aaguid?:string, attestationCertificateKeyIdentifiers?:string[],  
        alternativeDescriptions?:string, protocolFamily:string="uaf", authenticationAlgorithms?: number[],  publicKeyAlgAndEncodings?:number[],
        isKeyRestricted:boolean = true, isFreshUserVerificationRequired:boolean = true, operatingEnv?:string, 
        tcDisplayContentType?:string, tcDisplayPNGCharacteristics?:tcDisplayPNGCharacteristicsDescriptor, ecdaaTrustAnchors?:ecdaaTrustAnchor[], 
        icon?:string, supportedExtensions?: ExtensionDescriptor[]){

            this.legalHeader=legalHeader;
            this.aaid=aaid;
            this.aaguid=aaguid;
            if(attestationCertificateKeyIdentifiers != undefined){
                this.attestationCertificateKeyIdentifiers=Array.from(attestationCertificateKeyIdentifiers);
            }
            else{
                this.attestationCertificateKeyIdentifiers = undefined;
            }
            this.description=description;
            this.alternativeDescriptions=alternativeDescriptions;
            this.authenticatorVersion=authenticatorVersion;
            this.protocolFamily=protocolFamily;
            this.upv=Array.from(upv);
            this.assertionScheme=assertionScheme;
            this.authenticationAlgorithm=authenticationAlgorithm;
            //controllo che authenticationAlgorithms esista per assegnarlo a this.authenticationAlgorithms
            if(authenticationAlgorithms != undefined){
                this.authenticationAlgorithms=Array.from(authenticationAlgorithms);
            }
            else{
                this.authenticationAlgorithms = undefined;
            }
            this.publicKeyAlgAndEncoding=publicKeyAlgAndEncoding;
            //controllo che publicKeyAlgAndEncodings esista per assegnarlo a this.publicKeyAlgAndEncodings
            if(publicKeyAlgAndEncodings != undefined){
                this.publicKeyAlgAndEncodings=Array.from(publicKeyAlgAndEncodings);
            }
            else{
                this.publicKeyAlgAndEncodings = undefined;
            }
            this.attestationTypes=Array.from(attestationTypes);
            this.userVerificationDetails=userVerificationDetails;
            this.keyProtection=keyProtection;
            this.isKeyRestricted=isKeyRestricted;
            this.isFreshUserVerificationRequired=isFreshUserVerificationRequired;
            this.matcherProtection=matcherProtection;
            this.cryptoStrength=cryptoStrength;
            this.operatingEnv=operatingEnv;
            this.attachmentHint=attachmentHint;
            this.isSecondFactorOnly=isSecondFactorOnly;
            this.tcDisplay=tcDisplay;                         
            this.tcDisplayContentType=tcDisplayContentType;                            
            this.tcDisplayPNGCharacteristics=tcDisplayPNGCharacteristics;
            this.attestationRootCertificates=attestationRootCertificates;
            if(ecdaaTrustAnchors != undefined){
                this.ecdaaTrustAnchors=Array.from(ecdaaTrustAnchors);
            }
            else{
                this.ecdaaTrustAnchors = undefined;
            }
            this.icon=icon;
            //controllo che supportedExtensions esista per assegnarlo a this.supportedExtensions
            if(supportedExtensions != undefined){
                this.supportedExtensions=Array.from(supportedExtensions);
            }
            else{
                this.supportedExtensions = undefined;
            }  
    }

    //dichiarazione di tutte le variabili con relativo tipo    
    private legalHeader: string | undefined;
    private aaid: string | undefined; 
    private aaguid: string | undefined; 
    private attestationCertificateKeyIdentifiers: string[] | undefined; 
    private description: string;
    private alternativeDescriptions: string | undefined;
    private authenticatorVersion: number; 
    private protocolFamily: string;
    private upv: Version[];
    private assertionScheme: string;
    private authenticationAlgorithm: number;                 
    private authenticationAlgorithms: number[] | undefined; 
    private publicKeyAlgAndEncoding: number;
    private publicKeyAlgAndEncodings: number[] | undefined;
    private attestationTypes: number[];
    private userVerificationDetails: VerificationMethodANDCombinations[];
    private keyProtection: number;
    private isKeyRestricted: boolean;
    private isFreshUserVerificationRequired: boolean;
    private matcherProtection: number;
    private cryptoStrength: number | undefined;
    private operatingEnv: string | undefined;
    private attachmentHint: number;
    private isSecondFactorOnly: boolean;   
    private tcDisplay: number;
    private tcDisplayContentType: string | undefined;                               
    private tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor | undefined;
    private attestationRootCertificates: string[];
    private ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined;
    private icon: string | undefined;
    private supportedExtensions: ExtensionDescriptor[] | undefined;

    //funzione validazione singolo campo
    //public validateData(): boolean{
    //    return true;
    //}

    //funzione validazione per tutti i campi
    public validateAll(): boolean{
        if(this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() && this.authenticatorVersionCheck() &&
        this.protocolFamilyCheck() && this.upvCheck() && this.assertionSchemeCheck() && this.authenticationAlgorithmCheck() &&
        this.authenticationAlgorithmsCheck() && this.publicKeyAlgAndEncodingCheck() && 
        this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
        this.keyProtectionCheck() && this.matcherProtectionCheck() && this.cryptoStrengthCeck() && this.operatingEnvCheck() && 
        this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() && 
        this.tcDisplayPNGCharacteristicsCheck() && this.attestationRootCertificatesCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck() 
        // && this.supportedExtensionsCheck() basta che i campi dati siano conformi
        ){
            return true;
        }
        return false;        
    }
            
        //controllo upv
        /*
            jsonParsed[0]["minor"] == 1){
        */

    /**
     * Campo legalHeader non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */
    

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "uaf"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "fido2"
     *          3) che la stringa, se presente sia conforme a quanto riportato qui: https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef          
     */
    private aaidCheck(): boolean{
        if(this.protocolFamily == "uaf" && this.aaid == undefined)
            return false;
        if(this.aaid != undefined && (!RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid) || this.protocolFamily == "fido2"))
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     *          3) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example  
     */
    private aaguidCheck(): boolean{
        if(this.protocolFamily == "fido2" && this.aaguid == undefined)
            return false;
        if(this.protocolFamily == "uaf" && this.aaguid != undefined)
            return false;
        if(this.aaguid != undefined){
            if(this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                    return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) il campo deve essere presente se né aaid né aaguid sono presenti
     *          2) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    private attestationCertificateKeyIdentifiersCheck(): boolean{
        if(this.aaid == undefined && this.aaguid == undefined && this.attestationCertificateKeyIdentifiers == undefined)
            return false;

        if(this.attestationCertificateKeyIdentifiers != undefined){
            for(let i = 0; i < this.attestationCertificateKeyIdentifiers.length; i++) {
                if (!RegExp(/^[0-9a-f]+$/).test(this.attestationCertificateKeyIdentifiers[i]))
                    return false;
            }
        }
        return true;
    }

    /**
     * Campo description non controllato:
     *          1) perché è obbligatorio (controllato nel costruttore)
     *          2) perché è una stringa
     */

    /**
     * Campo alternativeDescriptions non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */

    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    private authenticatorVersionCheck(){
        if(this.authenticatorVersion < 0 || this.authenticatorVersion > 65535)
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) se si usa metadata statement per u2f deve esserci obbligatoriamente il campo "u2f", se si usa FIDO 2.0/WebAuthentication Authenticator il campo deve essere "fido2"
     */
    private protocolFamilyCheck(): boolean{
        if(this.protocolFamily != undefined && this.protocolFamily != "uaf" && this.protocolFamily != "u2f" && this.protocolFamily != "fido2")
            return false;
        if(this.protocolFamily != "fido2" && this.assertionScheme == "FIDOV2")
            return false;
        if(this.protocolFamily != "u2f" && this.assertionScheme == "U2FV1BIN")
            return false;
        if((this.protocolFamily != "uaf" && this.protocolFamily != undefined) && this.assertionScheme == "UAFV1TLV" ) 
            return false;
        return true;
    }

    /**
     * Controlli: 
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     */
     private upvCheck(){
        for(let i=0; i<this.upv.length;i++){
            if(this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo stringa sia presente in assertionSchemeEnum (quidi che sia un tra U2FV1BIN, FIDOV2 e UAFV1TLV)
     */
    private assertionSchemeCheck(): boolean{
        if(assertionSchemeEnum[this.assertionScheme as keyof typeof assertionSchemeEnum] == undefined)
                return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    private authenticationAlgorithmCheck(): boolean{
        if(this.authenticationAlgorithm < 1 || this.authenticationAlgorithm > 18)
            return false;
        if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    private authenticationAlgorithmsCheck(): boolean{
        if(this.authenticationAlgorithms != undefined){    
            for(let i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (this.authenticationAlgorithms[i] < 1 || this.authenticationAlgorithms[i] > 18)
                    return false;
                if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 256 e 260
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    private publicKeyAlgAndEncodingCheck(): boolean{
        if(this.publicKeyAlgAndEncoding < 256 || this.publicKeyAlgAndEncoding > 260)
            return false;
        if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 256 e 260
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    private publicKeyAlgAndEncodingsCheck(): boolean{
        if(this.publicKeyAlgAndEncodings != undefined){
            for(let i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (this.publicKeyAlgAndEncodings[i] < 256 || this.publicKeyAlgAndEncodings[i] > 260)
                    return false;
                if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 15879(0x3E07) e 15882(0x3E0A)
     */
    private attestationTypesCheck(): boolean{
        for(let i = 0; i < this.attestationTypes.length; i++) {
            if (this.attestationTypes[i] < 15879 || this.attestationTypes[i] > 15882)
                return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#idl-def-VerificationMethodDescriptor)
     */
    private userVerificationDetailsCheck(): boolean{
        for(let i = 0; i < this.userVerificationDetails.length; i++) {
            if (!this.userVerificationDetails[i].validateData())
                return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types)
     */
    private keyProtectionCheck(): boolean{
        if(this.keyProtection < 1 || this.keyProtection > 24) // 16 + 8 -> 24, massimo num raggiungibile (This flag MUST be set in conjunction with one of the other KEY_PROTECTION flags...)
            return false;
        if(this.keyProtection == (1 || 2 || 4 || 6 || 8 || 10 || 11 || 17 || 18 || 20 || 24))
            return true;
        else    
            return false;
    }

    /**
     * Campo isKeyRestricted non controllato:
     *          1) perché è opzionale (se non viene specificato è true)
     *          2) perché è un booleano
     */

    /**
     * Campo isFreshUserVerificationRequired non controllato:
     *          1) perché è opzionale (se non viene specificato è true)
     *          2) perché è un booleano
     */

    /**
     * Controlli:
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types)
     */    
    private matcherProtectionCheck(): boolean{
        if(this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     */   
    private cryptoStrengthCeck(): boolean{
        if(this.cryptoStrength != undefined){
            if(this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo stringa sia presente in operatingEnvEnum
     */
    private operatingEnvCheck(): boolean{
        if(this.operatingEnv != undefined){
            if(operatingEnvEnum[this.operatingEnv as keyof typeof operatingEnvEnum] == undefined)
                return false;
            }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    //idea alla base: dato il valore di this.attachmentHint tolgo il valore i, a partire da 256, fino a 1, 
    //per capire se sono stati utilizzati o meno i campi critici (internal->1 , external->2)
    private attachmentHintCheck(): boolean{
        let counter = 0;
        let i = 256;
        let tot = this.attachmentHint;
        if(tot == 1)//superfluo
            return true;
        while(i>0){
            if((i==1 && counter >= 1) || (i==2 && counter == 0))
                return false;
            if(tot >= i){
                tot = tot -i;
                counter+=1;
            }
            i=i/2;
        }
        return true;
    }

    /**
     * Campo isSecondFactorOnly non controllato:
     *          1) perché è un booleano obbligatorio
     */

    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti secondo: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#transaction-confirmation-display-types
     */
    private tcDisplayCheck(): boolean{
        if(this.tcDisplay == (6 || 10 || 12)){
            return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo sia anche tcDisplay (non 0)
     *          2) che il campo presenti un valore tra quelli presentu in tcDisplayContentTypeEnum
     */
    private tcDisplayContentTypeCheck(): boolean{
        if(this.tcDisplay != 0 && this.tcDisplayContentType == undefined)
            return false;

        if(this.tcDisplayContentType != undefined){
            if(tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == undefined)
                return false;
        }
        return true;
    }   

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non 0) e tcDisplayContentType (deve essere image/png)
     */
    private tcDisplayPNGCharacteristicsCheck(): boolean{ //(seconda parte: se variabile tcDisplayContentType è image/png)
        if(this.tcDisplay != 0 && tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == tcDisplayContentTypeEnum["image/png" as keyof typeof tcDisplayContentTypeEnum] && this.tcDisplayPNGCharacteristics == undefined)
            return false;
        return true;
    }

    /**
     * Controlli: 
     *          1) 
     * 
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case. 
     */
    private attestationRootCertificatesCheck(): boolean{
        for(let i=0;i<this.attestationRootCertificates.length;i++){
            const x509 = new X509Certificate(this.attestationRootCertificates[i])
            if(!x509.ca)
                return false;  
        }
        
        return true;
    }

    /**
     * Controlli:
     *          1) Se e solo se AttestationTypes include ATTESTATION_ECDAA (15881) ecdaaTrustAnchors deve essere presente
     *          2) Validazione campo G1Curve di  EcdaaTrustAnchor 
     */
    private ecdaaTrustAnchorsCheck(): boolean{
        let temp: number | undefined = this.attestationTypes.find(element => element == 15881);
        if((temp != undefined && this.ecdaaTrustAnchors == undefined) || (temp == undefined && this.ecdaaTrustAnchors != undefined))
            return false;
        if(this.ecdaaTrustAnchors != undefined){
            for(let i=0;i<this.ecdaaTrustAnchors.length;i++){
                if(!this.ecdaaTrustAnchors[i].validateData())
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli: 
     *          1) formato con cui sono inserite le immagini tramite regular expression
     */
    private iconCheck(): boolean{
        if(this.icon != undefined){
            let temp:string=this.icon;
            if(this.icon.indexOf("data:") != -1){
                temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64")+7), "");
            }
            if(!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)){
                return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Basta che i campi dati siano compatibili con ExstensionDescriptor
     */
        /*private supportedExtensionsCheck(): boolean{
            return true;
        }
    */
}

class Version{
    constructor(ma:number, mi:number){
        this.major=ma;
        this.minor=mi;
    }
    readonly major: number;
    readonly minor: number;
}


enum tcDisplayContentTypeEnum{
    "application/octet-stream",
    "application/postscript",
    "message/external-body",
    "message/rfc822",
    "audio/basic",
    "image/jpeg",
    "image/gif",
    "image/png",
    "text/enriched",
    "text/plain",
    "text/foo",
}

enum operatingEnvEnum{
    "TEEs based on ARM TrustZone HW",
    "TEE Based on Intel VT HW", 
    "TEE Based on Intel SGX HW",
    "TEE Based on Intel ME/TXE HW",
    "TEE with GlobalPlatform TEE Protection Profile Certification",
    "Windows 10 Virtualization-based Security",
    "Secure World of AMD PSP (Platform Security coProcessor)",
    "Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications",
    "Secure Element (SE)",
}

enum assertionSchemeEnum{
    "U2FV1BIN",
    "FIDOV2",
    "UAFV1TLV",
}

class CodeAccuracyDescriptor{
    constructor(ba:number, mL: number, mR?: number, bl?: number){
        this.base=ba;
        this.minLength=mL;
        this.maxRetries=mR!;
        this.blockSlowdown=bl!;
    }
    public base: number;
    public minLength: number;
    public maxRetries: number;
    public blockSlowdown: number;
}

class BiometricAccuracyDescriptor{
    constructor(SFR?:boolean, SFA?: boolean, mT?: number, mR?: number, bls?:number){
        this.selfAttestedFRR=SFR!;
        this.selfAttestedFAR=SFA!;
        this.maxTemplates=mT!;
        this.maxRetries=mR!;
        this.blockSlowdown=bls!;
    }
    public selfAttestedFRR: boolean;
    public selfAttestedFAR: boolean;
    public maxTemplates: number;
    public maxRetries: number;
    public blockSlowdown:number;
}

class PatternAccuracyDescriptor{
    constructor(ba:number, mL?: number, bl?: number){
        this.minComplexity=ba;
        this.maxRetries=mL!;
        this.blockSlowdown=bl!;

    }
    public minComplexity: number;
    public maxRetries: number;
    public blockSlowdown: number;
}

class VerificationMethodDescriptor{
    constructor(uv: number = 0, c?:CodeAccuracyDescriptor, b?:BiometricAccuracyDescriptor, p?:PatternAccuracyDescriptor){
        this.userVerification=uv;
        this.caDesc=c!;
        this.baDesc=b!;
        this.paDesc=p!;
    }
    public userVerification: number;
    public caDesc: CodeAccuracyDescriptor;
    public baDesc: BiometricAccuracyDescriptor;
    public paDesc: PatternAccuracyDescriptor;

    public validateData(): boolean{
        if(this.userVerification == 0 || this.userVerification != 1024||512||256||128||64||32||16||8||4||2||1)
            return false;
        else
            return true;
    }
}

class VerificationMethodANDCombinations{
    constructor(d:VerificationMethodDescriptor[]){
        this.data=Array.from(d);
    }
    public data: VerificationMethodDescriptor[];
    public validateData(): boolean{
        for(let i = 0; i < this.data.length; i++){
            if(!this.data[i].validateData())
                return false;
        }
        return true;
    }
}

export class userVerificationDetails {
    constructor(info: VerificationMethodANDCombinations[]){
        this.data=Array.from(info);
    }
    public data: VerificationMethodANDCombinations[];
    public validateData(): boolean{
        for(let i = 0; i < this.data.length; i++){
            if(!this.data[i].validateData())
                return false;
        }
        return true;
    }
}

class ExtensionDescriptor{
    constructor(i:string, f:boolean, t?:number, d?:string){
        this.id=i;
        this.tag=t!;
        this.data=d!;
        this.fail_if_unknown=f;
    }
    public id: string;
    public tag: number;
    public data: string;
    public fail_if_unknown: boolean;
}

export class supportedExtensions {
    constructor(info: ExtensionDescriptor){
        this.data=info;
    }
    public data: ExtensionDescriptor;
}

class  rgbPaletteEntry{

    constructor(r1: number=0, g1: number=0, b1: number=0){
        this.r=r1;
        this.g=g1;
        this.b=b1;
    }
    public r: number;
    public g: number;
    public b: number;

    public validateData(): boolean{
        if(this.r < 0 || this.r > 255 || this.g < 0 || this.g > 255 || this.b < 0 || this.b > 255){
            return false;
        }
        else{
            return true;
        }
    }
}

export class tcDisplayPNGCharacteristicsDescriptor {

    constructor(w: number=0 , h: number=0, b: number=0, c: number=0, f: number=0, i: number=0, p?: rgbPaletteEntry[]){
        this.width=w;
        this.height=h;
        this.bitDepth=b;
        this.compression=c;
        this.filter=f;
        this.interlace=i;
        this.plte=p;
    }
    public width: number;
    public height: number;
    public bitDepth: number;
    public compression: number;
    public filter: number;
    public interlace: number;
    public plte:  rgbPaletteEntry[] | undefined;
}

export class attestationRootCertificates {
    constructor(info:string[]){
        this.data=Array.from(info);
    }
    public data: string[];
}

//This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA.
export class ecdaaTrustAnchor {
    constructor(x: string, y: string, c: string, s1: string, s2: string, g: string){
        this.X=x;
        this.Y=y;
        this.c=c;
        this.sx=s1;
        this.sy=s2;
        this.G1Curve=g;
    }

    public X: string;
    public Y: string;
    public c: string;
    public sx: string;
    public sy: string;
    public G1Curve: string;

    public validateData(): boolean{
        if(G1CurveEnum[this.G1Curve as keyof typeof G1CurveEnum] == undefined)
            return false;

        return true;
    }
}

//nome completo curve sarebbe "TPM_ECC_BN_...." e "ECC_BN_...."
enum G1CurveEnum{
    "BN_P256",
    "BN_P638",
    "BN_ISOP256",
    "BN_ISOP512",
}






