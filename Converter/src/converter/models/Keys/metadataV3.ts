import { X509Certificate } from 'crypto'; // per controllare attestationRootCertificates

export class metadataKeysV3{

    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    constructor(description:string, authenticatorVersion:number, upv:Version[], authenticationAlgorithm:number, schema:number,
        publicKeyAlgAndEncoding:number, attestationTypes:string[], attestationCertificateKeyIdentifiers:string[],
        userVerificationDetails: VerificationMethodANDCombinations[], isSecondFactorOnly:boolean, authenticationAlgorithms: string[],  publicKeyAlgAndEncodings:string[],
        keyProtection: string[], matcherProtection: string[], cryptoStrength:number | undefined = undefined, attachmentHint: string[], tcDisplay: string[] | null, 
        attestationRootCertificates:string[], legalHeader:string, aaid?:string, aaguid?:string, alternativeDescriptions?:string, 
        protocolFamily:string="uaf", isKeyRestricted:boolean = true, isFreshUserVerificationRequired:boolean = true, operatingEnv?:string, 
        tcDisplayContentType?:string, tcDisplayPNGCharacteristics?:tcDisplayPNGCharacteristicsDescriptor, ecdaaTrustAnchors?:ecdaaTrustAnchor[], 
        icon?:string, supportedExtensions?: ExtensionDescriptor[]){

            this.legalHeader=legalHeader;
            this.aaid=aaid;
            this.aaguid=aaguid;
            this.attestationCertificateKeyIdentifiers=attestationCertificateKeyIdentifiers;
            this.description=description;
            this.alternativeDescriptions=alternativeDescriptions;
            this.authenticatorVersion=authenticatorVersion;
            this.protocolFamily=protocolFamily;
            this.schema=schema;
            this.upv=Array.from(upv);
            this.authenticationAlgorithms=Array.from(authenticationAlgorithms);
            this.publicKeyAlgAndEncodings=Array.from(publicKeyAlgAndEncodings); 
            this.attestationTypes=Array.from(attestationTypes);
            this.userVerificationDetails=userVerificationDetails;
            this.keyProtection=Array.from(keyProtection);
            this.isKeyRestricted=isKeyRestricted;
            this.isFreshUserVerificationRequired=isFreshUserVerificationRequired;
            this.matcherProtection=Array.from(matcherProtection);
            this.cryptoStrength=cryptoStrength;
            this.attachmentHint=attachmentHint;
            if(tcDisplay != null){
                this.tcDisplay=Array.from(tcDisplay);
            }
            else{
                this.tcDisplay = null;
             }                        
            this.tcDisplayContentType=tcDisplayContentType;                            
            this.tcDisplayPNGCharacteristics=tcDisplayPNGCharacteristics;
            this.attestationRootCertificates=attestationRootCertificates;
            this.ecdaaTrustAnchors=Array.from(ecdaaTrustAnchors!);
            this.icon=icon;
            //controllo che supportedExtensions esista per assegnarlo a this.supportedExtensions
            if(supportedExtensions != undefined){
                this.supportedExtensions=Array.from(supportedExtensions);
            }
            
    }

    //dichiarazione di tutte le variabili con relativo tipo    
    private legalHeader: string;
    private aaid: string | undefined; 
    private aaguid: string | undefined; 
    private attestationCertificateKeyIdentifiers: string[]; 
    private description: string;
    private alternativeDescriptions: string | undefined;
    private authenticatorVersion: number; 
    private protocolFamily: string;
    private schema: number;
    private upv: Version[];              
    private authenticationAlgorithms: string[];
    private publicKeyAlgAndEncodings: string[];
    private attestationTypes: string[];
    private userVerificationDetails: VerificationMethodANDCombinations[];
    private keyProtection: string[];
    private isKeyRestricted: boolean;
    private isFreshUserVerificationRequired: boolean;
    private matcherProtection: string[];
    private cryptoStrength: number | undefined;
    private attachmentHint: string[];
    private tcDisplay: string[] | null; // null corrisponde a 0, ciò significa che transaction confirmation non è supportata dall'autenticatore
    private tcDisplayContentType: string | undefined;                               
    private tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor | undefined;
    private attestationRootCertificates: string[];
    private ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined;
    private icon: string | undefined;
    private supportedExtensions: ExtensionDescriptor[] | undefined;
    private authenticatorGetInfo: AuthenticatorGetInfo | undefined;

    //funzione validazione singolo campo
    //public validateData(): boolean{
    //    return true;
    //}

    //funzione validazione per tutti i campi
    public validateAll(): boolean{
        if(this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() && this.authenticatorVersionCheck() &&
        this.protocolFamilyCheck() && this.schemaCheck() && this.upvCheck() &&
        this.authenticationAlgorithmsCheck() && 
        this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
        this.keyProtectionCheck() && this.matcherProtectionCheck() && this.cryptoStrengthCeck() && 
        this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() && 
        this.tcDisplayPNGCharacteristicsCheck() && this.attestationRootCertificatesCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck() 
        //&& this.supportedExtensionsCheck()
        && this.authenticatorGetInfoCheck()
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
     *          1) è obbligatorio ci sia (controllo nel costruttore)
     *          2) perché è una stringa
     */

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "uaf"
     *          2) che la stringa, se presente sia conforme a quanto riportato qui: https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef
     */
    private aaidCheck(): boolean{
        if(this.protocolFamily == "uaf" && this.aaid == undefined)
            return false;
        if(this.aaid != undefined && !RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid))
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
        if(this.aaguid != undefined){
            if(this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                    return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    private attestationCertificateKeyIdentifiersCheck(): boolean{
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
     *          1) perché è opzionale
     *          2) perché è una stringa
     */

    /**
     * Campo alternativeDescriptions non controllato:
     *          1) perché è opzionale
     *          2) perché è una stringa
     */

    /**
     * Conrtolli:
     *          1) essendo il campo unsigned long:  0 <= authenticatorVersion <= 4294967295
     */
    private authenticatorVersionCheck(): boolean{
        if(this.authenticatorVersion < 0 || this.authenticatorVersion > 4294967295)
            return false;
        if(this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.firmwareVersion != this.authenticatorVersion)
            return false;
        return true;
    }

    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     */
    private protocolFamilyCheck(): boolean{
        if(this.protocolFamily == undefined )
            return false;
        if(protocolFamilyEnum[this.protocolFamily as keyof typeof protocolFamilyEnum] == undefined) 
            return false;
        return true;
    }

    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    private schemaCheck(): boolean{
        if(this.schema < 0 || this.schema > 65535)
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
     *          1) che i campi numero siano compresi tra 1 e 18
     */
    private authenticationAlgorithmsCheck(): boolean{
        if(this.authenticationAlgorithms != undefined){    
            for(let i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (authenticationAlgorithmsEnum[this.authenticationAlgorithms[i] as keyof typeof authenticationAlgorithmsEnum] == undefined)
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi numero siano compresi tra 256 e 260
     */
    private publicKeyAlgAndEncodingsCheck(): boolean{
        if(this.publicKeyAlgAndEncodings != undefined){
            for(let i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (publicKeyAlgAndEncodingsEnum[this.publicKeyAlgAndEncodings[i] as keyof typeof publicKeyAlgAndEncodingsEnum] == undefined)
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi stringa siano basic_full, basic_surrogate, ecdaa oppure attca
     */
    private attestationTypesCheck(): boolean{
        for(let i = 0; i < this.attestationTypes.length; i++) {
            if (attestationTypesEnum[this.attestationTypes[i] as keyof typeof attestationTypesEnum] == undefined)
                return false;
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
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
     *          1) Verifica conformità campi (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types)
     */
    private keyProtectionCheck(): boolean{
        for(let i=0;i<this.keyProtection.length;i++){
            if(keyProtectionEnum[this.keyProtection[i] as keyof typeof keyProtectionEnum] == undefined)
                return false;
        }

        if(this.keyProtection.find(element => element == "software") != undefined){
            if(this.keyProtection.find(element => element == "hardware") != undefined)
                return false;
            if(this.keyProtection.find(element => element == "tee") != undefined)
                return false;
            if(this.keyProtection.find(element => element == "secure_element") != undefined)
                return false;    
        }

        if(this.keyProtection.find(element => element == "tee") != undefined){
            if(this.keyProtection.find(element => element == "secure_element") != undefined)
                return false;  
        }

        return true;
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types)
     */    
    private matcherProtectionCheck(): boolean{
        for(let i=0;i<this.matcherProtection.length;i++){
            if(matcherProtectionEnum[this.matcherProtection[i] as keyof typeof matcherProtectionEnum] == undefined)
                return false;
        }
        if(this.matcherProtection.find(element => element == "software") != undefined){
            if(this.matcherProtection.find(element => element == "tee") != undefined || this.matcherProtection.find(element => element == "on_chip") != undefined)
                return false;
        }
        if(this.matcherProtection.find(element => element == "tee") != undefined){
            if(this.matcherProtection.find(element => element == "on_chip") != undefined)
                return false;
        }
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
     *          1) che il campo number presenti i valori corretti
     */
    private attachmentHintCheck(): boolean{
        for(let i=0;i<this.matcherProtection.length;i++){
            if(attachmentHintEnum[this.attachmentHint[i] as keyof typeof attachmentHintEnum] == undefined)
                return false;
        }
        //se c'è elemento internal insieme ad un altro elemento differente --> errore
        if(this.matcherProtection.find(element => element == "internal") != undefined){
            if(this.matcherProtection.find(element => element != "internal") != undefined)
                return false;
        }
        //se si ha elemento external senza altri elementi si ha errore (il controllo su internal non è stato fatto in quanto fatto dall'if precedente)
        if(this.matcherProtection.find(element => element == "external") != undefined){
            if(this.matcherProtection.find(element => element != "external") == undefined)
                return false;
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
     *          2) campo null -> the authenticator does not support a transaction confirmation display
     */
    private tcDisplayCheck(): boolean{
        if(this.tcDisplay != null){
            for(let i=0;i<this.tcDisplay.length;i++){
                if(tcDisplayEnum[this.tcDisplay[i] as keyof typeof tcDisplayEnum] == undefined)
                    return false;
            }
            if(this.tcDisplay.find(element => element == "privileged_software") != undefined){
                if(this.tcDisplay.find(element => element == "tee") != undefined || this.tcDisplay.find(element => element == "hardware") != undefined)
                    return false;
            }
            if(this.tcDisplay.find(element => element == "tee") != undefined){
                if(this.tcDisplay.find(element => element == "hardware") != undefined)
                    return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo sia anche tcDisplay (non undefined)
     *          2) che il campo presenti un valore tra quelli presentu in tcDisplayContentTypeEnum
     */
    private tcDisplayContentTypeCheck(): boolean{
        if(this.tcDisplay != null && this.tcDisplayContentType == undefined)
            return false;

        if(this.tcDisplayContentType != undefined){
            if(tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == undefined)
                return false;
        }
        return true;
    }   

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non null) e tcDisplayContentType (deve essere image/png)
     */
    private tcDisplayPNGCharacteristicsCheck(): boolean{ //(seconda parte: se variabile tcDisplayContentType è image/png)
        if(this.tcDisplay != null && tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == tcDisplayContentTypeEnum["image/png" as keyof typeof tcDisplayContentTypeEnum] && this.tcDisplayPNGCharacteristics == undefined)
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
        let temp: string | undefined = this.attestationTypes.find(element => element == "ecdaa");
        if(temp != undefined && this.ecdaaTrustAnchors == undefined || temp == undefined && this.ecdaaTrustAnchors != undefined)
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
            if(!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(this.icon)){
                return false;
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che gli oggetti nell'array siamo di tipo ExtensionDescriptor
     */
//    private supportedExtensionsCheck(): boolean{
//        return true;
//    }

    /**
     * Controlli: 
     *          1) Deve essere presente in caso di autenticatore fido2 (gli altri, uaf e u2f, non lo supportano)
     */
     private authenticatorGetInfoCheck(): boolean{
        if(this.protocolFamily == "fido2" && this.authenticatorGetInfo == undefined || this.authenticatorGetInfo != undefined && !this.authenticatorGetInfo.validateData())
            return false;
        return true;
    }
}

class Version{
    constructor(ma:number, mi:number){
        this.major=ma;
        this.minor=mi;
    }
    readonly major: number;
    readonly minor: number;
}

//controlli da fare
class AuthenticatorGetInfo{
    constructor(ver:string[], aag: string, ext?: string[], opt?:authenticatorOption, maxM?:number, pin?:number[],maxCc?: number, maxCIi?: number,
        tra?: string[], alg?:algorithmAuthenticatorGetInfo, maxA?: number, def?: number, fir?: number){
            this.version = Array.from(ver);
            if(ext != undefined){
                this.extensions = Array.from(ext);
            }
            this.aaguid=aag;
            this.options=opt;

    }
    public version: string[];
    public extensions: string[] | undefined;
    public aaguid: string;
    public options: authenticatorOption | undefined;
    public maxMsgSize: number | undefined;
    public pinUvAuthProtocols: number[] | undefined;
    public maxCredentialCountInList: number | undefined;
    public maxCredentialIdLength: number | undefined;
    public transports: string[] | undefined;
    public algorithms: algorithmAuthenticatorGetInfo | undefined;
    public maxAuthenticatorConfigLength: number | undefined;
    public defaultCredProtect: number | undefined;
    public firmwareVersion: number | undefined;

    public validateData(): boolean{
        if(this.version.find(element => element != "FIDO_2_0") == undefined && this.version.find(element => element != "U2F_V2") == undefined)
            return false;
        
        return true;
    }
}

//controlli da fare
class authenticatorOption{
    constructor(p:boolean = false, r:boolean = false, c:boolean | null = null, up:boolean, uv:boolean | null = null,
        uvT?:boolean, co?: boolean){
            this.plat=p;
            this.rk=r;
            this.clientPin=c;
            this.up=up;
            this.uv=uv;
            this.uvToken=uvT;
            this.config=co;
    }
    public plat: boolean;
    public rk: boolean;
    public clientPin: boolean | null;
    public up: boolean;
    public uv: boolean | null;
    public uvToken: boolean | undefined;
    public config: boolean | undefined;
}

class algorithmAuthenticatorGetInfo{
    constructor(type:string, alg:number){
        this.type=type;
        this.alg=alg;
    }
    public type:string;
    public alg: number;
}

enum tcDisplayEnum{
    "any",
    "privileged_software",
    "tee",
    "hardware",
    "remote",
}

enum attachmentHintEnum{
    "internal",
    "external",
    "wired",
    "wireless",
    "nfc",
    "bluetooth",
    "network",
    "ready",
    "wifi_direct",
}

enum matcherProtectionEnum{
    "software",
    "tee",
    "on_chip",
}

enum keyProtectionEnum{
    "software",
    "hardware",
    "tee",
    "secure_element",
    "remote_handle",
}

enum protocolFamilyEnum{
    "uaf",
    "u2f",
    "fido2",
}

enum authenticationAlgorithmsEnum{
    "secp256r1_ecdsa_sha256_raw",
    "secp256r1_ecdsa_sha256_der",
    "rsassa_pss_sha256_raw",
    "rsassa_pss_sha256_der",
    "secp256k1_ecdsa_sha256_raw",
    "secp256k1_ecdsa_sha256_der",
    "sm2_sm3_raw",
    "rsa_emsa_pkcs1_sha256_raw",
    "rsa_emsa_pkcs1_sha256_der",
    "rsassa_pss_sha384_raw",
    "rsassa_pss_sha512_raw",
    "rsassa_pkcsv15_sha256_raw",
    "rsassa_pkcsv15_sha384_raw",
    "rsassa_pkcsv15_sha512_raw",
    "rsassa_pkcsv15_sha1_raw",
    "secp384r1_ecdsa_sha384_raw",
    "secp512r1_ecdsa_sha256_raw",
    "ed25519_eddsa_sha512_raw",
}

enum publicKeyAlgAndEncodingsEnum{
    "ecc_x962_raw",
    "ecc_x962_der",
    "rsa_2048_raw",
    "rsa_2048_der",
    "cose",
}

enum attestationTypesEnum{
    "basic_full",
    "basic_surrogate",
    "ecdaa",
    "attca",
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

enum VerificationMethodDescriptorUserVerificationMethodEnum{
    "presence_internal",
    "fingerprint_internal",
    "passcode_internal",
    "voiceprint_internal",
    "faceprint_internal",
    "location_internal",
    "eyeprint_internal",
    "pattern_internal",
    "handprint_internal",
    "passcode_external",
    "pattern_external",
    "none",
    "all",
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
    constructor(uv: string, c?:CodeAccuracyDescriptor, b?:BiometricAccuracyDescriptor, p?:PatternAccuracyDescriptor){
        this.userVerification=uv;
        this.caDesc=c!;
        this.baDesc=b!;
        this.paDesc=p!;
    }
    public userVerification: string;
    public caDesc: CodeAccuracyDescriptor;
    public baDesc: BiometricAccuracyDescriptor;
    public paDesc: PatternAccuracyDescriptor;

    public validateData(): boolean{
        if(VerificationMethodDescriptorUserVerificationMethodEnum[this.userVerification as keyof typeof VerificationMethodDescriptorUserVerificationMethodEnum] == undefined)
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

enum G1CurveEnum{
    "BN_P256",
    "BN_P638",
    "BN_ISOP256",
    "BN_ISOP512",
}






