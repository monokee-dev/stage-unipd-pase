import { X509Certificate } from 'crypto'; // per controllare attestationRootCertificates
import { metadataKeysV2 } from './metadataV2';
import { convertAttestationRootCertificates } from '../FieldConverter/usefulFunction';
import { convertAssertionSchemaV3toV2, convertAttachmentHintV3toV2, convertAttestationTypesV3toV2, convertauthenticationAlgorithmV3toV2, convertCryptoStrength3toV2, convertIsSecondFactorOnly3toV2, convertKeyProtectionV3toV2, convertMatcherProtectionV3toV2, convertOperatingEnv3toV2, convertpublicKeyAlgAndEncodingV3toV2, convertTcDisplayV3toV2, convertUserVerificationDetailsV3toV2 } from '../FieldConverter/V3toV2';
import { MetadataKeyError } from '../Error/error';

export class metadataKeysV3{

    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    constructor(description:string, authenticatorVersion:number, upv:Version[], schema:number,
        attestationTypes:string[], attestationCertificateKeyIdentifiers:string[] | undefined,
        userVerificationDetails: VerificationMethodANDCombinations[], authenticationAlgorithms: string[],  publicKeyAlgAndEncodings:string[],
        keyProtection: string[], matcherProtection: string[], cryptoStrength:number | undefined = undefined, attachmentHint: string[], tcDisplay: string[] | undefined, 
        attestationRootCertificates:string[], legalHeader:string, aaid?:string, aaguid?:string, alternativeDescriptions?:string, 
        protocolFamily:string="uaf", isKeyRestricted:boolean = true, isFreshUserVerificationRequired:boolean = true, 
        tcDisplayContentType?:string, tcDisplayPNGCharacteristics?:tcDisplayPNGCharacteristicsDescriptor[], ecdaaTrustAnchors?:ecdaaTrustAnchor[], 
        icon?:string, supportedExtensions?: ExtensionDescriptor[], authenticatorGetInfo?:AuthenticatorGetInfo ){

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
            if(tcDisplay != undefined){
                this.tcDisplay=Array.from(tcDisplay);
            }
            else{
                this.tcDisplay = undefined;
             }                        
            this.tcDisplayContentType=tcDisplayContentType;        
            if(tcDisplayPNGCharacteristics != undefined){                    
                this.tcDisplayPNGCharacteristics=Array.from(tcDisplayPNGCharacteristics);
            }
            else{
                this.tcDisplayPNGCharacteristics = undefined;
            }  
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
            this.authenticatorGetInfo = authenticatorGetInfo;
            
    }

    //dichiarazione di tutte le variabili con relativo tipo    
    public legalHeader: string;
    public aaid: string | undefined; 
    public aaguid: string | undefined; 
    public attestationCertificateKeyIdentifiers: string[] | undefined; 
    public description: string;
    public alternativeDescriptions: string | undefined;
    public authenticatorVersion: number; 
    public protocolFamily: string;
    public schema: number;
    public upv: Version[];              
    public authenticationAlgorithms: string[];
    public publicKeyAlgAndEncodings: string[];
    public attestationTypes: string[];
    public userVerificationDetails: VerificationMethodANDCombinations[];
    public keyProtection: string[];
    public isKeyRestricted: boolean;
    public isFreshUserVerificationRequired: boolean;
    public matcherProtection: string[];
    public cryptoStrength: number | undefined;
    public attachmentHint: string[];
    public tcDisplay: string[] | undefined; // undefined corrisponde all'array vuoto, ciò significa che transaction confirmation non è supportata dall'autenticatore
    public tcDisplayContentType: string | undefined;                               
    public tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor[] | undefined;
    public attestationRootCertificates: string[];
    public ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined;
    public icon: string | undefined;
    public supportedExtensions: ExtensionDescriptor[] | undefined;
    public authenticatorGetInfo: AuthenticatorGetInfo | undefined;

    //medodo statico per generazione metadata V2
    public static fromV3toV2(m : metadataKeysV3): metadataKeysV2 {
        let result: metadataKeysV2;
        if(!m.validateAll())
            throw "Errore, metadata versione 3 non valido";
        else{
            //conversioni + campi essenziali
            let legalHeader = m.legalHeader != undefined ? m.legalHeader : "https://fidoalliance.org/metadata/metadata-statement-legal-header/";
            let aaid = m.aaid != undefined ? m.aaid : undefined;
            let aaguid = m.aaguid != undefined ? m.aaguid : undefined;; 
            let attestationCertificateKeyIdentifiers = m.attestationCertificateKeyIdentifiers != undefined ? Array.from(m.attestationCertificateKeyIdentifiers) : undefined; 
            let description = m.description;
            let alternativeDescriptions = m.alternativeDescriptions != undefined ? m.alternativeDescriptions : undefined;
            let authenticatorVersion = m.authenticatorVersion;
            let protocolFamily = m.protocolFamily;
            let upv = Array.from(m.upv);  
            let assertionScheme = convertAssertionSchemaV3toV2(m.protocolFamily);   
            // prendere primo elemento array di algoritmi per inserirlo nl campo corretto (quello singolo del metadata v2)
            let authenticationAlgorithm = m.authenticationAlgorithms[0] != undefined ? convertauthenticationAlgorithmV3toV2(m.authenticationAlgorithms[0]) : undefined;
            //array con elemento in meno (posizionato nel campo precedente)
            let tempAlg = Array.from(m.authenticationAlgorithms.slice(1));
            let authenticationAlgorithms;
            if(tempAlg.length != 0){
                authenticationAlgorithms = new Array();
                for( let i = 0; i < tempAlg.length; i++)
                    authenticationAlgorithms.push(convertauthenticationAlgorithmV3toV2(tempAlg[i]));
            }
            else{
                authenticationAlgorithms = undefined;
            }
            // stesssa cosa per publicKeyAlgAndEncoding
            let publicKeyAlgAndEncoding = m.publicKeyAlgAndEncodings != undefined ? convertpublicKeyAlgAndEncodingV3toV2(m.publicKeyAlgAndEncodings[0]) : undefined;
            let tempEnc = Array.from(m.publicKeyAlgAndEncodings.slice(1));
            let publicKeyAlgAndEncodings;
            if(tempEnc.length != 0){
                publicKeyAlgAndEncodings = new Array()
                for( let i = 0; i < tempEnc.length; i++)
                    publicKeyAlgAndEncodings.push(convertpublicKeyAlgAndEncodingV3toV2(tempEnc[i]));
            }
            else{
                publicKeyAlgAndEncodings = undefined;
            }
            let attestationTypes;
            let tempAttType = convertAttestationTypesV3toV2(m.attestationTypes)
            if(tempAttType != undefined)
                attestationTypes = Array.from(tempAttType);

            let userVerificationDetails = Array();
            for(let i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails.push(m.userVerificationDetails[i])
                if (!(m.userVerificationDetails[i])){
                        for(let l = 0; l < m.userVerificationDetails[i].data.length; l++ ){
                            let numEX = m.userVerificationDetails[i].data[l].userVerification
                            userVerificationDetails[i].data[l].userVerification = convertUserVerificationDetailsV3toV2(m.userVerificationDetails[i].data[l].userVerification) 
                        }
                }
            }

            let keyProtection = convertKeyProtectionV3toV2(m.keyProtection)
            let isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            let isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            let matcherProtection = convertMatcherProtectionV3toV2(m.matcherProtection);
            let cryptoStrength = convertCryptoStrength3toV2(m.cryptoStrength);
            let operatingEnv = convertOperatingEnv3toV2();
            let attachmentHint = convertAttachmentHintV3toV2(m.attachmentHint);
            let isSecondFactorOnly = convertIsSecondFactorOnly3toV2(undefined);
            if(m.authenticatorGetInfo != undefined){
                if(m.authenticatorGetInfo.options != undefined){
                    if(m.authenticatorGetInfo.options.uv != undefined){
                        isSecondFactorOnly = convertIsSecondFactorOnly3toV2(m.authenticatorGetInfo.options.uv)
                    }
                }
            }
            let tcDisplay;
            if(m.tcDisplay != undefined)
                tcDisplay = convertTcDisplayV3toV2(m.tcDisplay);
            else
                tcDisplay = undefined;
            let tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;                            
            let tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor[] | undefined = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined;
            let attestationRootCertificates: string[] = Array.from(m.attestationRootCertificates);
            let ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            let icon: string | undefined = m.icon != undefined ? m.icon : undefined;
            let supportedExtensions: ExtensionDescriptor[] | undefined = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined; 
            result = new metadataKeysV2(description,authenticatorVersion,upv,assertionScheme,authenticationAlgorithm != undefined ? authenticationAlgorithm : 0 ,publicKeyAlgAndEncoding != undefined ? publicKeyAlgAndEncoding : 0,
                attestationTypes != undefined ? attestationTypes : new Array(), userVerificationDetails,isSecondFactorOnly,keyProtection != undefined ? keyProtection : 0,matcherProtection != undefined ? matcherProtection : 0,
                cryptoStrength != undefined ? cryptoStrength : 0 ,attachmentHint != undefined ? attachmentHint : 0,tcDisplay != undefined ? tcDisplay : 0,attestationRootCertificates,legalHeader,aaid,aaguid,attestationCertificateKeyIdentifiers,
                alternativeDescriptions,protocolFamily,authenticationAlgorithms != undefined ? authenticationAlgorithms : undefined,publicKeyAlgAndEncodings != undefined ? publicKeyAlgAndEncodings : undefined,isKeyRestricted,isFreshUserVerificationRequired,operatingEnv,tcDisplayContentType,
                tcDisplayPNGCharacteristics,ecdaaTrustAnchors,icon,supportedExtensions);
        }
        return result;
    }

    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    public validateData(str:string): boolean{
        switch(V3FunctionName[str as keyof typeof V3FunctionName]){
            case 1:
                return this.aaidCheck()
                
            case 2:
                return this.aaguidCheck()
                
            case 3:
                return this.attestationCertificateKeyIdentifiersCheck();
                
            case 4:
                return this.authenticatorVersionCheck();
                
            case 5:
                return this.protocolFamilyCheck()
                
            case 6:
                return this.schemaCheck();
                
            case 7:
                return this.upvCheck();
                
            case 8:
                return this.authenticationAlgorithmsCheck();
                
            case 9:
                return this.publicKeyAlgAndEncodingsCheck();
                
            case 10:
                return this.attestationTypesCheck();
                
            case 11:
                return this.userVerificationDetailsCheck();
                
            case 12:
                return this.keyProtectionCheck();
                
            case 13:
                return this.matcherProtectionCheck();
                
            case 14:
                return this.cryptoStrengthCeck();
                
            case 15:
                return this.attachmentHintCheck();
                
            case 16:
                return this.tcDisplayCheck();
                
            case 17:
                return this.tcDisplayContentTypeCheck();
                
            case 18:
                return this.tcDisplayPNGCharacteristicsCheck();
                
            case 19:
                return this.attestationRootCertificatesCheck();
                
            case 20:
                return this.ecdaaTrustAnchorsCheck();
                
            case 21:
                return this.iconCheck();
                
            case 22:
                return this.authenticatorGetInfoCheck();
                
            //case 23:
            //      return this.supportedExtensionsCheck();
            //      
        }
        throw "La stringa " + str + " non è una funzione di controllo";
    }

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
            

    /**
     * Campo legalHeader non controllato:
     *          1) è obbligatorio ci sia (controllo nel costruttore)
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
            throw new MetadataKeyError("Errore valore aaid");
        //no distinzione upper-lower case
        if(this.aaid != undefined && (!RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid) || this.protocolFamily == "fido2"))
            throw new MetadataKeyError("Errore valore aaid")
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     *          3) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example  
     */
    private aaguidCheck(): boolean{
        if((this.protocolFamily == "fido2" && this.aaguid == undefined) || (this.protocolFamily == "uaf" && this.aaguid != undefined))
            throw new MetadataKeyError("Errore valore aaguid")
        if(this.aaguid != undefined){
            if(this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                throw new MetadataKeyError("Errore valore aaguid")
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
                    throw new MetadataKeyError("Errore valore attestationCertificateKeyIdentifiers in posizione: " + i + ". ")
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
     *          2) controllo uguaglianza firmwareVersion non svolto perché non sempre è vero
     */
    private authenticatorVersionCheck(): boolean{
        if(this.authenticatorVersion < 0 || this.authenticatorVersion > 4294967295)
            throw new MetadataKeyError("Errore valore authenticatorVersion")
        if(this.authenticatorGetInfo != undefined && (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.firmwareVersion != undefined && this.authenticatorGetInfo.firmwareVersion != this.authenticatorVersion))
            throw new MetadataKeyError("Errore valore authenticatorVersion")
        return true;
    }

    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) controllo corrispondenza con campo "version" di authenticatorgetinfo
     */
    private protocolFamilyCheck(): boolean{
        if(this.protocolFamily == undefined )
            throw new MetadataKeyError("Errore valore protocolFamily")
        if(protocolFamilyEnum[this.protocolFamily as keyof typeof protocolFamilyEnum] == undefined) 
            throw new MetadataKeyError("Errore valore protocolFamily")
        if(this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.version != undefined){
            if(this.protocolFamily == "fido2" && (this.authenticatorGetInfo.version.find(element => element == "FIDO_2_1") == undefined && 
                                                this.authenticatorGetInfo.version.find(element => element == "FIDO_2_0") == undefined &&
                                                this.authenticatorGetInfo.version.find(element => element == "FIDO_2_1_PRE") == undefined))
                throw new MetadataKeyError("Errore valore protocolFamily")
            if(this.protocolFamily == "u2f" && (this.authenticatorGetInfo.version.find(element => element == "U2F_V2") == undefined))
                throw new MetadataKeyError("Errore valore protocolFamily")
        }  
        return true;
    }

    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    private schemaCheck(): boolean{
        if(this.schema < 0 || this.schema > 65535)
            throw new MetadataKeyError("Errore valore Schema");
        return true;
    }

    /**
     * Controlli: 
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     *          2) controlli specifici non effettuati sulla versione nei casi UAF, U2F e FIDO2/CTAP2
     */
     private upvCheck(){
        for(let i=0; i<this.upv.length;i++){
            if(this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                throw new MetadataKeyError("Errore valore upv in posizione: " + i + ". ")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che secp256r1_ecdsa_sha256_raw
     */
    private authenticationAlgorithmsCheck(): boolean{
        if(this.authenticationAlgorithms != undefined){    
            for(let i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (authenticationAlgorithmsEnum[this.authenticationAlgorithms[i] as keyof typeof authenticationAlgorithmsEnum] == undefined)
                    throw new MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ")
                if(this.protocolFamily == "u2f" && this.authenticationAlgorithms[i] != "secp256r1_ecdsa_sha256_raw")
                    throw new MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ")
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che ecc_x962_raw
     */
    private publicKeyAlgAndEncodingsCheck(): boolean{
        if(this.publicKeyAlgAndEncodings != undefined){
            for(let i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (publicKeyAlgAndEncodingsEnum[this.publicKeyAlgAndEncodings[i] as keyof typeof publicKeyAlgAndEncodingsEnum] == undefined){
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")}
                if(this.protocolFamily == "u2f" && this.publicKeyAlgAndEncodings[i] != "ecc_x962_raw"){
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")}
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
                throw new MetadataKeyError("Errore valore attestationTypes")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
     */
     private userVerificationDetailsCheck(): boolean{
        for(let i = 0; i < this.userVerificationDetails.length; i++) {
            if (!(this.userVerificationDetails[i])){
                    for(let l = 0; l < this.userVerificationDetails[i].data.length; l++ ){
                        if(!this.userVerificationDetails[i].data[l].validateInternalData())
                            throw new MetadataKeyError("Errore valore userVerificationDetails")
                    }
            }
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
                throw new MetadataKeyError("Errore valore keyProtection")
        }

        if(this.keyProtection.find(element => element == "software") != undefined){
            if(this.keyProtection.find(element => element == "hardware") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
            if(this.keyProtection.find(element => element == "tee") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
            if(this.keyProtection.find(element => element == "secure_element") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")   
        }

        if(this.keyProtection.find(element => element == "tee") != undefined){
            if(this.keyProtection.find(element => element == "secure_element") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")  
        }

        //(remote_handle) MUST be set in conjunction with one of the other KEY_PROTECTION flags 
        if(this.keyProtection.find(element => element == "remote_handle") != undefined){
            if(this.keyProtection.find(element => element != "remote_handle") == undefined)
                throw new MetadataKeyError("Errore valore keyProtection")  
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
                throw new MetadataKeyError("Errore valore matcherProtection")  
        }
        if(this.matcherProtection.find(element => element == "software") != undefined){
            if(this.matcherProtection.find(element => element == "tee") != undefined || this.matcherProtection.find(element => element == "on_chip") != undefined)
                throw new MetadataKeyError("Errore valore matcherProtection")  
        }
        if(this.matcherProtection.find(element => element == "tee") != undefined){
            if(this.matcherProtection.find(element => element == "on_chip") != undefined)
                throw new MetadataKeyError("Errore valore matcherProtection")  
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
                throw new MetadataKeyError("Errore valore cryptoStrength")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    private attachmentHintCheck(): boolean{
        for(let i=0;i<this.attachmentHint.length;i++){
            if(attachmentHintEnum[this.attachmentHint[i] as keyof typeof attachmentHintEnum] == undefined)
                throw new MetadataKeyError("Errore valore attachmentHint")
        }
        //se c'è elemento internal insieme ad un altro elemento differente --> errore
        if(this.attachmentHint.find(element => element == "internal") != undefined){
            if(this.attachmentHint.find(element => element != "internal") != undefined)
                throw new MetadataKeyError("Errore valore attachmentHint")
        }
        //se si ha elemento external senza altri elementi si ha errore (il controllo su internal non è stato fatto in quanto fatto dall'if precedente)
        if(this.attachmentHint.find(element => element == "external") != undefined){
            if(this.attachmentHint.find(element => element != "external") == undefined)
                throw new MetadataKeyError("Errore valore attachmentHint")
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
     *          2) campo undefined -> the authenticator does not support a transaction confirmation display
     */
    private tcDisplayCheck(): boolean{
        if(this.tcDisplay != undefined){
            for(let i=0;i<this.tcDisplay.length;i++){
                if(tcDisplayEnum[this.tcDisplay[i] as keyof typeof tcDisplayEnum] == undefined)
                    throw new MetadataKeyError("Errore valore tcDisplay")
            }
            if(this.tcDisplay.find(element => element == "privileged_software") != undefined){
                if(this.tcDisplay.find(element => element == "tee") != undefined || this.tcDisplay.find(element => element == "hardware") != undefined)
                    throw new MetadataKeyError("Errore valore tcDisplay")
            }
            if(this.tcDisplay.find(element => element == "tee") != undefined){
                if(this.tcDisplay.find(element => element == "hardware") != undefined)
                    throw new MetadataKeyError("Errore valore tcDisplay")
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
        if((this.tcDisplay != undefined && this.tcDisplay.length >= 1) && this.tcDisplayContentType == undefined)
            throw new MetadataKeyError("Errore valore tcDisplayContentType")

        if(this.tcDisplayContentType != undefined && (this.tcDisplay != undefined && this.tcDisplay.length >= 1)){
            if(tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == undefined)
                throw new MetadataKeyError("Errore valore tcDisplayContentType")
        }
        return true;
    }   

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non undefined) e tcDisplayContentType (deve essere image/png)
     */
    private tcDisplayPNGCharacteristicsCheck(): boolean{ //(seconda parte: se variabile tcDisplayContentType è image/png)
        if(this.tcDisplay != undefined && tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == tcDisplayContentTypeEnum["image/png" as keyof typeof tcDisplayContentTypeEnum] && this.tcDisplayPNGCharacteristics == undefined)
            throw new MetadataKeyError("Errore valore tcDisplayPNGCharacteristics")
        return true;
    }

    /**
     * Controlli: 
     *          1) 
     * 
     * //ATTENZIONE: When supporting surrogate basic attestation only (see [UAFProtocol], section "Surrogate Basic Attestation"), no attestation trust anchor is required/used. So this array MUST be empty in that case. 
     */
    private attestationRootCertificatesCheck(): boolean {
        for (let i = 0; i < this.attestationRootCertificates.length; i++) {
            const testCert: X509Certificate = new X509Certificate(convertAttestationRootCertificates(this.attestationRootCertificates[i]));
            if (testCert.ca) {
                // caso 1 CA o intermediate ca
                if (testCert.verify(testCert.publicKey)) {
                    //console.log("attestationRootCertificate[" + i + "]" + ": root CA");
                } else {
                    //console.log("attestationRootCertificate[" + i + "]" + ": intermediate CA");
                }
            }
            //this can be achieved by either specifying the AAID or AAGUID in the attestation certificate
            else {
                // using the extension id-fido-gen-ce-aaid { 1 3 6 1 4 1 45724 1 1 1 }
                if(this.aaid != undefined  && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.1") != undefined)
                    throw new MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ")
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if(this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.4") != undefined)
                    throw new MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ")
                // or by using the attestationCertificateKeyIdentifier method => ??? TODO
                
                //console.debug(testCert);
                //console.log("attestationRootCertificate[" + i + "]" + ": leaf");
            }
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
            throw new MetadataKeyError("Errore valore ecdaaTrustAnchors")
        
        if(this.ecdaaTrustAnchors != undefined){
            for(let i=0;i<this.ecdaaTrustAnchors.length;i++){
                if(!this.ecdaaTrustAnchors[i].validateInternalData())
                    throw new MetadataKeyError("Errore valore ecdaaTrustAnchors in posizione: " + i + ". ")
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
            let temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64")+7), "");
            if(!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)){
                throw new MetadataKeyError("Errore valore icon")
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
     *          1) Verifica correttezza campi
     *          2) se presente c'è controllo in protocol family
     */
    private authenticatorGetInfoCheck(): boolean{
        return this.authenticatorGetInfo!.validateInternalData();
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

export class AuthenticatorGetInfo{
    constructor(ver:string[], aag: string, ext?: string[], opt?:authenticatorOption, maxM?:number, pin?:number[],maxCc?: number, maxCIi?: number,
        tra?: string[], alg?:algorithmAuthenticatorGetInfo, maxA?: number, def?: number, fir?: number, maxS?: number, force?: boolean, minP?: number,
        maxCbl?: number, maxRpin?: number, pref?: number, uvM?: number, certif?: string[], remaining?: number, vendor?: number[]){
            this.version = Array.from(ver);
            if(ext != undefined){
                this.extensions = Array.from(ext);
            }
            this.aaguid=aag;
            this.options=opt;
            this.maxMsgSize=maxM;
            this.pinUvAuthProtocols=pin;
            this.maxCredentialCountInList=maxCc;
            this.maxCredentialIdLength=maxCIi;
            this.transports=tra;
            this.algorithms=alg;
            this.maxSerializedLargeBlobArray=maxS;
            this.forcePINChange=force;
            this.minPINLength=minP;
            this.firmwareVersion=fir;
            this.maxCredBlobLength=maxCbl;
            this.maxRPIDsForSetMinPINLength=maxRpin;
            this.preferredPlatformUvAttempts=pref;
            this.uvModality=uvM;
            this.certifications=certif;
            this.remainingDiscoverableCredentials=remaining;
            this.vendorPrototypeConfigCommands=vendor;
            this.maxAuthenticatorConfigLength=maxA;
            this.defaultCredProtect=def;
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

    //possibile aumentare i controlli: guardare https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
    public algorithms: algorithmAuthenticatorGetInfo | undefined;
    public maxSerializedLargeBlobArray: number | undefined;
    public forcePINChange: boolean | undefined;
    public minPINLength: number | undefined;
    public firmwareVersion: number | undefined;
    public maxCredBlobLength: number | undefined;
    public maxRPIDsForSetMinPINLength: number | undefined;
    public preferredPlatformUvAttempts: number | undefined;
    public uvModality: number | undefined;
    public certifications: string[] | undefined;
    public remainingDiscoverableCredentials: number | undefined;
    public vendorPrototypeConfigCommands: number[] | undefined;
    public maxAuthenticatorConfigLength: number | undefined;
    public defaultCredProtect: number | undefined;

    public validateInternalData(): boolean{
        //se i valori non sono tra quelli consentiti
        if(this.version.find(element => element == "FIDO_2_0") == undefined && this.version.find(element => element == "U2F_V2") == undefined && this.version.find(element => element == "FIDO_2_1") == undefined &&
        this.version.find(element => element == "FIDO_2_1_PRE") == undefined)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: version")
        //non è possibile che come valore ci sia soltanto U2F_V2 senza almeno FIDO_2_0, perché "FIDO UAF and FIDO U2F authenticators do not support authenticatorGetInfo" (https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
        if(this.version.find(element => element == "U2F_V2") != undefined && this.version.find(element => element == "FIDO_2_0") == undefined)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: version")
        //se extension no ha un valore tra quelli consentiti
        if(this.extensions != undefined && this.extensions.find(element => element == "credProtect") == undefined && this.extensions.find(element => element == "credBlob") == undefined &&
            this.extensions.find(element => element == "credProtect") == undefined && this.extensions.find(element => element == "largeBlobKey") == undefined &&
            this.extensions.find(element => element == "minPinLength") == undefined && this.extensions.find(element => element == "hmac-secret"))
                throw new MetadataKeyError("Errore valore authenticatorGetInfo: extensions")
        if(!RegExp(/^[0-9a-f]+$/).test(this.aaguid))
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: aaguid")
        if(this.maxMsgSize != undefined && this.maxMsgSize < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxMsgSize")
        if(this.pinUvAuthProtocols != undefined){
            for(let i=0; i<this.pinUvAuthProtocols.length;i++){
                if(this.pinUvAuthProtocols[i] < 0)
                    throw new MetadataKeyError("Errore valore authenticatorGetInfo: pinUvAuthProtocols in posizione: " + i)
            }
        }
        if(this.maxCredentialCountInList != undefined && this.maxCredentialCountInList < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxCredentialCountInList")
        if(this.maxCredentialIdLength != undefined && this.maxCredentialIdLength < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxCredentialIdLength")
        if(this.transports != undefined && this.transports.find(element => element == "usb") == undefined && this.transports.find(element => element == "nfc") == undefined &&
            this.transports.find(element => element == "ble") == undefined && this.transports.find(element => element == "internal") == undefined)
                throw new MetadataKeyError("Errore valore authenticatorGetInfo: transports")
        
        if(this.maxSerializedLargeBlobArray != undefined && this.maxSerializedLargeBlobArray < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxSerializedLargeBlobArray")
        if(this.minPINLength != undefined && this.minPINLength < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: minPINLength")
        if(this.firmwareVersion != undefined && this.firmwareVersion < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: firmwareVersion")
        if(this.maxCredBlobLength  != undefined && this.maxCredBlobLength  < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxCredBlobLength")
        if(this.maxRPIDsForSetMinPINLength != undefined && this.maxRPIDsForSetMinPINLength < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: maxRPIDsForSetMinPINLength")
        if(this.preferredPlatformUvAttempts != undefined && this.preferredPlatformUvAttempts < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: preferredPlatformUvAttempts")
        if(this.certifications != undefined && this.certifications.find(element => element == "FIPS-CMVP-2") == undefined && this.certifications.find(element => element == "FIPS-CMVP-2") == undefined &&
        this.certifications.find(element => element == "FIPS-CMVP-3") == undefined && this.certifications.find(element => element == "FIPS-CMVP-2-PHY") == undefined && 
        this.certifications.find(element => element == "FIPS-CMVP-3-PHY") == undefined && this.certifications.find(element => element == "CC-EAL") == undefined &&
        this.certifications.find(element => element == "FIDO") == undefined)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: certifications")
        if(this.remainingDiscoverableCredentials != undefined && this.remainingDiscoverableCredentials < 0)
            throw new MetadataKeyError("Errore valore authenticatorGetInfo: remainingDiscoverableCredentials")
        if(this.vendorPrototypeConfigCommands != undefined){
            for(let i=0; i<this.vendorPrototypeConfigCommands.length;i++){
                if(this.vendorPrototypeConfigCommands[i] < 0)
                    throw new MetadataKeyError("Errore valore authenticatorGetInfo: vendorPrototypeConfigCommands in posizione: " + i)
            }
        }
        return true;
    }
}

//controlli da fare
export class authenticatorOption{
    constructor(p:boolean = false, r:boolean = false, c:boolean | null = null, up:boolean=true, uv:boolean | null = null,
        uvT?:boolean, no?: boolean, la?:boolean, ep?:boolean, bio?:boolean, user?:boolean, uvBio?:boolean, auth?:boolean, uva?:boolean,
        cred?:boolean, crede?:boolean,setM?:boolean, make?:boolean, alw?:boolean){
            this.plat=p;
            this.rk=r;
            this.clientPin=c;
            this.up=up;
            this.uv=uv;
            this.pinUvAuthToken=uvT;
            this.noMcGaPermissionsWithClientPin=no;
            this.largeBlobs=la;
            this.ep=ep;
            this.bioEnroll=bio;
            this.userVerificationMgmtPreview=user;
            this.uvBioEnroll=uvBio;
            this.authnrCfg=auth;
            this.uvAcfg=uva;
            this.credMgmt=cred;
            this.credentialMgmtPreview=crede;
            this.setMinPINLength=setM;
            this.makeCredUvNotRqd=make;
            this.alwaysUv=alw;
    }
    public plat: boolean;
    public rk: boolean;
    public clientPin: boolean | null;
    public up: boolean;
    public uv: boolean | null;
    public pinUvAuthToken: boolean | undefined;
    public noMcGaPermissionsWithClientPin: boolean | undefined;
    public largeBlobs: boolean | undefined;
    public ep: boolean | undefined;
    public bioEnroll: boolean | undefined;
    public userVerificationMgmtPreview: boolean | undefined;
    public uvBioEnroll: boolean | undefined;
    public authnrCfg: boolean | undefined;
    public uvAcfg: boolean | undefined;
    public credMgmt: boolean | undefined;
    public credentialMgmtPreview: boolean | undefined;
    public setMinPINLength: boolean | undefined;
    public makeCredUvNotRqd: boolean | undefined;
    public alwaysUv: boolean | undefined;
}

class algorithmAuthenticatorGetInfo{
    constructor(type:string, alg:number){
        this.type=type;
        this.alg=alg;
    }
    public type:string;
    public alg: number;
}

enum V3FunctionName{
    "aaid" = 1,
    "aaguid" = 2,
    "attestationCertificateKeyIdentifiers" = 3,
    "authenticatorVersion" = 4,
    "protocolFamily" = 5,
    "schema" = 6,
    "upv" = 7,
    "authenticationAlgorithms" = 8,
    "publicKeyAlgAndEncodings" = 9,
    "attestationTypes" = 10,
    "userVerificationDetails" = 11,
    "keyProtection" = 12,
    "matcherProtection" = 13,
    "cryptoStrength" = 14,
    "attachmentHint" = 15,
    "tcDisplay" = 16,
    "tcDisplayContentType" = 17,
    "tcDisplayPNGCharacteristics" = 18,
    "attestationRootCertificates" = 19,
    "ecdaaTrustAnchors" = 20,
    "icon" = 21,
    "authenticatorGetInfo" = 22,
    //supportedExtensions = 23,
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

//errore documentazione: 0x000B == 0x003 (solo nome tra virgolette)
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
    "error",
    "presence_internal",
    "fingerprint_internal",
    "passcode_internal",
    "voiceprint_internal",
    "faceprint_internal",
    "location_internal",
    "eyeprint_internal",
    "pattern_internal",
    "handprint_internal",
    "none",
    "all",
    "passcode_external",
    "pattern_external",
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
    public caDesc: CodeAccuracyDescriptor | undefined;
    public baDesc: BiometricAccuracyDescriptor | undefined;
    public paDesc: PatternAccuracyDescriptor | undefined;

    public validateInternalData(): boolean{
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
    public validateInternalData(): boolean{
        for(let i = 0; i < this.data.length; i++){
            if(!this.data[i].validateInternalData())
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
    public validateInternalData(): boolean{
        for(let i = 0; i < this.data.length; i++){
            if(!this.data[i].validateInternalData())
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

    public validateInternalData(): boolean{
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

    public validateInternalData(): boolean{
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