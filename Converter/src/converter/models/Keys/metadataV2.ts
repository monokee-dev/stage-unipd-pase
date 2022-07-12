import { X509Certificate } from 'crypto'; // per controllare attestationRootCertificates
import { metadataKeysV3 } from './metadataV3';
import * as  conversion  from './../FieldConverter/V2toV3'
import { convertAttestationRootCertificates } from '../FieldConverter/usefulFunction';
import { convertUserVerificationDetailsV3toV2 } from '../FieldConverter/V3toV2';
import { MetadataKeyError } from '../Error/error';

export class metadataKeysV2{

    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    constructor(description:string, authenticatorVersion:number, upv:Version[], assertionScheme:string, authenticationAlgorithm:number, 
        publicKeyAlgAndEncoding:number, attestationTypes:number[], userVerificationDetails: VerificationMethodANDCombinations[], isSecondFactorOnly:boolean,
        keyProtection: number, matcherProtection: number, cryptoStrength:number | undefined, attachmentHint: number, tcDisplay: number, 
        attestationRootCertificates:string[], legalHeader:string | undefined, aaid:string | undefined, aaguid:string | undefined, attestationCertificateKeyIdentifiers:string[] | undefined,  
        alternativeDescriptions:string | undefined, protocolFamily:string="uaf", authenticationAlgorithms: number[] | undefined,  publicKeyAlgAndEncodings:number[] | undefined,
        isKeyRestricted:boolean = true, isFreshUserVerificationRequired:boolean = true, operatingEnv:string | undefined, 
        tcDisplayContentType:string | undefined, tcDisplayPNGCharacteristics:tcDisplayPNGCharacteristicsDescriptor[] | undefined, ecdaaTrustAnchors:ecdaaTrustAnchor[] | undefined, 
        icon:string | undefined, supportedExtensions: ExtensionDescriptor[] | undefined){

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
            this.userVerificationDetails=Array.from(userVerificationDetails); 
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
            if(tcDisplayPNGCharacteristics != undefined){                            
                this.tcDisplayPNGCharacteristics=Array.from(tcDisplayPNGCharacteristics);
            }
            else{
                this.tcDisplayPNGCharacteristics=undefined;
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
    }

    //dichiarazione di tutte le variabili con relativo tipo    
    public legalHeader: string | undefined;
    public aaid: string | undefined; 
    public aaguid: string | undefined; 
    public attestationCertificateKeyIdentifiers: string[] | undefined; 
    public description: string;
    public alternativeDescriptions: string | undefined;
    public authenticatorVersion: number; 
    public protocolFamily: string;
    public upv: Version[];
    public assertionScheme: string;
    public authenticationAlgorithm: number;                 
    public authenticationAlgorithms: number[] | undefined; 
    public publicKeyAlgAndEncoding: number;
    public publicKeyAlgAndEncodings: number[] | undefined;
    public attestationTypes: number[];
    public userVerificationDetails: VerificationMethodANDCombinations[];
    public keyProtection: number;
    public isKeyRestricted: boolean;
    public isFreshUserVerificationRequired: boolean;
    public matcherProtection: number;
    public cryptoStrength: number | undefined;
    public operatingEnv: string | undefined;
    public attachmentHint: number;
    public isSecondFactorOnly: boolean;   
    public tcDisplay: number;
    public tcDisplayContentType: string | undefined;                               
    public tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor[] | undefined;
    public attestationRootCertificates: string[];
    public ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined;
    public icon: string | undefined;
    public supportedExtensions: ExtensionDescriptor[] | undefined;

    //medodo statico per generazione metadata V2
    public static fromV2toV3(m : metadataKeysV2): metadataKeysV3 {
        let result: metadataKeysV3;
        if(!m.validateAll())
            throw "Errore, metadata versione 2 non valido";
        else{

            let legalHeader = m.legalHeader != undefined ? m.legalHeader : "https://fidoalliance.org/metadata/metadata-statement-legal-header/";
            let aaid = m.aaid != undefined ? m.aaid : undefined;
            let aaguid = m.aaguid != undefined ? m.aaguid : undefined;
            let attestationCertificateKeyIdentifiers = m.attestationCertificateKeyIdentifiers != undefined ? Array.from(m.attestationCertificateKeyIdentifiers) : undefined; //
            let description = m.description;
            let alternativeDescriptions = m.alternativeDescriptions != undefined ? m.alternativeDescriptions : undefined;
            let authenticatorVersion = m.authenticatorVersion; // semplice uguaglianza in quanto c'è conversione unsigned int -> unsigned long
            //in v2 protocolFamily non è obbligatorio -> per ottenere il campo viene utilizzato assertionscheme
            let protocolFamily: string;
            if(m.protocolFamily != undefined){
                protocolFamily = m.protocolFamily;
            }
            else{
                if(m.assertionScheme == "U2FV1BIN")
                    protocolFamily = "u2f";
                else if(m.assertionScheme == "FIDOV2")
                    protocolFamily = "fido2";
                else//UAFV1TLV
                    protocolFamily = "u2f";
            }
            let upv = Array.from(m.upv);

            //authenticationAlgorithms: array ricavato da elementi presenti in m.authenticationAlgorithms e/o valore singolo ricavato da m.authenticationAlgorithm 
            let authenticationAlgorithms: string[] = new Array();
            let tempAuthAlg = conversion.convertauthenticationAlgorithmV2toV3(m.authenticationAlgorithm);
            if(tempAuthAlg != undefined)
                authenticationAlgorithms.push(tempAuthAlg)
            //se l'array in m non è vuoto:
            if(m.authenticationAlgorithms != undefined){
                //aggiungo alla variabile authenticationAlgorithms gli elementi presenti nell'array dell'oggetto
                for(let i = 0; i < m.authenticationAlgorithms.length; i++){
                    let temp = conversion.convertauthenticationAlgorithmV2toV3(m.authenticationAlgorithms[i]);
                    if(temp != undefined)
                        authenticationAlgorithms.push(temp)
                }
            }

            let publicKeyAlgAndEncodings: string[] = new Array();
            let PubKey = conversion.convertpublicKeyAlgAndEncodingV2toV3(m.publicKeyAlgAndEncoding);
            if(PubKey != undefined){
                publicKeyAlgAndEncodings.push(PubKey)
            } 
            if(m.publicKeyAlgAndEncodings != undefined){
                for(let i = 0; i < m.publicKeyAlgAndEncodings.length; i++){
                    let temp = conversion.convertpublicKeyAlgAndEncodingV2toV3(m.publicKeyAlgAndEncodings[i]);
                    if(temp != undefined)
                        publicKeyAlgAndEncodings.push(temp)
                }
            }

            let attestationTypes = conversion.convertAttestationTypesV2toV3(m.attestationTypes);
            let userVerificationDetails = Array();

            for(let i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails.push(m.userVerificationDetails[i])
                if (!(m.userVerificationDetails[i])){
                        for(let l = 0; l < m.userVerificationDetails[i].data.length; l++ ){
                            let numEX = m.userVerificationDetails[i].data[l].userVerification
                            userVerificationDetails[i].data[l].userVerification = conversion.convertUserVerificationDetailsV2toV3(m.userVerificationDetails[i].data[l].userVerification) 
                        }
                }
            }

        
            let keyProtection = conversion.convertKeyProtectionV2toV3(m.keyProtection);
            let isKeyRestricted: boolean = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            let isFreshUserVerificationRequired: boolean = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            let matcherProtection: string[] | undefined = conversion.convertMatcherProtectionV2toV3(m.matcherProtection);
            let cryptoStrength: number | undefined = m.cryptoStrength != undefined ? m.cryptoStrength : undefined;
            let attachmentHint: string[] | undefined = conversion.convertAttachmentHintV2toV3(m.attachmentHint);
            let tcDisplay: string[] | undefined = conversion.convertTcDisplayV2toV3(m.tcDisplay);
            let tcDisplayContentType: string | undefined = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            let tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsDescriptor[] | undefined = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined;//?
            let attestationRootCertificates: string[] = Array.from(m.attestationRootCertificates);
            let ecdaaTrustAnchors: ecdaaTrustAnchor[] | undefined = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            let icon: string | undefined = m.icon != undefined ? m.icon : undefined;
            let supportedExtensions: ExtensionDescriptor[] | undefined = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            let schema:number = conversion.convertSchemaV2toV3();
            let authenticatorgetinfo;
            if(m.aaguid == undefined){
                if(m.assertionScheme == "FIDOV2")
                    throw "Errore, campo assertionScheme presente con valore FidoV2, perciò authenticatorgetinfo è obbligatorio: il campo aaguid non è presente"
                else
                    authenticatorgetinfo = undefined;
            }
            else
                authenticatorgetinfo = conversion.convertAuthenticatorGetInfoV2toV3(m.aaguid, m.assertionScheme);

            //ATTENZIONE controllare i vari campi all'interno del costruttore: i campi dati undefined che sono obbligatori dovrebbero essere inseriti con operatore ternario

            result = new metadataKeysV3(description,authenticatorVersion,upv,schema,attestationTypes != undefined ? attestationTypes : new Array<string>(),
                attestationCertificateKeyIdentifiers,userVerificationDetails != undefined ? userVerificationDetails : new Array(),
                authenticationAlgorithms,Array.from(publicKeyAlgAndEncodings), keyProtection != undefined ? keyProtection : new Array(),
                matcherProtection != undefined ? matcherProtection : new Array(), cryptoStrength, attachmentHint != undefined ? attachmentHint : new Array(), 
                tcDisplay, attestationRootCertificates, legalHeader, aaid, aaguid, alternativeDescriptions, protocolFamily, isKeyRestricted, isFreshUserVerificationRequired, 
                tcDisplayContentType, tcDisplayPNGCharacteristics != undefined ? tcDisplayPNGCharacteristics : undefined , ecdaaTrustAnchors,
                icon, supportedExtensions);
        }
        return result;
    }

    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    public validateData(str:string): boolean{
        switch(V2FunctionName[str as keyof typeof V2FunctionName]){
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
                return this.upvCheck();
                
            case 7:
                return this.assertionSchemeCheck();
                
            case 8:
                return this.authenticationAlgorithmCheck();
                
            case 9:
                return this.authenticationAlgorithmsCheck();
                
            case 10:
                return this.publicKeyAlgAndEncodingCheck();
                
            case 11:
                return this.publicKeyAlgAndEncodingsCheck();
                
            case 12:
                return this.attestationTypesCheck();
                
            case 13:
                return this.userVerificationDetailsCheck();
                
            case 14:
                return this.keyProtectionCheck();
                
            case 15:
                return this.matcherProtectionCheck();
                
            case 16:
                return this.cryptoStrengthCeck();
                
            case 17:
                return this.operatingEnvCheck();
                
            case 18:
                return this.attachmentHintCheck();
                
            case 19:
                return this.tcDisplayCheck();
                
            case 20:
                return this.tcDisplayContentTypeCheck();
                
            case 21:
                return this.tcDisplayPNGCharacteristicsCheck();
                
            case 22:
                return this.attestationRootCertificatesCheck();
                
            case 23:
                return this.ecdaaTrustAnchorsCheck();
                
            case 24:
                return this.iconCheck();
                
            //case 25:
            //    return this.supportedExtensionsCheck();
            //    
        }
        throw "La stringa " + str + " non è una funzione di controllo";
    }


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
            throw new MetadataKeyError("Errore valore aaid")
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
        if(this.protocolFamily == "fido2" && this.aaguid == undefined)
            throw new MetadataKeyError("Errore valore aaguid")
        if(this.protocolFamily == "uaf" && this.aaguid != undefined)
            throw new MetadataKeyError("Errore valore aaguid")
        if(this.aaguid != undefined){
            if(this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                throw new MetadataKeyError("Errore valore aaguid")
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
            throw new MetadataKeyError("Errore valore attestationCertificateKeyIdentifiers")
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
            throw new MetadataKeyError("Errore valore authenticatorVersion")
        return true;
    }

    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) se si usa metadata statement per u2f deve esserci obbligatoriamente il campo "u2f", se si usa FIDO 2.0/WebAuthentication Authenticator il campo deve essere "fido2"
     */
    private protocolFamilyCheck(): boolean{
        if(this.protocolFamily != undefined && this.protocolFamily != "uaf" && this.protocolFamily != "u2f" && this.protocolFamily != "fido2")
            throw new MetadataKeyError("Errore valore protocolFamily")
        if(this.protocolFamily != "fido2" && this.assertionScheme == "FIDOV2")
            throw new MetadataKeyError("Errore valore protocolFamily")
        if(this.protocolFamily != "u2f" && this.assertionScheme == "U2FV1BIN")
            throw new MetadataKeyError("Errore valore protocolFamily")
        if((this.protocolFamily != "uaf" && this.protocolFamily != undefined) && this.assertionScheme == "UAFV1TLV" ) 
            throw new MetadataKeyError("Errore valore protocolFamily")
        return true;
    }

    /**
     * Controlli: 
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
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
     *          1) che il campo stringa sia presente in assertionSchemeEnum (quidi che sia un tra U2FV1BIN, FIDOV2 e UAFV1TLV)
     */
    private assertionSchemeCheck(): boolean{
        if(assertionSchemeEnum[this.assertionScheme as keyof typeof assertionSchemeEnum] == undefined)
            throw new MetadataKeyError("Errore valore assertionScheme")
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo numero sia compreso tra 1 e 18
     *          2) FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
     */
    private authenticationAlgorithmCheck(): boolean{
        if(this.authenticationAlgorithm < 1 || this.authenticationAlgorithm > 18)
            throw new MetadataKeyError("Errore valore authenticationAlgorithm")
        if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
            throw new MetadataKeyError("Errore valore authenticationAlgorithm")
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
                    throw new MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ")
                if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 1)
                    throw new MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ")
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
        if(this.publicKeyAlgAndEncoding <= 255 || this.publicKeyAlgAndEncoding >= 261){
            throw new MetadataKeyError("Errore valore publicKeyAlgAndEncoding")
        }
        if(this.assertionScheme == "U2FV1BIN" && this.publicKeyAlgAndEncoding != 256){ // supporta solo il primo algoritmo
            throw new MetadataKeyError("Errore valore publicKeyAlgAndEncoding")
        }
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
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")
                if(this.assertionScheme == "U2FV1BIN" && this.authenticationAlgorithm != 256)
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")
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
                throw new MetadataKeyError("Errore valore attestationTypes in posizione: " + i + ". ")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#idl-def-VerificationMethodDescriptor)
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types)
     */
    private keyProtectionCheck(): boolean{
        if(this.keyProtection <= 0 || this.keyProtection >= 25){ // 16 + 8 -> 24, massimo num raggiungibile (This flag MUST be set in conjunction with one of the other KEY_PROTECTION flags...)
            throw new MetadataKeyError("Errore valore keyProtection")
        }    
        if(this.keyProtection != 1 && this.keyProtection != 2 && this.keyProtection != 4 && this.keyProtection != 6 &&
            this.keyProtection != 8 && this.keyProtection != 10 && this.keyProtection != 11 && 
            this.keyProtection != 17 && this.keyProtection != 18 && this.keyProtection != 20 && this.keyProtection != 24){
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
     *          1) Verifica conformità campo (https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types)
     */    
    private matcherProtectionCheck(): boolean{
        if(this.matcherProtection < 1 || this.matcherProtection > 4 || this.matcherProtection == 3)
            throw new MetadataKeyError("Errore valore matcherProtection")
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     *       ATTENZIONE:   Se non si sa deve essere posta ad unknown (siccome cryptostrength è unsigned short per convenzione è posta a 0)
     */   
    private cryptoStrengthCeck(): boolean{
        if(this.cryptoStrength != undefined){
            if(this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                throw new MetadataKeyError("Errore valore cryptoStrength")
        }
        if(this.cryptoStrength == undefined)
            throw new MetadataKeyError("Errore valore cryptoStrength")

        return true;
    }

    /**
     * Controlli:
     *          1) che il campo stringa sia presente in operatingEnvEnum
     */
    private operatingEnvCheck(): boolean{
        if(this.operatingEnv != undefined){
            if(operatingEnvEnum[this.operatingEnv as keyof typeof operatingEnvEnum] == undefined)
                throw new MetadataKeyError("Errore valore operatingEnv")
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
            if((i==1 && counter >= 1 && tot != 0) || (i==2 && counter == 0)){
                throw new MetadataKeyError("Errore valore attachmentHint")
            }
            if(tot >= i){
                tot = tot -i;
                counter+=1;
            }
            if(i == 1){
                i=0
            }
            else{
                i=i/2;
            }
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
        if(this.tcDisplay == 6 || this.tcDisplay == 10 || this.tcDisplay == 12){
            throw new MetadataKeyError("Errore valore tcDisplay")
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
            throw new MetadataKeyError("Errore valore tcDisplayContentType")

        if(this.tcDisplayContentType != undefined){
            if(tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == undefined)
                throw new MetadataKeyError("Errore valore tcDisplayContentType")
        }
        return true;
    }   

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non 0) e tcDisplayContentType (deve essere image/png)
     */
    private tcDisplayPNGCharacteristicsCheck(): boolean{ //(seconda parte: se variabile tcDisplayContentType è image/png)
        if(this.tcDisplay != 0 && tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == tcDisplayContentTypeEnum["image/png" as keyof typeof tcDisplayContentTypeEnum] && this.tcDisplayPNGCharacteristics == undefined)
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
                if(this.aaid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.1") != undefined)
                    throw new MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ")
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if(this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.4") != undefined)
                    throw new MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ")
                // or by using the attestationCertificateKeyIdentifier method => ???  TODO
                
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
        let temp: number | undefined = this.attestationTypes.find(element => element == 15881);
        if((temp != undefined && this.ecdaaTrustAnchors == undefined) || (temp == undefined && this.ecdaaTrustAnchors != undefined))
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
            let temp:string=this.icon;
            if(this.icon.indexOf("data:") != -1){
                temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64")+7), "");
            }
            if(!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)){
                throw new MetadataKeyError("Errore valore icon")
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

enum V2FunctionName{
    "aaid" = 1,
    "aaguid" = 2,
    "attestationCertificateKeyIdentifiers" = 3,
    "authenticatorVersion" = 4,
    "protocolFamily" = 5,
    "upv" = 6,
    "assertionScheme" = 7,
    "authenticationAlgorithm" = 8,
    "authenticationAlgorithms" = 9,
    "publicKeyAlgAndEncoding" = 10,
    "publicKeyAlgAndEncodings" = 11,
    "attestationTypes" = 12,
    "userVerificationDetails" = 13,
    "keyProtection" = 14,
    "matcherProtection" = 15,
    "cryptoStrengthCeck" = 16,
    "operatingEnv" = 17,
    "attachmentHint" = 18,
    "tcDisplay" = 19,
    "tcDisplayContentType" = 20,
    "tcDisplayPNGCharacteristics" = 21,
    "attestationRootCertificates" = 22,
    "ecdaaTrustAnchors" = 23,
    "icon" = 24,
    //supportedExtensions = 25,   
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
    public caDesc: CodeAccuracyDescriptor | undefined;
    public baDesc: BiometricAccuracyDescriptor | undefined;
    public paDesc: PatternAccuracyDescriptor | undefined;

    public validateInternalData(): boolean{
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

//nome completo curve sarebbe "TPM_ECC_BN_...." e "ECC_BN_...."
enum G1CurveEnum{
    "BN_P256",
    "BN_P638",
    "BN_ISOP256",
    "BN_ISOP512",
}






