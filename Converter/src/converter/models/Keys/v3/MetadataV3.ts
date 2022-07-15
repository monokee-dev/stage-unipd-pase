import { X509Certificate } from 'crypto'; // per controllare attestationRootCertificates
import { MetadataKeyError } from '../../Error/error';
import { V3toV2 } from '../../FieldConverter/V3toV2';
import { metadataKeysV2 } from '../metadataV2';
import { AuthenticatorGetInfo } from '../fields/AuthenticatorGetInfo';
import { Version } from "../fields/Version"

class MetadataKeysV3 {

    //costruttore con tutti i campi, quelli richiesti sono obbligatori, gli altri facoltativi
    constructor(description: string, authenticatorVersion: number, upv: Version[], schema: number,
        attestationTypes: string[], attestationCertificateKeyIdentifiers: string[] | undefined,
        userVerificationDetails: VerificationMethodANDCombinations[], authenticationAlgorithms: string[], publicKeyAlgAndEncodings: string[],
        keyProtection: string[], matcherProtection: string[], cryptoStrength: number | undefined = undefined, attachmentHint: string[], tcDisplay: string[] | undefined,
        attestationRootCertificates: string[], legalHeader: string, aaid?: string, aaguid?: string, alternativeDescriptions?: string,
        protocolFamily: string = "uaf", isKeyRestricted: boolean = true, isFreshUserVerificationRequired: boolean = true,
        tcDisplayContentType?: string, tcDisplayPNGCharacteristics?: TcDisplayPNGCharacteristicsDescriptor[], ecdaaTrustAnchors?: ECDAATrustAnchor[],
        icon?: string, supportedExtensions?: ExtensionDescriptor[], authenticatorGetInfo?: AuthenticatorGetInfo) {

        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.schema = schema;
        this.upv = Array.from(upv);
        this.authenticationAlgorithms = Array.from(authenticationAlgorithms);
        this.publicKeyAlgAndEncodings = Array.from(publicKeyAlgAndEncodings);
        this.attestationTypes = Array.from(attestationTypes);
        this.userVerificationDetails = userVerificationDetails;
        this.keyProtection = Array.from(keyProtection);
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = Array.from(matcherProtection);
        this.cryptoStrength = cryptoStrength;
        this.attachmentHint = attachmentHint;
        if (tcDisplay != undefined) {
            this.tcDisplay = Array.from(tcDisplay);
        }
        else {
            this.tcDisplay = undefined;
        }
        this.tcDisplayContentType = tcDisplayContentType;
        if (tcDisplayPNGCharacteristics != undefined) {
            this.tcDisplayPNGCharacteristics = Array.from(tcDisplayPNGCharacteristics);
        }
        else {
            this.tcDisplayPNGCharacteristics = undefined;
        }
        this.attestationRootCertificates = attestationRootCertificates;
        if (ecdaaTrustAnchors != undefined) {
            this.ecdaaTrustAnchors = Array.from(ecdaaTrustAnchors);
        }
        else {
            this.ecdaaTrustAnchors = undefined;
        }
        this.icon = icon;
        //controllo che supportedExtensions esista per assegnarlo a this.supportedExtensions
        if (supportedExtensions != undefined) {
            this.supportedExtensions = Array.from(supportedExtensions);
        }
        else {
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
    public tcDisplayPNGCharacteristics: TcDisplayPNGCharacteristicsDescriptor[] | undefined;
    public attestationRootCertificates: string[];
    public ecdaaTrustAnchors: ECDAATrustAnchor[] | undefined;
    public icon: string | undefined;
    public supportedExtensions: ExtensionDescriptor[] | undefined;
    public authenticatorGetInfo: AuthenticatorGetInfo | undefined;

    //medodo statico per generazione metadata V2
    public static fromV3toV2(m: MetadataKeysV3): metadataKeysV2 {
        let result: metadataKeysV2;
        if (!m.validateAll())
            throw "Errore, metadata versione 3 non valido";
        else {
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
            let assertionScheme = V3toV2.convertAssertionSchema(m.protocolFamily);
            // prendere primo elemento array di algoritmi per inserirlo nl campo corretto (quello singolo del metadata v2)
            let authenticationAlgorithm = m.authenticationAlgorithms[0] != undefined ? V3toV2.convertauthenticationAlgorithm(m.authenticationAlgorithms[0]) : undefined;
            //array con elemento in meno (posizionato nel campo precedente)
            let tempAlg: string[] = Array.from(m.authenticationAlgorithms.slice(1));
            let authenticationAlgorithms;
            if (tempAlg.length != 0) {
                authenticationAlgorithms = new Array();
                for (let i = 0; i < tempAlg.length; i++)
                    authenticationAlgorithms.push(V3toV2.convertauthenticationAlgorithm(tempAlg[i]));
            }
            else {
                authenticationAlgorithms = undefined;
            }
            // stesssa cosa per publicKeyAlgAndEncoding
            let publicKeyAlgAndEncoding = m.publicKeyAlgAndEncodings != undefined ? V3toV2.convertpublicKeyAlgAndEncoding(m.publicKeyAlgAndEncodings[0]) : undefined;
            let tempEnc: string[] = Array.from(m.publicKeyAlgAndEncodings.slice(1));
            let publicKeyAlgAndEncodings;
            if (tempEnc.length != 0) {
                publicKeyAlgAndEncodings = new Array()
                for (let i = 0; i < tempEnc.length; i++)
                    publicKeyAlgAndEncodings.push(V3toV2.convertpublicKeyAlgAndEncoding(tempEnc[i]));
            }
            else {
                publicKeyAlgAndEncodings = undefined;
            }
            let attestationTypes;
            let tempAttType = V3toV2.convertAttestationTypes(m.attestationTypes)
            if (tempAttType != undefined)
                attestationTypes = Array.from(tempAttType);

            let userVerificationDetails = Array();
            for (let i = 0; i < m.userVerificationDetails.length; i++) {
                userVerificationDetails.push(m.userVerificationDetails[i])
                if (!(m.userVerificationDetails[i])) {
                    for (let l = 0; l < m.userVerificationDetails[i].data.length; l++) {
                        let numEX = m.userVerificationDetails[i].data[l].userVerification
                        userVerificationDetails[i].data[l].userVerification = V3toV2.convertUserVerificationDetails(m.userVerificationDetails[i].data[l].userVerification)
                    }
                }
            }

            let keyProtection = V3toV2.convertKeyProtection(m.keyProtection)
            let isKeyRestricted = m.isKeyRestricted != undefined ? m.isKeyRestricted : true;
            let isFreshUserVerificationRequired = m.isFreshUserVerificationRequired != undefined ? m.isFreshUserVerificationRequired : true;
            let matcherProtection = V3toV2.convertMatcherProtection(m.matcherProtection);
            let cryptoStrength = V3toV2.convertCryptoStrength(m.cryptoStrength);
            let operatingEnv = V3toV2.convertOperatingEnv();
            let attachmentHint = V3toV2.convertAttachmentHint(m.attachmentHint);
            let isSecondFactorOnly = V3toV2.convertIsSecondFactorOnly(undefined);
            if (m.authenticatorGetInfo != undefined) {
                if (m.authenticatorGetInfo.options != undefined) {
                    if (m.authenticatorGetInfo.options.uv != undefined) {
                        isSecondFactorOnly = V3toV2.convertIsSecondFactorOnly(m.authenticatorGetInfo.options.uv)
                    }
                }
            }
            let tcDisplay;
            if (m.tcDisplay != undefined)
                tcDisplay = V3toV2.convertTcDisplay(m.tcDisplay);
            else
                tcDisplay = undefined;
            let tcDisplayContentType = m.tcDisplayContentType != undefined ? m.tcDisplayContentType : undefined;
            let tcDisplayPNGCharacteristics: TcDisplayPNGCharacteristicsDescriptor[] | undefined = m.tcDisplayPNGCharacteristics != undefined ? Array.from(m.tcDisplayPNGCharacteristics) : undefined;
            let attestationRootCertificates: string[] = Array.from(m.attestationRootCertificates);
            let ecdaaTrustAnchors: ECDAATrustAnchor[] | undefined = m.ecdaaTrustAnchors != undefined ? Array.from(m.ecdaaTrustAnchors) : undefined;
            let icon: string | undefined = m.icon != undefined ? m.icon : undefined;
            let supportedExtensions: ExtensionDescriptor[] | undefined = m.supportedExtensions != undefined ? Array.from(m.supportedExtensions) : undefined;
            result = new metadataKeysV2(description, authenticatorVersion, upv, assertionScheme, authenticationAlgorithm != undefined ? authenticationAlgorithm : 0, publicKeyAlgAndEncoding != undefined ? publicKeyAlgAndEncoding : 0,
                attestationTypes != undefined ? attestationTypes : new Array(), userVerificationDetails, isSecondFactorOnly, keyProtection != undefined ? keyProtection : 0, matcherProtection != undefined ? matcherProtection : 0,
                cryptoStrength != undefined ? cryptoStrength : 0, attachmentHint != undefined ? attachmentHint : 0, tcDisplay != undefined ? tcDisplay : 0, attestationRootCertificates, legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers,
                alternativeDescriptions, protocolFamily, authenticationAlgorithms != undefined ? authenticationAlgorithms : undefined, publicKeyAlgAndEncodings != undefined ? publicKeyAlgAndEncodings : undefined, isKeyRestricted, isFreshUserVerificationRequired, operatingEnv, tcDisplayContentType,
                tcDisplayPNGCharacteristics, ecdaaTrustAnchors, icon, supportedExtensions);
        }
        return result;
    }

    //funzione validazione singolo campo
    //attenzione, lo switch deve corrispondere all'enum
    public validateData(str: string): boolean {
        console.debug("validateData of " + str + " use code case:" + V3FunctionName[str as keyof typeof V3FunctionName])
        switch (V3FunctionName[str as keyof typeof V3FunctionName]) {
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
    public validateAll(): boolean {
        if (this.aaidCheck() && this.aaguidCheck() && this.attestationCertificateKeyIdentifiersCheck() && this.authenticatorVersionCheck() &&
            this.protocolFamilyCheck() && this.schemaCheck() && this.upvCheck() &&
            this.authenticationAlgorithmsCheck() &&
            this.publicKeyAlgAndEncodingsCheck() && this.attestationTypesCheck() && this.userVerificationDetailsCheck() &&
            this.keyProtectionCheck() && this.matcherProtectionCheck() && this.cryptoStrengthCeck() &&
            this.attachmentHintCheck() && this.tcDisplayCheck() && this.tcDisplayContentTypeCheck() &&
            this.tcDisplayPNGCharacteristicsCheck() && this.attestationRootCertificatesCheck() && this.ecdaaTrustAnchorsCheck() && this.iconCheck()
            //&& this.supportedExtensionsCheck()
            && this.authenticatorGetInfoCheck()
        ) {
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
    private aaidCheck(): boolean {
        if (this.protocolFamily == "uaf" && this.aaid == undefined)
            throw new MetadataKeyError("Errore valore aaid");
        //no distinzione upper-lower case
        if (this.aaid != undefined && (!RegExp(/^[0-9A-F]{4}#[0-9A-F]{4}$/i).test(this.aaid) || this.protocolFamily == "fido2"))
            throw new MetadataKeyError("Errore valore aaid")
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso protocol family sia settato su "fido2"
     *          2) per questioni di compatibilità il campo aaguid non può essere presente se protocol family è settato su "uaf"
     *          3) che la stringa, se presente sia conforme a quanto ricavato qui: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#fido2-example  
     */
    private aaguidCheck(): boolean {
        if ((this.protocolFamily == "fido2" && this.aaguid == undefined) || (this.protocolFamily == "uaf" && this.aaguid != undefined))
            throw new MetadataKeyError("Errore valore aaguid")
        if (this.aaguid != undefined) {
            if (this.aaguid.length != 36 || (this.aaguid.length == 36 && !RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i).test(this.aaguid)))
                throw new MetadataKeyError("Errore valore aaguid")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) campo codificato con stringa esadecimale con tutte le lettere devono esserte in lowercase
     */
    private attestationCertificateKeyIdentifiersCheck(): boolean {
        if (this.attestationCertificateKeyIdentifiers != undefined) {
            for (let i = 0; i < this.attestationCertificateKeyIdentifiers.length; i++) {
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
    private authenticatorVersionCheck(): boolean {
        if (this.authenticatorVersion < 0 || this.authenticatorVersion > 4294967295)
            throw new MetadataKeyError("Errore valore authenticatorVersion")
        if (this.authenticatorGetInfo != undefined && (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.firmwareVersion != undefined && this.authenticatorGetInfo.firmwareVersion != this.authenticatorVersion))
            throw new MetadataKeyError("Errore valore authenticatorVersion")
        return true;
    }

    /**
     * Controlli:
     *          1) che campo sia una delle seguenti stringhe "uaf", "u2f", e "fido2"
     *          2) controllo corrispondenza con campo "version" di authenticatorgetinfo
     */
    private protocolFamilyCheck(): boolean {
        if (this.protocolFamily == undefined)
            throw new MetadataKeyError("Errore valore protocolFamily")
        if (protocolFamilyEnum[this.protocolFamily as keyof typeof protocolFamilyEnum] == undefined)
            throw new MetadataKeyError("Errore valore protocolFamily")
        if (this.authenticatorGetInfo != undefined && this.authenticatorGetInfo.version != undefined) {
            if (this.protocolFamily == "fido2" && (this.authenticatorGetInfo.version.find(element => element == "FIDO_2_1") == undefined &&
                this.authenticatorGetInfo.version.find(element => element == "FIDO_2_0") == undefined &&
                this.authenticatorGetInfo.version.find(element => element == "FIDO_2_1_PRE") == undefined))
                throw new MetadataKeyError("Errore valore protocolFamily")
            if (this.protocolFamily == "u2f" && (this.authenticatorGetInfo.version.find(element => element == "U2F_V2") == undefined))
                throw new MetadataKeyError("Errore valore protocolFamily")
        }
        return true;
    }

    /**
     * Conrtolli:
     *          1) essendo il campo unsigned short:  0 <= authenticatorVersion <= 65.535
     */
    private schemaCheck(): boolean {
        if (this.schema < 0 || this.schema > 65535)
            throw new MetadataKeyError("Errore valore Schema");
        return true;
    }

    /**
     * Controlli: 
     *          1) che i campi di Version siano unsigned short: 0 <= Campi Version upv <= 65.535
     *          2) controlli specifici non effettuati sulla versione nei casi UAF, U2F e FIDO2/CTAP2
     */
    private upvCheck() {
        for (let i = 0; i < this.upv.length; i++) {
            if (this.upv[i].major < 0 || this.upv[i].major > 65535 || this.upv[i].minor < 0 || this.upv[i].minor > 65535)
                throw new MetadataKeyError("Errore valore upv in posizione: " + i + ". ")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi corrispondano ad un algoritmo valido
     *          2) che nel caso si usi u2f l'algoritmo utilizzato non sia altro che secp256r1_ecdsa_sha256_raw
     */
    private authenticationAlgorithmsCheck(): boolean {
        if (this.authenticationAlgorithms != undefined) {
            for (let i = 0; i < this.authenticationAlgorithms.length; i++) {
                if (authenticationAlgorithmsEnum[this.authenticationAlgorithms[i] as keyof typeof authenticationAlgorithmsEnum] == undefined)
                    throw new MetadataKeyError("Errore valore authenticationAlgorithms in posizione: " + i + ". ")
                if (this.protocolFamily == "u2f" && this.authenticationAlgorithms[i] != "secp256r1_ecdsa_sha256_raw")
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
    private publicKeyAlgAndEncodingsCheck(): boolean {
        if (this.publicKeyAlgAndEncodings != undefined) {
            for (let i = 0; i < this.publicKeyAlgAndEncodings.length; i++) {
                if (publicKeyAlgAndEncodingsEnum[this.publicKeyAlgAndEncodings[i] as keyof typeof publicKeyAlgAndEncodingsEnum] == undefined) {
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")
                }
                if (this.protocolFamily == "u2f" && this.publicKeyAlgAndEncodings[i] != "ecc_x962_raw") {
                    throw new MetadataKeyError("Errore valore publicKeyAlgAndEncodings in posizione: " + i + ". ")
                }
            }
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che i campi stringa siano basic_full, basic_surrogate, ecdaa oppure attca
     */
    private attestationTypesCheck(): boolean {
        for (let i = 0; i < this.attestationTypes.length; i++) {
            if (attestationTypesEnum[this.attestationTypes[i] as keyof typeof attestationTypesEnum] == undefined)
                throw new MetadataKeyError("Errore valore attestationTypes")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica conformità campo userVerification di VerificationMethodDescriptor (https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
     */
    private userVerificationDetailsCheck(): boolean {
        for (let i = 0; i < this.userVerificationDetails.length; i++) {
            if (!(this.userVerificationDetails[i])) {
                for (let l = 0; l < this.userVerificationDetails[i].data.length; l++) {
                    if (!this.userVerificationDetails[i].data[l].validateInternalData())
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
    private keyProtectionCheck(): boolean {
        for (let i = 0; i < this.keyProtection.length; i++) {
            if (keyProtectionEnum[this.keyProtection[i] as keyof typeof keyProtectionEnum] == undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
        }

        if (this.keyProtection.find(element => element == "software") != undefined) {
            if (this.keyProtection.find(element => element == "hardware") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
            if (this.keyProtection.find(element => element == "tee") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
            if (this.keyProtection.find(element => element == "secure_element") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
        }

        if (this.keyProtection.find(element => element == "tee") != undefined) {
            if (this.keyProtection.find(element => element == "secure_element") != undefined)
                throw new MetadataKeyError("Errore valore keyProtection")
        }

        //(remote_handle) MUST be set in conjunction with one of the other KEY_PROTECTION flags 
        if (this.keyProtection.find(element => element == "remote_handle") != undefined) {
            if (this.keyProtection.find(element => element != "remote_handle") == undefined)
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
    private matcherProtectionCheck(): boolean {
        for (let i = 0; i < this.matcherProtection.length; i++) {
            if (matcherProtectionEnum[this.matcherProtection[i] as keyof typeof matcherProtectionEnum] == undefined)
                throw new MetadataKeyError("Errore valore matcherProtection")
        }
        if (this.matcherProtection.find(element => element == "software") != undefined) {
            if (this.matcherProtection.find(element => element == "tee") != undefined || this.matcherProtection.find(element => element == "on_chip") != undefined)
                throw new MetadataKeyError("Errore valore matcherProtection")
        }
        if (this.matcherProtection.find(element => element == "tee") != undefined) {
            if (this.matcherProtection.find(element => element == "on_chip") != undefined)
                throw new MetadataKeyError("Errore valore matcherProtection")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) Verifica campo sia unsigned short
     */
    private cryptoStrengthCeck(): boolean {
        if (this.cryptoStrength != undefined) {
            if (this.cryptoStrength < 0 || this.cryptoStrength > 65535)
                throw new MetadataKeyError("Errore valore cryptoStrength")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo number presenti i valori corretti
     */
    private attachmentHintCheck(): boolean {
        for (let i = 0; i < this.attachmentHint.length; i++) {
            if (attachmentHintEnum[this.attachmentHint[i] as keyof typeof attachmentHintEnum] == undefined)
                throw new MetadataKeyError("Errore valore attachmentHint")
        }
        //se c'è elemento internal insieme ad un altro elemento differente --> errore
        if (this.attachmentHint.find(element => element == "internal") != undefined) {
            if (this.attachmentHint.find(element => element != "internal") != undefined)
                throw new MetadataKeyError("Errore valore attachmentHint")
        }
        //se si ha elemento external senza altri elementi si ha errore (il controllo su internal non è stato fatto in quanto fatto dall'if precedente)
        if (this.attachmentHint.find(element => element == "external") != undefined) {
            if (this.attachmentHint.find(element => element != "external") == undefined)
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
    private tcDisplayCheck(): boolean {
        if (this.tcDisplay != undefined) {
            for (let i = 0; i < this.tcDisplay.length; i++) {
                if (tcDisplayEnum[this.tcDisplay[i] as keyof typeof tcDisplayEnum] == undefined)
                    throw new MetadataKeyError("Errore valore tcDisplay")
            }
            if (this.tcDisplay.find(element => element == "privileged_software") != undefined) {
                if (this.tcDisplay.find(element => element == "tee") != undefined || this.tcDisplay.find(element => element == "hardware") != undefined)
                    throw new MetadataKeyError("Errore valore tcDisplay")
            }
            if (this.tcDisplay.find(element => element == "tee") != undefined) {
                if (this.tcDisplay.find(element => element == "hardware") != undefined)
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
    private tcDisplayContentTypeCheck(): boolean {
        if ((this.tcDisplay != undefined && this.tcDisplay.length >= 1) && this.tcDisplayContentType == undefined)
            throw new MetadataKeyError("Errore valore tcDisplayContentType")

        if (this.tcDisplayContentType != undefined && (this.tcDisplay != undefined && this.tcDisplay.length >= 1)) {
            if (tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == undefined)
                throw new MetadataKeyError("Errore valore tcDisplayContentType")
        }
        return true;
    }

    /**
     * Controlli:
     *          1) che il campo sia presente nel caso lo siano anche tcDisplay (non undefined) e tcDisplayContentType (deve essere image/png)
     */
    private tcDisplayPNGCharacteristicsCheck(): boolean { //(seconda parte: se variabile tcDisplayContentType è image/png)
        if (this.tcDisplay != undefined && tcDisplayContentTypeEnum[this.tcDisplayContentType as keyof typeof tcDisplayContentTypeEnum] == tcDisplayContentTypeEnum["image/png" as keyof typeof tcDisplayContentTypeEnum] && this.tcDisplayPNGCharacteristics == undefined)
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
                if (this.aaid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.1") != undefined)
                    throw new MetadataKeyError("Errore valore attestationRootCertificates in posizione: " + i + ". ")
                // id-fido-gen-ce-aaguid { 1 3 6 1 4 1 45724 1 1 4 } or - when neither AAID nor AAGUID are defined -
                if (this.aaguid != undefined && testCert.keyUsage != undefined && testCert.keyUsage.find(element => element == "1.3.6.1.4.1.45724.1.1.4") != undefined)
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
    private ecdaaTrustAnchorsCheck(): boolean {
        let temp: string | undefined = this.attestationTypes.find(element => element == "ecdaa");
        if (temp != undefined && this.ecdaaTrustAnchors == undefined || temp == undefined && this.ecdaaTrustAnchors != undefined)
            throw new MetadataKeyError("Errore valore ecdaaTrustAnchors")

        if (this.ecdaaTrustAnchors != undefined) {
            for (let i = 0; i < this.ecdaaTrustAnchors.length; i++) {
                if (!this.ecdaaTrustAnchors[i].validateInternalData())
                    throw new MetadataKeyError("Errore valore ecdaaTrustAnchors in posizione: " + i + ". ")
            }
        }
        return true;
    }

    /**
     * Controlli: 
     *          1) formato con cui sono inserite le immagini tramite regular expression
     */
    private iconCheck(): boolean {
        if (this.icon != undefined) {
            let temp = this.icon.replace(this.icon.substring(this.icon.indexOf("data:"), this.icon.indexOf("base64") + 7), "");
            if (!RegExp(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/).test(temp)) {
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
    private authenticatorGetInfoCheck(): boolean {
        console.debug("This is Mv3 @705 authenticatorGetInfoCheck\tTHIS:", this)
        console.debug("This is Mv3 @705 authenticatorGetInfoCheck\tAGI: ", this.authenticatorGetInfo)
        if (this.authenticatorGetInfo !== undefined) {
            return this.authenticatorGetInfo.validateInternalData();
        }
        // FIXME: not sure if this should be throwing an exception or returning a false
        return false
    }
}