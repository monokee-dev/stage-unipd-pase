import { application } from "express";

export function attestationTypesConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return attestationTypesEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in attestationTypesEnumMap){
            if(iter === x){
                return attestationTypesEnumMap[iter];
            }
        }
        return undefined;
    }
}

export function userVerificationDetailsConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return userVerificationDetailsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in userVerificationDetailsEnumMap){
            if(iter === x){
                return userVerificationDetailsEnumMap[iter];
            }
        }
        return undefined;
    }
}

export function keyProtectionConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return keyProtectionEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in keyProtectionEnumMap){
            if(iter === x){
                return keyProtectionEnumMap[iter];
            }
        }
        return undefined;
    }
}


export function matcherProtectionConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return matcherProtectionEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in matcherProtectionEnumMap){
            if(iter === x){
                return matcherProtectionEnumMap[iter];
            }
        }
        return undefined;
    }
}

export function attachmentHintConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return attachmentHintEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in attachmentHintEnumMap){
            if(iter === x){
                return attachmentHintEnumMap[iter];
            }
        }
        return undefined;
    }
}

export function tcDisplayConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return tcDisplayEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in tcDisplayEnumMap){
            if(iter === x){
                return tcDisplayEnumMap[iter];
            }
        }
        return undefined;
    }
}


export function authenticationAlgorithmsConverter(x: number | string): number | string | undefined{
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return authenticationAlgorithmsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in authenticationAlgorithmsEnumMap){
            if(iter === x){
                return authenticationAlgorithmsEnumMap[iter];
            }
        }
        return undefined;
    }
}

export function publicKeyAlgAndEncodingsConverter(x: number | string): number | string | undefined {
    //controllo tipo: se number si ritorna il nome dell'algoritmo
    if(typeof x === "number"){
        return publicKeyAlgAndEncodingsEnumMap[x];
    }
    //se stringa si ritorna il valore numerico
    else if(typeof x === "string"){
        for(var iter in publicKeyAlgAndEncodingsEnumMap){
            if(iter === x){
                return publicKeyAlgAndEncodingsEnumMap[iter];
            }
        }
        return undefined;
    }
}

enum attestationTypesEnumMap{
    "basic_full" = 15879,
    "basic_surrogate" = 15880,
    "ecdaa" = 15881,
    "attca" = 15882,
}

enum userVerificationDetailsEnumMap{
    "presence_internal" = 1,
    "fingerprint_internal" = 2,
    "passcode_internal" = 4,
    "voiceprint_internal" = 8,
    "faceprint_internal" = 16,
    "location_internal" = 32,
    "eyeprint_internal" = 64,
    "pattern_internal" = 128,
    "handprint_internal" = 256,
    "none" = 512,
    "all" = 1024,
    "passcode_external" = 2048,
    "pattern_external" = 4096,
}

enum keyProtectionEnumMap{
    "software" = 1,
    "hardware" = 2,
    "tee" = 4,
    "secure_element" = 8,
    "remote_handle" = 16,
}

enum matcherProtectionEnumMap{
    "software" = 1,
    "tee" = 2,
    "on_chip" = 4,
}

enum attachmentHintEnumMap{
    "internal" = 1,
    "external" = 2,
    "wired" = 4,
    "wireless" = 8,
    "nfc" = 16,
    "bluetooth" = 32,
    "network" = 64,
    "ready" = 128,
    "wifi_direct" = 256,
}

enum tcDisplayEnumMap{
    "any" = 1,
    "privileged_software" = 2,
    "tee" = 4,
    "hardware" = 8,
    "remote" = 16,
}

enum authenticationAlgorithmsEnumMap{
    "secp256r1_ecdsa_sha256_raw" = 1,
    "secp256r1_ecdsa_sha256_der" = 2,
    "rsassa_pss_sha256_raw" = 3,
    "rsassa_pss_sha256_der" = 4,
    "esecp256k1_ecdsa_sha256_raw" = 5,
    "secp256k1_ecdsa_sha256_der" = 6,
    "sm2_sm3_raw" = 7,
    "rsa_emsa_pkcs1_sha256_raw" = 8,
    "rsa_emsa_pkcs1_sha256_der" = 9,
    "rsassa_pss_sha384_raw" = 10,
    "rsassa_pss_sha512_raw" = 11,
    "rsassa_pkcsv15_sha256_raw" = 12,
    "rsassa_pkcsv15_sha384_raw" = 13,
    "rsassa_pkcsv15_sha512_raw" = 14,
    "rsassa_pkcsv15_sha1_raw" = 15,
    "secp384r1_ecdsa_sha384_raw" = 16,
    "secp512r1_ecdsa_sha256_raw" = 17,
    "ed25519_eddsa_sha512_raw" = 18,
}

enum publicKeyAlgAndEncodingsEnumMap{
    "ecc_x962_raw" = 256,
    "ecc_x962_der" = 257,
    "rsa_2048_raw" = 258,
    "rsa_2048_der" = 259,
    "cose" = 260,
}