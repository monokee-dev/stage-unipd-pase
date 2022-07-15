export class AlgorithmAuthenticatorGetInfo {
    constructor(type: string, alg: number) {
        this.type = type;
        this.alg = alg;
    }
    public type: string;
    public alg: number;
}