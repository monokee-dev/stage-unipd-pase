//controlli da fare
export class AuthenticatorOption {
    constructor(p: boolean = false, r: boolean = false, c: boolean | null = null, up: boolean = true, uv: boolean | null = null,
        uvT?: boolean, no?: boolean, la?: boolean, ep?: boolean, bio?: boolean, user?: boolean, uvBio?: boolean, auth?: boolean, uva?: boolean,
        cred?: boolean, crede?: boolean, setM?: boolean, make?: boolean, alw?: boolean) {
        this.plat = p;
        this.rk = r;
        this.clientPin = c;
        this.up = up;
        this.uv = uv;
        this.pinUvAuthToken = uvT;
        this.noMcGaPermissionsWithClientPin = no;
        this.largeBlobs = la;
        this.ep = ep;
        this.bioEnroll = bio;
        this.userVerificationMgmtPreview = user;
        this.uvBioEnroll = uvBio;
        this.authnrCfg = auth;
        this.uvAcfg = uva;
        this.credMgmt = cred;
        this.credentialMgmtPreview = crede;
        this.setMinPINLength = setM;
        this.makeCredUvNotRqd = make;
        this.alwaysUv = alw;
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