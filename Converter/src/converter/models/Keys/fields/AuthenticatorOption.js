"use strict";
exports.__esModule = true;
exports.AuthenticatorOption = void 0;
//controlli da fare
var AuthenticatorOption = /** @class */ (function () {
    function AuthenticatorOption(p, r, c, up, uv, uvT, no, la, ep, bio, user, uvBio, auth, uva, cred, crede, setM, make, alw) {
        if (p === void 0) { p = false; }
        if (r === void 0) { r = false; }
        if (c === void 0) { c = null; }
        if (up === void 0) { up = true; }
        if (uv === void 0) { uv = null; }
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
    return AuthenticatorOption;
}());
exports.AuthenticatorOption = AuthenticatorOption;
