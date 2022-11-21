import BaseClient from "./core/BaseClient";
import {Platform} from "./core/device";
import Utils from "./core/utils";

export class Client extends BaseClient {
    public uin: number;
    public platform: Platform;

    constructor(uin: number, platform: Platform) {
        super(uin, platform);
        this.uin = uin;
        this.platform = platform;
    }

    public login(password?: string | Buffer): void {
        let p: Buffer;
        if (typeof password === "string")
            p = password;
        else
            p = Buffer.alloc(16);
        if (p.length !== 16) {
            p = Utils.md5(p);
        }
        this.passwordLogin(p);
    }

    public sendSMSCode() {
        return this.sendSmsCode();
    }

    public submitSMSCoded(code: string) {
        return this.submitSmsCode(code);
    }
}