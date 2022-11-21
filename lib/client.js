"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Client = void 0;
const BaseClient_1 = __importDefault(require("./core/BaseClient"));
const utils_1 = __importDefault(require("./core/utils"));
class Client extends BaseClient_1.default {
    uin;
    platform;
    constructor(uin, platform) {
        super(uin, platform);
        this.uin = uin;
        this.platform = platform;
    }
    login(password) {
        let p;
        if (typeof password === "string")
            p = password;
        else
            p = Buffer.alloc(16);
        if (p.length !== 16) {
            p = utils_1.default.md5(p);
        }
        this.passwordLogin(p);
    }
    sendSMSCode() {
        return this.sendSmsCode();
    }
    submitSMSCoded(code) {
        return this.submitSmsCode(code);
    }
}
exports.Client = Client;
