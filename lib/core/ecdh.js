"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const utils_1 = __importDefault(require("./utils"));
const CMC_PUBLIC_KEY = Buffer.from("04EBCA94D733E399B2DB96EACDD3F69A8BB0F74224E2B44E3357812211D2E62EFBC91BB553098E25E33A799ADC7F76FEB208DA7C6522CDB0719A305180CC54A82E", "hex");
/** 伤心了 为什么我的key就不行 */
// const CMC_PUBLIC_KEY = Buffer.from("04EA36207EDC67333D0E89BC6DAB81AEC0C6413AA230799ECC215A5648570CFBBC663D66CB710F3385D012F4E59E014F9C305DFC384DED5A7566E08D17A0E40D7A", "hex");
class Ecdh {
    ecdh = (0, crypto_1.createECDH)("prime256v1");
    public_key = this.ecdh.generateKeys();
    share_key = utils_1.default.md5(this.ecdh.computeSecret(CMC_PUBLIC_KEY).slice(0, 16));
}
exports.default = Ecdh;
