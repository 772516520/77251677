import {createECDH} from "crypto";
import Utils from "./utils";

const CMC_PUBLIC_KEY = Buffer.from("04EBCA94D733E399B2DB96EACDD3F69A8BB0F74224E2B44E3357812211D2E62EFBC91BB553098E25E33A799ADC7F76FEB208DA7C6522CDB0719A305180CC54A82E", "hex");
/** 伤心了 为什么我的key就不行 */
// const CMC_PUBLIC_KEY = Buffer.from("04EA36207EDC67333D0E89BC6DAB81AEC0C6413AA230799ECC215A5648570CFBBC663D66CB710F3385D012F4E59E014F9C305DFC384DED5A7566E08D17A0E40D7A", "hex");

export default class Ecdh {
    private ecdh = createECDH("prime256v1");
    public public_key = this.ecdh.generateKeys();
    public share_key = Utils.md5(this.ecdh.computeSecret(CMC_PUBLIC_KEY).slice(0, 16));
}