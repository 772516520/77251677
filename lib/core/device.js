"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getApklist = exports.Platform = void 0;
const utils_1 = __importDefault(require("./utils"));
const crypto_1 = require("crypto");
const Android = {
    id: "com.tencent.mobileqq",
    name: "A8.8.80.7400",
    version: "A8.8.90.83e6c009",
    ver: "8.8.80",
    sign: Buffer.from([166, 183, 45, 191, 24, 162, 194, 77, 52, 77, 16, 246, 243, 110, 182, 141]),
    buildtime: 1652271523,
    appid: 16,
    subid: 537119623,
    bitmap: 184024956,
    sdkver: "6.0.0.2508",
    sigmap: 34869472,
    display: "Android"
};
const hd = {
    id: "com.tencent.minihd.qq",
    name: "A8.8.80.7400",
    version: "A8.8.90.83e6c009",
    ver: "8.8.80",
    sign: Buffer.from([170, 57, 120, 244, 31, 217, 111, 249, 145, 74, 102, 158, 24, 100, 116, 199]),
    buildtime: 1637427966,
    appid: 16,
    subid: 537067382,
    bitmap: 150470524,
    sigmap: 1970400,
    sdkver: "6.0.0.2508",
    display: "aPad",
};
var Platform;
(function (Platform) {
    Platform[Platform["Android"] = 0] = "Android";
    Platform[Platform["aPad"] = 1] = "aPad";
    Platform[Platform["iPad"] = 2] = "iPad";
})(Platform = exports.Platform || (exports.Platform = {}));
const apklist = {
    [Platform.Android]: Android,
    [Platform.aPad]: hd,
    [Platform.iPad]: { ...hd }
};
apklist[Platform.iPad].subid = 537118796;
apklist[Platform.iPad].display = "iPad";
function getApklist(p) {
    return apklist[p];
}
exports.getApklist = getApklist;
class GenerateDevice {
    /** 生成设备信息 */
    static generateShortDevice(uin) {
        const hash = utils_1.default.md5(String(uin));
        const hex = hash.toString("hex");
        return {
            "--begin--": "该设备由账号作为seed固定生成，账号不变则永远相同",
            product: "CMC520",
            device: "LOVEWYC520",
            board: "WYC-YYDS",
            brand: "CMC",
            model: "ILOVE WYC",
            wifi_ssid: `TP-LINK-${uin.toString(16)}`,
            bootloader: "U-boot",
            android_id: `CMC.${hash.readUInt16BE()}${hash[2]}.${hash[3]}${String(uin)[0]}`,
            boot_id: hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" + hex.substr(20),
            proc_version: `Linux version 4.19.71-${hash.readUInt16BE(4)} (77251677.github.com)`,
            mac_address: `00:50:${hash[6].toString(16).toUpperCase()}:${hash[7].toString(16).toUpperCase()}:${hash[8].toString(16).toUpperCase()}:${hash[9].toString(16).toUpperCase()}`,
            ip_address: `10.0.${hash[10]}.${hash[11]}`,
            imei: this.generateImei(uin),
            incremental: hash.readUInt32BE(12),
            "--end--": "修改后可能需要重新验证设备",
        };
    }
    static generateFullDevice(d) {
        if (typeof d === "number")
            d = this.generateShortDevice(d);
        return {
            display: d.android_id,
            product: d.product,
            device: d.device,
            board: d.board,
            brand: d.brand,
            model: d.model,
            bootloader: d.bootloader,
            fingerprint: `${d.brand}/${d.product}/${d.device}:10/${d.android_id}/${d.incremental}:user/release-keys`,
            boot_id: d.boot_id,
            proc_version: d.proc_version,
            baseband: "",
            sim: "T-Mobile",
            os_type: "android",
            mac_address: d.mac_address,
            ip_address: d.ip_address,
            wifi_bssid: d.mac_address,
            wifi_ssid: d.wifi_ssid,
            imei: d.imei,
            android_id: d.android_id,
            apn: "wifi",
            version: {
                incremental: d.incremental,
                release: "10",
                codename: "REL",
                sdk: 29,
            },
            imsi: (0, crypto_1.randomBytes)(16),
            guid: utils_1.default.md5(Buffer.concat([Buffer.from(d.imei), Buffer.from(d.mac_address)])),
        };
    }
    static generateImei(uin) {
        let imei = uin % 2 ? "52" : "77";
        const buf = Buffer.alloc(4);
        buf.writeUint32BE(uin);
        let a = buf.readUInt16BE();
        let b = Buffer.concat([Buffer.alloc(1), buf.slice(1)]).readUInt32BE();
        if (a > 9999)
            a = Math.trunc(a / 10);
        else if (a < 1000)
            a = String(uin).slice(0, 5);
        while (b > 9999999)
            b = b >>> 1;
        if (b < 1000000)
            b = String(uin).slice(0, 5);
        imei += a + "0" + b;
        function calcSP(imei) {
            let sum = 0;
            for (let i = 0; i < imei.length; ++i) {
                if (i % 2) {
                    const j = parseInt(imei[i]) * 2;
                    sum += j * 10 + Math.trunc(j / 10);
                }
                else
                    sum += parseInt(imei[i]);
            }
            return Math.abs((100 - sum) % 10);
        }
        return imei + calcSP(imei);
    }
}
exports.default = GenerateDevice;
