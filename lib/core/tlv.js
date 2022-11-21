"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPacker = exports.packTlv = void 0;
const crypto_1 = require("crypto");
const writer_1 = __importDefault(require("./writer"));
const tea_1 = require("./tea");
const pb = __importStar(require("./protobuf"));
const utils_1 = __importDefault(require("./utils"));
const writer_2 = __importDefault(require("./writer"));
const packTlv = function (tag, ...args) {
    const t = tlvmap[tag].apply(this, args);
    const lbuf = Buffer.alloc(2);
    lbuf.writeUInt16BE(t.readableLength);
    t.unshift(lbuf);
    const tbuf = Buffer.alloc(2);
    tbuf.writeUInt16BE(tag);
    t.unshift(tbuf);
    return t.read();
};
exports.packTlv = packTlv;
const tlvmap = {
    0x01: function () {
        return new writer_1.default()
            .writeU16(1)
            .writeBytes((0, crypto_1.randomBytes)(4))
            .writeU32(this.uin)
            .writeU32(Date.now() & 0xffffffff)
            .writeU16(0)
            .writeU16(0)
            .writeU16(0);
    },
    0x08: function () {
        return new writer_1.default()
            .writeU16(0)
            .writeU32(2502)
            .writeU16(0);
    },
    0x18: function () {
        return new writer_1.default()
            .writeU16(1)
            .writeU32(1536)
            .writeU8(this.apk.appid)
            .writeU32(0)
            .writeU32(this.uin)
            .writeU16(0)
            .writeU16(0);
    },
    0x100: function () {
        return new writer_1.default()
            .writeU16(1)
            .writeU32(7) // dont over 7
            .writeU32(this.apk.appid)
            .writeU32(this.apk.subid)
            .writeU32(0)
            .writeU32(this.apk.sigmap);
    },
    0x104: function () {
        return new writer_1.default().writeBytes(this.sig.t104);
    },
    0x106: function (md5pass) {
        const body = new writer_1.default()
            .writeU16(4)
            .writeBytes((0, crypto_1.randomBytes)(4))
            .writeU32(7) // sso ver
            .writeU32(this.apk.appid) // apk.appid
            .writeU32(0)
            .writeU64(this.uin)
            .writeU32(Date.now() & 0xffffffff)
            .writeBytes(Buffer.alloc(4))
            .writeU8(1)
            .writeBytes(md5pass)
            .writeBytes(this.sig.tgtgt) // tgtgt rand 16bytes
            .writeU32(0)
            .writeU8(1)
            .writeBytes(this.device.guid) // guid
            .writeU32(this.apk.subid)
            .writeU32(1)
            .writeTlv(String(this.uin))
            .writeU16(0)
            .read();
        const buf = Buffer.alloc(4);
        buf.writeUint32BE(this.uin);
        const key = utils_1.default.md5(Buffer.concat([md5pass, Buffer.alloc(4), buf]));
        return new writer_1.default().writeBytes((0, tea_1.encrypt)(body, key));
    },
    0x107: function () {
        return new writer_1.default()
            .writeU16(0)
            .writeU8(0)
            .writeU16(0)
            .writeU16(1);
    },
    0x109: function () {
        return new writer_1.default()
            .writeBytes(utils_1.default.md5(this.device.imei));
    },
    0x116: function () {
        return new writer_1.default()
            .writeU8(0)
            .writeU32(this.apk.bitmap) // apk.bitmap
            .writeU32(0x10400)
            .writeU8(1)
            .writeU32(1600000226);
    },
    0x124: function () {
        return new writer_1.default()
            .writeTlv(this.device.os_type)
            .writeTlv(this.device.version.release)
            .writeU16(2)
            .writeTlv(this.device.sim)
            .writeU16(0)
            .writeTlv(this.device.apn);
    },
    0x128: function () {
        return new writer_1.default()
            .writeU16(0)
            .writeU8(0)
            .writeU8(1)
            .writeU8(0)
            .writeU32(16777216)
            .writeTlv(this.device.device.slice(0, 32))
            .writeTlv(this.device.guid.slice(0, 16))
            .writeTlv(this.device.brand.slice(0, 16));
    },
    0x141: function () {
        return new writer_1.default()
            .writeU16(1)
            .writeTlv(this.device.sim)
            .writeU16(2)
            .writeTlv(this.device.apn);
    },
    0x142: function () {
        return new writer_2.default()
            .writeU16(0)
            .writeTlv(this.apk.id.slice(0, 32));
    },
    0x144: function () {
        const body = new writer_1.default()
            .writeU16(5)
            .writeBytes(exports.packTlv.call(this, 0x109))
            .writeBytes(exports.packTlv.call(this, 0x52d))
            .writeBytes(exports.packTlv.call(this, 0x124))
            .writeBytes(exports.packTlv.call(this, 0x128))
            .writeBytes(exports.packTlv.call(this, 0x16e))
            .read();
        return new writer_1.default().writeBytes((0, tea_1.encrypt)(body, this.sig.tgtgt));
    },
    0x145: function () {
        return new writer_1.default()
            .writeBytes(this.device.guid);
    },
    0x147: function () {
        return new writer_1.default()
            .writeU32(this.apk.appid)
            .writeTlv(this.apk.ver.slice(0, 5))
            .writeTlv(this.apk.sign);
    },
    0x154: function () {
        return new writer_1.default()
            .writeU32(this.sig.seq + 1);
    },
    0x16e: function () {
        return new writer_1.default()
            .writeBytes(this.device.model);
    },
    0x174: function () {
        return new writer_1.default().writeBytes(this.sig.t174);
    },
    0x177: function () {
        return new writer_1.default()
            .writeU8(1)
            .writeU32(this.apk.buildtime)
            .writeTlv(this.apk.sdkver);
    },
    0x17a: function () {
        return new writer_1.default()
            .writeU32(9);
    },
    0x17c: function (code) {
        return new writer_1.default().writeTlv(code);
    },
    0x187: function () {
        return new writer_1.default()
            .writeTlv(utils_1.default.md5(this.device.mac_address));
    },
    0x188: function () {
        return new writer_1.default()
            .writeTlv(utils_1.default.md5(this.device.android_id));
    },
    0x191: function () {
        return new writer_1.default()
            .writeU8(0x82);
    },
    0x193: function (ticket) {
        return new writer_1.default().writeBytes(ticket);
    },
    0x194: function () {
        return new writer_1.default().writeBytes(this.device.imsi);
    },
    0x197: function () {
        return new writer_1.default().writeTlv(Buffer.alloc(1));
    },
    0x198: function () {
        return new writer_1.default().writeTlv(Buffer.alloc(1));
    },
    0x202: function () {
        return new writer_1.default()
            .writeTlv(this.device.wifi_bssid.slice(0, 16))
            .writeTlv(this.device.wifi_bssid.slice(0, 32));
    },
    0x401: function () {
        return new writer_1.default().writeTlv((0, crypto_1.randomBytes)(16)); // rand 16 bytes
    },
    0x511: function () {
        const domains = new Set([
            "aq.qq.com",
            "buluo.qq.com",
            "connect.qq.com",
            "docs.qq.com",
            "game.qq.com",
            "gamecenter.qq.com",
            // "graph.qq.com",
            "haoma.qq.com",
            "id.qq.com",
            // "imgcache.qq.com",
            "kg.qq.com",
            "mail.qq.com",
            "mma.qq.com",
            "office.qq.com",
            // "om.qq.com",
            "openmobile.qq.com",
            "qqweb.qq.com",
            "qun.qq.com",
            "qzone.qq.com",
            "ti.qq.com",
            "tenpay.com",
            "v.qq.com",
            "vip.qq.com",
            "y.qq.com",
        ]);
        const stream = new writer_1.default().writeU16(domains.size);
        for (const v of domains) {
            stream.writeU8(0x01).writeTlv(v);
        }
        return stream;
    },
    0x516: function () {
        return new writer_1.default()
            .writeU32(0);
    },
    0x521: function () {
        return new writer_1.default()
            .writeBytes(Buffer.alloc(6));
    },
    0x525: function () {
        return new writer_1.default()
            .writeU16(1)
            .writeU16(0x536)
            .writeTlv(Buffer.from([0x1, 0x0]));
    },
    0x52d: function () {
        const d = this.device;
        const buf = pb.encode({
            1: d.bootloader,
            2: d.proc_version,
            3: d.version.codename,
            4: d.version.incremental,
            5: d.fingerprint,
            6: d.boot_id,
            7: d.android_id,
            8: d.baseband,
            9: d.version.incremental
        });
        return new writer_1.default()
            .writeBytes(buf);
    },
    0x544: function () {
        return new writer_1.default();
    }
};
function getPacker(c) {
    return exports.packTlv.bind(c);
}
exports.getPacker = getPacker;
