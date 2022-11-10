import {randomBytes} from "crypto";
import Writer from "./writer";
import {encrypt} from "./tea";
import * as pb from "./protobuf";
import Utils from "./utils";
import BaseClient from "./BaseClient";
import writer from "./writer";

const packTlv = function (this: BaseClient, tag: number, ...args: Array<any>) {
    const t = tlvmap[tag].apply(this, args);
    const lbuf = Buffer.alloc(2);
    lbuf.writeUInt16BE(t.readableLength);
    t.unshift(lbuf);
    const tbuf = Buffer.alloc(2);
    tbuf.writeUInt16BE(tag);
    t.unshift(tbuf);
    return t.read();
};

const tlvmap: { [tag: number]: (this: BaseClient, ...args: Array<any>) => Writer } = {
    0x01: function (): Writer {
        return new Writer()
            .writeU16(1)
            .writeBytes(randomBytes(4))
            .writeU32(this.uin)
            .writeU32(Date.now() & 0xffffffff)
            .writeU16(0)
            .writeU16(0)
            .writeU16(0);

    },
    0x08: function (): Writer {
        return new Writer()
            .writeU16(0)
            .writeU32(2502)
            .writeU16(0);
    },
    0x18: function (): Writer {
        return new Writer()
            .writeU16(1)
            .writeU32(1536)
            .writeU8(10)
            .writeU32(this.uin)
            .writeU8(0)
            .writeU8(0);
    },
    0x100: function (): Writer { // 设备信息?
        return new Writer()
            .writeU16(1)
            .writeU32(12)
            .writeU32(this.apk.appid)
            .writeU32(this.apk.subid)
            .writeU32(0)
            .writeU32(this.apk.sigmap);
    },
    0x106: function (md5pass: Buffer): Writer { // login
        const body = new Writer()
            .writeU16(4)
            .writeBytes(randomBytes(4))
            .writeU32(12)
            .writeU32(10)
            .writeU32(0)
            .writeU32(0)
            .writeU32(this.uin)
            .writeU32(Date.now() & 0xffffffff)
            .writeBytes(Buffer.alloc(4))
            .writeU8(1)
            .writeBytes(md5pass)
            .writeBytes(this.sig.tgtgt) // tgtgt rand 16bytes
            .writeBytes(Buffer.alloc(4))
            .writeU8(1)
            .writeBytes(this.device.guid) // guid
            .writeU32(this.apk.subid)
            .writeU32(1)
            .writeTlv(String(this.uin))
            .writeU16(0)
            .read();
        const buf = Buffer.alloc(4);
        buf.writeUint32BE(this.uin);
        const key = Buffer.concat([md5pass, Buffer.alloc(4), buf]);
        return new Writer().writeBytes(encrypt(body, key));
    },
    0x107: function (): Writer {
        return new Writer()
            .writeBytes(Buffer.alloc(4))
            .writeU16(1);
    },
    0x109: function (): Writer {
        return new Writer()
            .writeBytes(Utils.md5(this.device.imei));
    },
    0x116: function (): Writer {
        return new Writer()
            .writeU8(0)
            .writeU32(this.apk.bitmap) // platform
            .writeU32(0x10400)
            .writeU8(1)
            .writeU32(1600000226);
    },
    0x124: function (): Writer {
        return new Writer()
            .writeU16(7)
            .writeBytes(this.device.os_type)
            .writeU16(5)
            .writeBytes(this.device.version.release)
            .writeU16(2)
            .writeTlv(this.device.sim)
            .writeU16(0)
            .writeBytes(this.device.apn);
    },
    0x128: function (): Writer {
        return new Writer()
            .writeU16(0)
            .writeU8(0)
            .writeU8(1)
            .writeU8(0)
            .writeU32(16777216)
            .writeTlv(this.device.device.slice(0, 32))
            .writeTlv(this.device.guid.slice(0, 16))
            .writeTlv(this.device.brand);
    },
    0x141: function (): Writer {
        return new Writer()
            .writeU16(1)
            .writeTlv(this.device.sim)
            .writeU16(2)
            .writeTlv(this.device.apn);
    },
    0x144: function (): Writer {
        const body = new Writer()
            .writeU16(5)
            .writeBytes(packTlv.call(this, 0x109))
            .writeBytes(packTlv.call(this, 0x52d))
            .writeBytes(packTlv.call(this, 0x124))
            .writeBytes(packTlv.call(this, 0x128))
            .writeBytes(packTlv.call(this, 0x16e))
            .read();
        return new Writer().writeBytes(encrypt(body, this.sig.tgtgt));
    },
    0x145: function (): Writer {
        return new Writer()
            .writeBytes(this.device.guid);
    },
    0x147: function (): Writer {
        return new Writer()
            .writeU32(this.apk.appid)
            .writeTlv(this.apk.ver)
            .writeTlv(this.apk.sigin);
    },
    0x154: function (): Writer {
        return new Writer()
            .writeU32(this.sig.seq + 1);
    },
    0x16e: function (): Writer {
        return new Writer()
            .writeBytes(this.device.model);
    },
    0x177: function (): Writer {
        return new Writer()
            .writeU8(1)
            .writeU32(this.apk.buildtime)
            .writeTlv(this.apk.sdkver);
    },
    0x187: function (): Writer {
        return new Writer()
            .writeTlv(Utils.md5(this.device.mac_address));
    },
    0x188: function (): Writer {
        return new Writer()
            .writeTlv(Utils.md5(this.device.android_id));
    },
    0x191: function (): writer {
        return new Writer()
            .writeU8(0x82);
    },
    0x202: function (): Writer {
        return new Writer()
            .writeTlv(Utils.md5(this.device.wifi_bssid.slice(0, 16)))
            .writeTlv(this.device.wifi_bssid.slice(0, 32));
    },
    0x511: function (): Writer {
        const domains = new Set<Domain>([
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
        const stream = new Writer().writeU16(domains.size);
        for (const v of domains) {
            stream.writeU8(0x01).writeTlv(v);
        }
        return stream;
    },
    0x516: function (): Writer {
        return new Writer()
            .writeU32(0);
    },
    0x521: function (): Writer {
        return new Writer()
            .writeBytes(Buffer.alloc(6));
    },
    0x525: function (): Writer {
        return new Writer()
            .writeU16(1)
            .writeU16(0x536)
            .writeTlv(Buffer.from([0x1, 0x0]));
    },
    0x52d: function (): Writer {
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
        return new Writer()
            .writeBytes(buf);
    },
    0x544: function (): Writer {
        return new Writer();
    }
};

type Domain = "aq.qq.com"
    | "buluo.qq.com"
    | "connect.qq.com"
    | "docs.qq.com"
    | "game.qq.com"
    | "gamecenter.qq.com"
    // | "graph.qq.com"
    | "haoma.qq.com"
    | "id.qq.com"
    // | "imgcache.qq.com"
    | "kg.qq.com"
    | "mail.qq.com"
    | "mma.qq.com"
    | "office.qq.com"
    // | "om.qq.com"
    | "openmobile.qq.com"
    | "qqweb.qq.com"
    | "qun.qq.com"
    | "qzone.qq.com"
    | "ti.qq.com"
    | "tenpay.com"
    | "v.qq.com"
    | "vip.qq.com"
    | "y.qq.com"
    | ""