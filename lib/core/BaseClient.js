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
const crypto_1 = require("crypto");
const device_1 = __importStar(require("./device"));
const writer_1 = __importDefault(require("./writer"));
const tlv_1 = require("./tlv");
const network_1 = __importDefault(require("./network"));
const constants_1 = require("./constants");
const ecdh_1 = __importDefault(require("./ecdh"));
const tea_1 = require("./tea");
const events_1 = __importDefault(require("events"));
const stream_1 = require("stream");
const pb = __importStar(require("./protobuf"));
const jce = __importStar(require("./jce"));
const utils_1 = __importDefault(require("./utils"));
const timers_1 = require("timers");
const NET = Symbol("NET");
const ECDH = Symbol("ECDH");
const FN_SEND = Symbol("FN_SEND");
const FN_SEND_LOGIN = Symbol("FN_SEND_LOGIN");
const FN_NEXT_SEQ = Symbol("FN_NEXT_SEQ");
const LOGIN_LOCK = Symbol("LOGIN_LOCK");
const HANDLERS = Symbol("HANDLERS");
const HEARTBEAT = Symbol("HEARTBEAT");
class BaseClient extends events_1.default {
    uin;
    device;
    apk;
    [NET] = new network_1.default;
    interval = 30;
    [ECDH] = new ecdh_1.default;
    [HEARTBEAT];
    [HANDLERS] = new Map();
    sig = {
        d2: constants_1.BUF0,
        d2key: constants_1.BUF0,
        seq: (0, crypto_1.randomBytes)(4).readUInt32BE() & 0xfff,
        skey: constants_1.BUF0,
        tgt: constants_1.BUF0,
        t104: constants_1.BUF0,
        t174: constants_1.BUF0,
        tgtgt: (0, crypto_1.randomBytes)(16),
        randkey: (0, crypto_1.randomBytes)(16),
        session: (0, crypto_1.randomBytes)(4),
        hb480: (() => {
            const buf = Buffer.alloc(9);
            buf.writeUint32BE(this.uin);
            buf.writeUint32BE(0x01A53E, 5);
            return pb.encode({
                1: 1152,
                2: 9,
                3: buf
            });
        })()
    };
    statistics = {
        remote_ip: 0,
        remote_port: 0
    };
    [LOGIN_LOCK] = false;
    constructor(uin, p = device_1.Platform.Android) {
        super();
        this.uin = uin;
        this.device = device_1.default.generateFullDevice(uin);
        this.apk = (0, device_1.getApklist)(p);
        this[NET].on("connect2", () => {
            this.statistics.remote_ip = this[NET].remoteAddress;
            this.statistics.remote_port = this[NET].remotePort;
            this.emit("con", this.statistics.remote_ip, this.statistics.remote_port);
            // syncTimeDiff.call(this);
        });
        this[NET].on("packet", packetListener.bind(this));
    }
    [FN_NEXT_SEQ]() {
        if (++this.sig.seq > 0x8000)
            this.sig.seq = 1;
        return this.sig.seq;
    }
    [FN_SEND](pkt, timeout = 5) {
        console.log("FN_SEND");
        return new Promise((resolve, reject) => {
            const id = setTimeout(() => {
                reject(new Error("Timeout"));
            }, timeout * 1000);
            this[NET].join(() => {
                this[NET].write(pkt, () => {
                    this[HANDLERS].set(this.sig.seq, (payload) => {
                        clearTimeout(id);
                        this[HANDLERS].delete(this.sig.seq);
                        resolve(payload);
                    });
                });
            });
        });
    }
    async sendUin(cmd, body, timeout = 5) {
        console.log("sendUin");
        const pkt = buildUinPkt.call(this, cmd, body);
        return this[FN_SEND](pkt, timeout);
    }
    async [FN_SEND_LOGIN](cmd, body) {
        if (this[LOGIN_LOCK])
            return;
        this[LOGIN_LOCK] = true;
        const pkt = buildLoginPacket.call(this, cmd, body);
        decodeLoginResponse.call(this, await this[FN_SEND](pkt));
    }
    passwordLogin(md5pass) {
        const t = (0, tlv_1.getPacker)(this);
        const body = new writer_1.default()
            .writeU16(9)
            .writeU16(23)
            .writeBytes(t(0x18))
            .writeBytes(t(0x01))
            .writeBytes(t(0x106, md5pass))
            .writeBytes(t(0x116))
            .writeBytes(t(0x100))
            .writeBytes(t(0x107))
            .writeBytes(t(0x142))
            .writeBytes(t(0x144))
            .writeBytes(t(0x145))
            .writeBytes(t(0x147))
            .writeBytes(t(0x154))
            .writeBytes(t(0x141))
            .writeBytes(t(0x08))
            .writeBytes(t(0x511))
            .writeBytes(t(0x187))
            .writeBytes(t(0x188))
            .writeBytes(t(0x194)) //
            .writeBytes(t(0x191))
            .writeBytes(t(0x202))
            .writeBytes(t(0x177))
            .writeBytes(t(0x516))
            .writeBytes(t(0x521))
            .writeBytes(t(0x525))
            .read();
        this[FN_SEND_LOGIN]("wtlogin.login", body);
    }
    /** 提交滑块验证码 */
    submitSlider(ticket) {
        ticket = ticket.trim();
        const t = (0, tlv_1.getPacker)(this);
        const body = new writer_1.default()
            .writeU16(2)
            .writeU16(4)
            .writeBytes(t(0x193, ticket))
            .writeBytes(t(0x08))
            .writeBytes(t(0x104))
            .writeBytes(t(0x116))
            .read();
        this[FN_SEND_LOGIN]("wtlogin.login", body);
    }
    /** 发送短信 */
    sendSmsCode() {
        const t = (0, tlv_1.getPacker)(this);
        const body = new writer_1.default()
            .writeU16(8)
            .writeU16(6)
            .writeBytes(t(0x08))
            .writeBytes(t(0x104))
            .writeBytes(t(0x116))
            .writeBytes(t(0x174))
            .writeBytes(t(0x17a))
            .writeBytes(t(0x197))
            .read();
        this[FN_SEND_LOGIN]("wtlogin.login", body);
    }
    /** 提交短信 */
    submitSmsCode(code) {
        code = code.trim();
        if (Buffer.byteLength(code) !== 6) {
            code = "123456";
        }
        const t = (0, tlv_1.getPacker)(this);
        const body = new writer_1.default()
            .writeU16(7)
            .writeU16(7)
            .writeBytes(t(0x08))
            .writeBytes(t(0x104))
            .writeBytes(t(0x116))
            .writeBytes(t(0x174))
            .writeBytes(t(0x17c, code))
            .writeBytes(t(0x401))
            .writeBytes(t(0x198))
            .read();
        this[FN_SEND_LOGIN]("wtlogin.login", body);
    }
}
function syncTimeDiff() {
    const pkt = buildLoginPacket.call(this, "Client.CorrectTime", constants_1.BUF4, 0);
    this[FN_SEND](pkt).then(r => {
        console.log(r);
        console.log("syncTimeDiff");
    }).catch();
}
function readTlv(r) {
    const t = {};
    while (r.readableLength > 2) {
        const tag = r.read(2).readUInt16BE();
        const len = r.read(2);
        t[tag] = r.read(len.readUInt16BE());
    }
    return t;
}
function parseSso(buf) {
    const headlen = buf.readUInt32BE(); // len
    const seq = buf.readUInt32BE(4); // seq
    const retcode = buf.readUInt32BE(8);
    if (retcode !== 0) {
        this.emit("internal.error.token");
        throw new Error("unsuccessful retcode: " + retcode);
    }
    let offset = buf.readUInt32BE(12) + 12;
    let len = buf.readUInt32BE(offset);
    const cmd = String(buf.slice(offset + 4, offset + len));
    offset += len;
    len = buf.readUInt32BE(offset);
    const flag = buf.readUInt32BE(offset + len);
    let payload;
    if (flag === 0)
        payload = buf.slice(headlen + 4);
    else if (flag === 1) {
        console.log("zip?");
        payload = Buffer.alloc(8);
    }
    else if (flag === 8)
        payload = buf.slice(headlen);
    else
        throw new Error("unknown compressed flag: " + flag);
    return { seq, cmd, payload };
}
function buildLoginPacket(cmd, body, type = 2) {
    this[FN_NEXT_SEQ]();
    const cmdid = 0x810;
    if (type === 2) {
        body = new writer_1.default()
            .writeU8(0x02)
            .writeU8(0x01) // const
            .writeBytes(this.sig.randkey) // randkey 16
            .writeU16(0x131)
            .writeU16(1)
            .writeTlv(this[ECDH].public_key)
            .writeBytes((0, tea_1.encrypt)(body, this[ECDH].share_key))
            .read();
        body = new writer_1.default()
            .writeU8(0x02)
            .writeU16(29 + body.length) // len
            .writeU16(8001)
            .writeU16(cmdid) // cmdid
            .writeU16(1) // const
            .writeU32(this.uin) // uin
            .writeU8(3) // const --
            .writeU8(0x87) // encrypt
            .writeU8(0)
            .writeU32(2)
            .writeU32(0)
            .writeU32(0)
            .writeBytes(body)
            .writeU8(0x03)
            .read();
    }
    let sso = new writer_1.default()
        .writeWithLength(new writer_1.default()
        .writeU32(this.sig.seq)
        .writeU32(this.apk.subid)
        .writeU32(this.apk.subid)
        .writeBytes(Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]))
        .writeWithLength(this.sig.tgt)
        .writeWithLength(cmd)
        .writeWithLength(this.sig.session)
        .writeWithLength(this.device.imei)
        .writeU32(4)
        .writeU16(2)
        .writeU32(4)
        .read())
        .writeWithLength(body)
        .read();
    if (type === 1)
        sso = (0, tea_1.encrypt)(sso, this.sig.d2key);
    else if (type === 2)
        sso = (0, tea_1.encrypt)(sso, constants_1.BUF16);
    return new writer_1.default()
        .writeWithLength(new writer_1.default()
        .writeU32(0x0A) // 10 11
        .writeU8(type) // 1 need 2 no need
        .writeWithLength(this.sig.d2) // tk
        .writeU8(0)
        .writeWithLength(String(this.uin))
        .writeBytes(sso)
        .read())
        .read();
}
function buildUinPkt(cmd, body) {
    this[FN_NEXT_SEQ]();
    // let len = cmd.length + 22;
    // console.log("len: " + len);
    // let sso = Buffer.alloc(len);
    // sso.writeUint32BE(len);
    // sso.writeUint32BE(cmd.length + 4, 4);
    // sso.fill(cmd, 8);
    // len = cmd.length + 8;
    // sso.writeUint32BE(8, len);
    // sso.fill(this.sig.session, len + 4);
    // sso.writeUint32BE(6, len + 8);
    // sso.writeUint32BE(0x70000000, len + 12);
    // sso.writeUInt16BE(body.length);
    // sso.fill(body, len + 18);
    const sso = new writer_1.default()
        .writeU32(cmd.length + 22)
        .writeWithLength(cmd)
        .writeU32(0x08)
        .writeBytes(this.sig.session)
        .writeU32(6)
        .writeU16(0x7000) // 0x70000000
        .writeWithLength(body)
        .read();
    const encrypted = (0, tea_1.encrypt)(sso, this.sig.d2key);
    const uin = String(this.uin);
    const pkt = new writer_1.default()
        .writeWithLength(new writer_1.default()
        .writeU32(0x0B)
        .writeU8(1)
        .writeU32(this.sig.seq)
        .writeU8(0)
        .writeWithLength(uin)
        .writeBytes(encrypted)
        .read())
        .read();
    return pkt;
}
function packetListener(pkt) {
    this[LOGIN_LOCK] = false;
    try {
        const flag = pkt.readUInt8(4);
        const encrypted = pkt.slice(pkt.readUInt32BE(6) + 6);
        let decrypted;
        console.log("flag");
        console.log(flag);
        switch (flag) {
            case 0:
                decrypted = encrypted;
                break;
            case 1:
                decrypted = (0, tea_1.decrypt)(encrypted, this.sig.d2key);
                break;
            case 2:
                decrypted = (0, tea_1.decrypt)(encrypted, constants_1.BUF16);
                break;
            default:
                throw new Error("unknown flag:" + flag);
        }
        const sso = parseSso.call(this, decrypted);
        if (this[HANDLERS].has(sso.seq))
            this[HANDLERS].get(sso.seq)?.(sso.payload);
    }
    catch (error) {
        console.log(error);
    }
}
function register(logout = false) {
    this[FN_NEXT_SEQ]();
    (0, timers_1.clearInterval)(this[HEARTBEAT]);
    const pb_buf = pb.encode({
        1: [
            { 1: 46, 2: Math.floor(Date.now() / 1000) },
            { 1: 283, 2: 0 }
        ]
    });
    const d = this.device;
    const SvcReqRegister = jce.encodeStruct([
        this.uin,
        (logout ? 0 : 7),
        0,
        "",
        (logout ? 21 : 11),
        0,
        0,
        0,
        0,
        0,
        (logout ? 44 : 0),
        d.version.sdk,
        1,
        "",
        0,
        null,
        d.guid,
        2052,
        0,
        d.model,
        d.model,
        d.version.release,
        1,
        0,
        0,
        null,
        0,
        0,
        "",
        0,
        d.brand,
        d.brand,
        "",
        pb_buf,
        0,
        null,
        0,
        null,
        1000,
        98
    ]);
    const body = jce.encodeWrapper({ SvcReqRegister }, "PushService", "SvcReqRegister");
    const pkt = buildLoginPacket.call(this, "StatSvc.register", body, 1);
    this[HEARTBEAT] = setInterval(async () => {
        console.log("[发送] 心跳");
        this.sendUin("OidbSvc.0x480_9_IMCore", this.sig.hb480)
            .catch(() => this.sendUin("OidbSvc.0x480_9_IMCore", this.sig.hb480)
            .catch(() => this.sendUin("OidbSvc.0x480_9_IMCore", this.sig.hb480)));
    }, this.interval * 1000);
    this[FN_SEND](pkt);
}
function decodeT119(t119) {
    const r = stream_1.Readable.from((0, tea_1.decrypt)(t119, this.sig.tgtgt), { objectMode: false });
    r.read(2);
    const t = readTlv(r);
    this.sig.tgt = t[0x10a];
    this.sig.skey = t[0x120];
    this.sig.d2 = t[0x143];
    this.sig.d2key = t[0x305];
    this.sig.tgtgt = utils_1.default.md5(this.sig.d2key);
    const token = Buffer.concat([
        this.sig.d2key,
        this.sig.d2,
        this.sig.tgt
    ]);
    const age = t[0x11a].slice(2, 3).readUInt8();
    const gender = t[0x11a].slice(3, 4).readUInt8();
    const nickname = String(t[0x11a].slice(5));
    console.log(nickname);
    return { token, age, gender, nickname };
}
function decodeLoginResponse(payload) {
    payload = (0, tea_1.decrypt)(payload.slice(16, payload.length - 1), this[ECDH].share_key);
    const r = stream_1.Readable.from(payload, { objectMode: false });
    r.read(2);
    const type = r.read(1).readUInt8();
    r.read(2);
    const t = readTlv(r);
    console.log("type");
    console.log(type);
    if (type === 0) {
        console.log("login");
        this.sig.t104 = constants_1.BUF0;
        this.sig.t174 = constants_1.BUF0;
        decodeT119.call(this, t[0x119]);
        return register.call(this);
    }
    if (type === 160) {
        if (!t[0x204] && !t[0x174])
            return console.log("已向保密发送验证码");
        let phone = "";
        if (t[0x174] && t[0x178]) {
            this.sig.t104 = t[0x104];
            this.sig.t104 = t[0x174];
            phone = String(t[0x178]).substr(t[0x178].indexOf("\x0b") + 1, 11);
        }
        console.log(t[0x104]);
        console.log(t[0x174]);
        return this.emit("verify", t[0x204]?.toString() || "", phone);
    }
    if (t[0x149]) {
        throw new Error("errl");
    }
    if (t[0x146]) {
        const stream = stream_1.Readable.from(t[0x146], { objectMode: false });
        const version = stream.read(4);
        const title = stream.read(stream.read(2).readUInt16BE()).toString();
        const content = stream.read(stream.read(2).readUInt16BE()).toString();
        console.log(`${type} [${title}]${content}`);
    }
}
exports.default = BaseClient;
