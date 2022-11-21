"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const writer_1 = __importDefault(require("../core/writer"));
const qq = "3591417713";
const buf = Buffer.alloc(4);
buf.writeUint32BE(7725);
function a() {
    return new writer_1.default()
        .writeU16(1)
        .writeBytes(buf)
        .writeU32(3591417713)
        .writeU32(1667975332)
        .writeU16(0)
        .writeU16(0)
        .writeU16(0);
}
console.log(qq);
console.log(Buffer.from(qq));
console.log(a().read());
