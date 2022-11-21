import Writer from "../core/writer";
import {randomBytes} from "crypto";

const qq = "3591417713";

const buf = Buffer.alloc(4);
buf.writeUint32BE(7725);

function a(): Writer {
    return new Writer()
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








