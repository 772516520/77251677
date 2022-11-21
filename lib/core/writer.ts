import {PassThrough} from "stream";

class Writer extends PassThrough {
    writeU8(v: number) {
        const buf = Buffer.alloc(1);
        buf.writeUInt8(v);
        this.write(buf);
        return this;
    }

    writeU16(v: number) {
        const buf = Buffer.alloc(2);
        buf.writeUInt16BE(v);
        this.write(buf);
        return this;
    }

    writeU32(v: number) {
        const buf = Buffer.alloc(4);
        buf.writeUInt32BE(v);
        this.write(buf);
        return this;
    }

    writeU64(v: number) {
        const buf = Buffer.alloc(8);
        buf.writeBigUint64BE(BigInt(v));
        this.write(buf);
        return this;
    }

    writeBytes(v: string | Uint8Array) {
        if (typeof v === "string")
            v = Buffer.from(v);
        this.write(v);
        return this;
    }

    writeWithLength(v: string | Uint8Array) {
        return this.writeU32(Buffer.byteLength(v) + 4).writeBytes(v);
    }

    writeTlv(v: string | Uint8Array) {
        return this.writeU16(Buffer.byteLength(v)).writeBytes(v);
    }
}

export default Writer;