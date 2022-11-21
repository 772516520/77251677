import {Socket} from "net";
import {BUF0, NOOP} from "./constants";

const default_host = "msfwifi.3g.qq.com";
const default_port = 8080;

export default class Network extends Socket {
    private buf = BUF0;
    private host = default_host;
    private port = default_port;
    private connected = false;

    constructor() {
        super();
        this.on("close", () => {
            console.log("close");
            this.emit("lost", 0x000f);
        });

        this.on("data", (chunk) => {
            console.log("-----Response-----");
            console.log(chunk.length);
            this.buf = this.buf.length === 0 ? chunk : Buffer.concat([BUF0, chunk]);
            while (this.buf.length >= 4) {
                const len = this.buf.readUInt32BE(); // len
                if (this.buf.length >= len) {
                    const packet = this.buf.slice(4, len);
                    this.buf = this.buf.slice(len); // r0
                    this.emit("packet", packet);
                } else
                    break;
            }
        });

        // this.connect(this.port, this.host, () => {
        //     this.connected = true;
        //     this.emit("connect2");
        // });

        this.on("error", (e) => {
            console.log("err");
            console.log(e);
        });
    }

    public join(cb: NOOP) {
        if (this.connecting) return;
        if (this.connected) return cb();
        this.connect(this.port, this.host, () => {
            this.connected = true;
            this.emit("connect2");
            cb();
        });
    }

}