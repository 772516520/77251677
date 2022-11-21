"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("../client");
const c = new client_1.Client(123, 2);
c.login("");
c.on("con", (ip, port) => {
    console.log("connected");
    console.log(ip);
    console.log(port);
});
c.on("p", (chunk) => {
    console.log(chunk);
});
c.on("verify", (d, p) => {
    console.log(d);
    process.stdin.once("data", (data) => {
        console.log("dddddddd");
        c.sendSMSCode();
    });
}).login("");
