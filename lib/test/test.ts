import {Client} from "../client";

const c = new Client(123, 2);

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