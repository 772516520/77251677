"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const node_crypto_1 = require("node:crypto");
class Utils {
    static md5(pwd) {
        return (0, node_crypto_1.createHash)("md5").update(pwd).digest();
    }
}
exports.default = Utils;
