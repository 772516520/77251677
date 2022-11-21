"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BUF16 = exports.BUF4 = exports.BUF0 = void 0;
const buffer_1 = require("buffer");
/** 0长度Buffer */
exports.BUF0 = buffer_1.Buffer.alloc(0);
/** 4长度Buffer */
exports.BUF4 = buffer_1.Buffer.alloc(4);
/** 16长度Buffer */
exports.BUF16 = buffer_1.Buffer.alloc(16);
