import {Buffer} from "buffer";

export type NOOP = () => void;

/** 0长度Buffer */
export const BUF0 = Buffer.alloc(0);

/** 4长度Buffer */
export const BUF4 = Buffer.alloc(4);

/** 16长度Buffer */
export const BUF16 = Buffer.alloc(16);
