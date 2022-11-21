import {createHash} from "node:crypto";
import {BinaryLike} from "crypto";

class Utils {
    public static md5(pwd: BinaryLike) {
        return createHash("md5").update(pwd).digest();
    }
}

export default Utils;