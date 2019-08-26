const CryptoJS = require('crypto-js');
const crypto = require('crypto');
var pad = require("../padding");
var MCrypt = require('mcrypt').MCrypt;
const {algorithm, mode} = require('cryptian');

function get_mod(de_mode) {
    switch (de_mode) {
        case "CBC":
            de_mode = CryptoJS.mode.CBC;
            break;
        case "CFB":
            de_mode = CryptoJS.mode.CFB;
            break;
        case "ECB":
            de_mode = CryptoJS.mode.ECB;
            break;
        case "OFB":
            de_mode = CryptoJS.mode.OFB;
            break;
        case "CTRGladman":
            de_mode = CryptoJS.mode.CTRGladman;
            break;
        case "CTR":
            de_mode = CryptoJS.mode.CTR;
            break;
        case "No":
            de_mode = null;
            break
    }
    return de_mode
}

function get_padding(de_padding) {
    switch (de_padding) {
        case "Pkcs7":
            de_padding = CryptoJS.pad.Pkcs7;
            break;
        case "AnsiX923":
            de_padding = CryptoJS.pad.AnsiX923;
            break;
        case "Iso10126":
            de_padding = CryptoJS.pad.Iso10126;
            break;
        case "Iso97971":
            de_padding = CryptoJS.pad.Iso97971;
            break;
        case "NoPadding":
            de_padding = CryptoJS.pad.NoPadding;
            break;
        case "ZeroPadding":
            de_padding = CryptoJS.pad.ZeroPadding;
            break;
    }
    return de_padding
}

var AES;
(function () {
    var aes = {};
    AES = {
        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    aes.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    aes.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    aes.key = CryptoJS.enc.Hex.parse(key);
                    break;
            }
            switch (IvType) {
                case "Text":
                    aes.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    aes.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    aes.iv = CryptoJS.enc.Hex.parse(iv);
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.AES.decrypt(srcs, aes.key, {iv: aes.iv, mode: de_mode, padding: de_padding});
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = "";
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.AES.encrypt(srcs, aes.key, {iv: aes.iv, mode: de_mode, padding: de_padding});
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var DES;
(function () {
    var des = {};
    DES = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    des.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    des.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    des.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    des.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    des.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    des.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.DES.decrypt(srcs, des.key, {iv: des.iv, mode: de_mode, padding: de_padding});
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = "";
            try {


                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.DES.encrypt(srcs, des.key, {iv: des.iv, mode: de_mode, padding: de_padding});
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var TripleDES;
(function () {
    var tripledes = {};
    TripleDES = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    tripledes.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    tripledes.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    tripledes.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    tripledes.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    tripledes.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    tripledes.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.TripleDES.decrypt(srcs, tripledes.key, {
                    iv: tripledes.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = "";
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.TripleDES.encrypt(srcs, tripledes.key, {
                    iv: tripledes.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RC4;
(function () {
    var rc4 = {};
    RC4 = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    rc4.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    rc4.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    rc4.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    rc4.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    rc4.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    rc4.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rc4.iv = "";
            }
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.RC4.decrypt(srcs, rc4.key, {iv: rc4.iv, mode: de_mode, padding: de_padding});
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = "";
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rc4.iv = "";
            }
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.RC4.encrypt(srcs, rc4.key, {iv: rc4.iv, mode: de_mode, padding: de_padding});
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RC4Drop;
(function () {
    var rc4drop = {};
    RC4Drop = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    rc4drop.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    rc4drop.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    rc4drop.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    rc4drop.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    rc4drop.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    rc4drop.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, drop_bytes, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rc4drop.iv = "";
            }
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.RC4Drop.decrypt(srcs, rc4drop.key, {
                    iv: rc4drop.iv,
                    mode: de_mode,
                    padding: de_padding,
                    drop: drop_bytes
                });
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, drop_bytes, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rc4drop.iv = "";
            }
            var srcs = "";
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.RC4Drop.encrypt(srcs, rc4drop.key, {
                    iv: rc4drop.iv,
                    mode: de_mode,
                    padding: de_padding,
                    drop: drop_bytes
                });
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var Rabbit;
(function () {
    var rabbit = {};
    Rabbit = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    rabbit.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    rabbit.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    rabbit.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    rabbit.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    rabbit.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    rabbit.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rabbit.iv = null;
            }
            var srcs = src;
            try {
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.Rabbit.decrypt(srcs, rabbit.key, {
                    iv: rabbit.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rabbit.iv = null;
            }
            var srcs = "";
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.Rabbit.encrypt(srcs, rabbit.key, {
                    iv: rabbit.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RabbitLegacy;
(function () {
    var rabbitlegacy = {};
    RabbitLegacy = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    rabbitlegacy.key = CryptoJS.enc.Utf8.parse(key);
                    break;
                case "Base64":
                    rabbitlegacy.key = CryptoJS.enc.Base64.parse(key);
                    break;
                case "Hex":
                    rabbitlegacy.key = CryptoJS.enc.Hex.parse(key);
                    break
            }
            switch (IvType) {
                case "Text":
                    rabbitlegacy.iv = CryptoJS.enc.Utf8.parse(iv);
                    break;
                case "Base64":
                    rabbitlegacy.iv = CryptoJS.enc.Base64.parse(iv);
                    break;
                case "Hex":
                    rabbitlegacy.iv = CryptoJS.enc.Hex.parse(iv);
                    break
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = src;
            try {
                if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                    rabbitlegacy.iv = "";
                }
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var decrypt = CryptoJS.RabbitLegacy.decrypt(srcs, rabbitlegacy.key, {
                    iv: rabbitlegacy.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
                var value = decryptedStr.toString();
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }
        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            de_mode = get_mod(de_mode);
            de_padding = get_padding(de_padding);
            var srcs = "";
            if (de_mode === null || de_mode === CryptoJS.mode.ECB) {
                rabbitlegacy.iv = "";
            }
            try {
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    srcs = CryptoJS.enc.Base64.parse(src);
                } else {
                    switch (plain_code) {
                        case "base64":
                            srcs = CryptoJS.enc.Base64.parse(src);
                            break;
                        case "hex":
                            srcs = CryptoJS.enc.Hex.parse(src);
                            break;
                        default:
                            srcs = CryptoJS.enc.Utf8.parse(src);
                            break;
                    }
                }
                const encrypted = CryptoJS.RabbitLegacy.encrypt(srcs, rabbitlegacy.key, {
                    iv: rabbitlegacy.iv,
                    mode: de_mode,
                    padding: de_padding
                });
                const hexStr = encrypted.ciphertext.toString().toUpperCase();
                switch (type) {
                    case "hex":
                        return hexStr;
                    case "Both":
                        const oldHexStr2 = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str2 = CryptoJS.enc.Base64.stringify(oldHexStr2);
                        const result = "Hex :" + "\n" + hexStr + "\n\n" + "Base64 :" + "\n" + base64Str2;
                        return result;
                    default:
                        const oldHexStr = CryptoJS.enc.Hex.parse(hexStr);
                        const base64Str = CryptoJS.enc.Base64.stringify(oldHexStr);
                        return base64Str
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var Blowfish;
(function () {
    var blowfish = {};
    Blowfish = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    blowfish.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    blowfish.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    blowfish.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    blowfish.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    blowfish.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    blowfish.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('bf-cbc', blowfish.key, blowfish.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('bf-cfb', blowfish.key, blowfish.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('bf-ecb', blowfish.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('bf-ofb', blowfish.key, blowfish.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;
                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'bf-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'bf-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'bf-ecb';
                        blowfish.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'bf-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, blowfish.key, blowfish.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var IDEA;
(function () {
    var idea = {};
    IDEA = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    idea.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    idea.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    idea.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    idea.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    idea.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    idea.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('idea-cbc', idea.key, idea.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('idea-cfb', idea.key, idea.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('idea-ecb', idea.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('idea-ofb', idea.key, idea.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                value = Buffer.from(value, "utf8").toString(result_code);
                return value;
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'idea-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'idea-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'idea-ecb';
                        idea.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'idea-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, idea.key, idea.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var SEED;
(function () {
    var seed = {};
    SEED = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    seed.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    seed.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    seed.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    seed.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    seed.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    seed.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('seed-cbc', seed.key, seed.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('seed-cfb', seed.key, seed.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('seed-ecb', seed.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('seed-ofb', seed.key, seed.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'seed-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'seed-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'seed-ecb';
                        seed.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'seed-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, seed.key, seed.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RC2;
(function () {
    var rc2 = {};
    RC2 = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    rc2.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    rc2.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    rc2.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    rc2.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    rc2.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    rc2.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('rc2-cbc', rc2.key, rc2.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('rc2-cfb', rc2.key, rc2.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('rc2-ecb', rc2.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('rc2-ofb', rc2.key, rc2.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'rc2-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'rc2-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'rc2-ecb';
                        rc2.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'rc2-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, rc2.key, rc2.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CAST5;
(function () {
    var cast5 = {};
    CAST5 = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    cast5.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    cast5.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    cast5.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    cast5.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    cast5.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    cast5.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('cast5-cbc', cast5.key, cast5.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('cast5-cfb', cast5.key, cast5.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('cast5-ecb', cast5.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('cast5-ofb', cast5.key, cast5.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'cast5-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'cast5-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'cast5-ecb';
                        cast5.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'cast5-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, cast5.key, cast5.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CAST;
(function () {
    var cast = {};
    CAST = {

        init: function (key, iv, keyType, IvType) {

            switch (keyType) {
                case "Text":
                    cast.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    cast.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    cast.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    cast.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    cast.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    cast.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('cast-cbc', cast.key, cast.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('cast-cfb', cast.key, cast.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('cast-ecb', cast.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('cast-ofb', cast.key, cast.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'cast-cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'cast-cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'cast-ecb';
                        cast.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'cast-ofb';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, cast.key, cast.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CAMELLIA;
(function () {
    var camellia = {};
    CAMELLIA = {

        init: function (key, iv, keyType, IvType) {
            if (key.length >= 16 && key.length < 24) {
                camellia.size = '128-';
            } else if (key.length >= 24 && key.length < 32) {
                camellia.size = '192-';
            } else if (key.length >= 32) {
                camellia.size = '256-';
            } else {
                camellia.size = '128-';
            }
            switch (keyType) {
                case "Text":
                    camellia.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    camellia.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    camellia.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    camellia.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    camellia.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    camellia.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = crypto.createDecipheriv('camellia-' + camellia.size + 'cbc', camellia.key, camellia.iv);
                        break;
                    case "CFB":
                        cipher = crypto.createDecipheriv('camellia-' + camellia.size + 'cfb', camellia.key, camellia.iv);
                        break;
                    case "ECB":
                        cipher = crypto.createDecipheriv('camellia-' + camellia.size + 'ecb', camellia.key, null);
                        break;
                    case "OFB":
                        cipher = crypto.createDecipheriv('camellia-' + camellia.size + 'ofb', camellia.key, camellia.iv);
                        break;
                    case "CTR":
                        cipher = crypto.createDecipheriv('camellia-' + camellia.size + 'ctr', camellia.key, camellia.iv);
                        break;
                }
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algorithm_name = "";
                switch (de_mode) {
                    case "CBC":
                        algorithm_name = 'camellia-' + camellia.size + 'cbc';
                        break;
                    case "CFB":
                        algorithm_name = 'camellia-' + camellia.size + 'cfb';
                        break;
                    case "ECB":
                        algorithm_name = 'camellia-' + camellia.size + 'ecb';
                        camellia.iv = "";
                        break;
                    case "OFB":
                        algorithm_name = 'camellia-' + camellia.size + 'ofb';
                        break;
                    case "CTR":
                        algorithm_name = 'camellia-' + camellia.size + 'ctr';
                        break;
                }
                const cipher = crypto.createCipheriv(algorithm_name, camellia.key, camellia.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CHACHA20;
(function () {
    var chacha20 = {};
    CHACHA20 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    chacha20.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    chacha20.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    chacha20.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    chacha20.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    chacha20.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    chacha20.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = crypto.createDecipheriv('chacha20', chacha20.key, chacha20.iv);
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                    case "NoPadding":
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                const cipher = crypto.createCipheriv("chacha20", chacha20.key, chacha20.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(0, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(0, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(0, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(0, src);
                        break;
                    case "NoPadding":
                        srcs = src;
                        break;
                    default:
                        srcs = pad.zeropadding(0, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var POLY1305;
(function () {
    var poly1305 = {};
    POLY1305 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    poly1305.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    poly1305.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    poly1305.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    poly1305.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    poly1305.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    poly1305.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = crypto.createDecipheriv('chacha20-poly1305', poly1305.key, poly1305.iv);
                cipher.setAutoPadding(false);
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value += cipher.update(srcs, 'base64', 'utf8');
                value += cipher.final('utf8');
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                    case "NoPadding":
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                const cipher = crypto.createCipheriv("chacha20-poly1305", poly1305.key, poly1305.iv);
                cipher.setAutoPadding(false);
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(0, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(0, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(0, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(0, src);
                        break;
                    case "NoPadding":
                        srcs = src;
                    default:
                        srcs = pad.zeropadding(0, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value += cipher.update(srcs, 'utf8', 'hex');
                        value += cipher.final('hex');
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 += cipher.update(srcs, 'utf8', 'hex');
                        oldHexStr2 += cipher.final('hex');
                        baseStr = Buffer.from(oldHexStr2, "Hex");
                        baseStr = baseStr.toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value += cipher.update(srcs, 'utf8', 'base64');
                        value += cipher.final('base64');
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RIJNDAEL128;
(function () {
    var rijndael128 = {};
    RIJNDAEL128 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    rijndael128.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    rijndael128.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    rijndael128.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    rijndael128.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    rijndael128.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    rijndael128.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-128', 'cbc');
                        cipher.open(rijndael128.key, rijndael128.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-128', 'cfb');
                        cipher.open(rijndael128.key, rijndael128.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-128', 'ecb');
                        cipher.open(rijndael128.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-128', 'ofb');
                        cipher.open(rijndael128.key, rijndael128.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-128', 'ctr');
                        cipher.open(rijndael128.key, rijndael128.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-128', 'cbc');
                        cipher.open(rijndael128.key, rijndael128.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-128', 'cfb');
                        cipher.open(rijndael128.key, rijndael128.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-128', 'ecb');
                        cipher.open(rijndael128.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-128', 'ofb');
                        cipher.open(rijndael128.key, rijndael128.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-128', 'ctr');
                        cipher.open(rijndael128.key, rijndael128.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var RIJNDAEL192;
(function () {
    var rijndael192 = {};
    RIJNDAEL192 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    rijndael192.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    rijndael192.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    rijndael192.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    rijndael192.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    rijndael192.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    rijndael192.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-192', 'cbc');
                        cipher.open(rijndael192.key, rijndael192.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-192', 'cfb');
                        cipher.open(rijndael192.key, rijndael192.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-192', 'ecb');
                        cipher.open(rijndael192.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-192', 'ofb');
                        cipher.open(rijndael192.key, rijndael192.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-192', 'ctr');
                        cipher.open(rijndael192.key, rijndael192.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-192', 'cbc');
                        cipher.open(rijndael192.key, rijndael192.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-192', 'cfb');
                        cipher.open(rijndael192.key, rijndael192.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-192', 'ecb');
                        cipher.open(rijndael192.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-192', 'ofb');
                        cipher.open(rijndael192.key, rijndael192.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-192', 'ctr');
                        cipher.open(rijndael192.key, rijndael192.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(24, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(24, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(24, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(24, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();


var RIJNDAEL256;
(function () {
    var rijndael256 = {};
    RIJNDAEL256 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    rijndael256.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    rijndael256.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    rijndael256.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    rijndael256.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    rijndael256.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    rijndael256.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-256', 'cbc');
                        cipher.open(rijndael256.key, rijndael256.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-256', 'cfb');
                        cipher.open(rijndael256.key, rijndael256.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-256', 'ecb');
                        cipher.open(rijndael256.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-256', 'ofb');
                        cipher.open(rijndael256.key, rijndael256.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-256', 'ctr');
                        cipher.open(rijndael256.key, rijndael256.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('rijndael-256', 'cbc');
                        cipher.open(rijndael256.key, rijndael256.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('rijndael-256', 'cfb');
                        cipher.open(rijndael256.key, rijndael256.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('rijndael-256', 'ecb');
                        cipher.open(rijndael256.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('rijndael-256', 'ofb');
                        cipher.open(rijndael256.key, rijndael256.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('rijndael-256', 'ctr');
                        cipher.open(rijndael256.key, rijndael256.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(32, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(32, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(32, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(32, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();


var GOST;
(function () {
    var gost = {};
    GOST = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    gost.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    gost.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    gost.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    gost.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    gost.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    gost.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('gost', 'cbc');
                        cipher.open(gost.key, gost.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('gost', 'cfb');
                        cipher.open(gost.key, gost.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('gost', 'ecb');
                        cipher.open(gost.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('gost', 'ofb');
                        cipher.open(gost.key, gost.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('gost', 'ctr');
                        cipher.open(gost.key, gost.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('gost', 'cbc');
                        cipher.open(gost.key, gost.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('gost', 'cfb');
                        cipher.open(gost.key, gost.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('gost', 'ecb');
                        cipher.open(gost.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('gost', 'ofb');
                        cipher.open(gost.key, gost.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('gost', 'ctr');
                        cipher.open(gost.key, gost.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var BLOWFISHCOMPAT;
(function () {
    var blowfishcompat = {};
    BLOWFISHCOMPAT = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    blowfishcompat.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    blowfishcompat.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    blowfishcompat.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    blowfishcompat.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    blowfishcompat.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    blowfishcompat.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('blowfish-compat', 'cbc');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('blowfish-compat', 'cfb');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('blowfish-compat', 'ecb');
                        cipher.open(blowfishcompat.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('blowfish-compat', 'ofb');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('blowfish-compat', 'ctr');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('blowfish-compat', 'cbc');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('blowfish-compat', 'cfb');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('blowfish-compat', 'ecb');
                        cipher.open(blowfishcompat.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('blowfish-compat', 'ofb');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('blowfish-compat', 'ctr');
                        cipher.open(blowfishcompat.key, blowfishcompat.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var TWOFISH;
(function () {
    var twofish = {};
    TWOFISH = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    twofish.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    twofish.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    twofish.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    twofish.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    twofish.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    twofish.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('twofish', 'cbc');
                        cipher.open(twofish.key, twofish.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('twofish', 'cfb');
                        cipher.open(twofish.key, twofish.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('twofish', 'ecb');
                        cipher.open(twofish.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('twofish', 'ofb');
                        cipher.open(twofish.key, twofish.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('twofish', 'ctr');
                        cipher.open(twofish.key, twofish.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('twofish', 'cbc');
                        cipher.open(twofish.key, twofish.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('twofish', 'cfb');
                        cipher.open(twofish.key, twofish.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('twofish', 'ecb');
                        cipher.open(twofish.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('twofish', 'ofb');
                        cipher.open(twofish.key, twofish.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('twofish', 'ctr');
                        cipher.open(twofish.key, twofish.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var SERPENT;
(function () {
    var serpent = {};
    SERPENT = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    serpent.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    serpent.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    serpent.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    serpent.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    serpent.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    serpent.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('serpent', 'cbc');
                        cipher.open(serpent.key, serpent.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('serpent', 'cfb');
                        cipher.open(serpent.key, serpent.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('serpent', 'ecb');
                        cipher.open(serpent.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('serpent', 'ofb');
                        cipher.open(serpent.key, serpent.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('serpent', 'ctr');
                        cipher.open(serpent.key, serpent.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('serpent', 'cbc');
                        cipher.open(serpent.key, serpent.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('serpent', 'cfb');
                        cipher.open(serpent.key, serpent.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('serpent', 'ecb');
                        cipher.open(serpent.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('serpent', 'ofb');
                        cipher.open(serpent.key, serpent.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('serpent', 'ctr');
                        cipher.open(serpent.key, serpent.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var LOKI97;
(function () {
    var loki97 = {};
    LOKI97 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    loki97.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    loki97.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    loki97.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    loki97.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    loki97.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    loki97.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('loki97', 'cbc');
                        cipher.open(loki97.key, loki97.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('loki97', 'cfb');
                        cipher.open(loki97.key, loki97.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('loki97', 'ecb');
                        cipher.open(loki97.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('loki97', 'ofb');
                        cipher.open(loki97.key, loki97.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('loki97', 'ctr');
                        cipher.open(loki97.key, loki97.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('loki97', 'cbc');
                        cipher.open(loki97.key, loki97.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('loki97', 'cfb');
                        cipher.open(loki97.key, loki97.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('loki97', 'ecb');
                        cipher.open(loki97.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('loki97', 'ofb');
                        cipher.open(loki97.key, loki97.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('loki97', 'ctr');
                        cipher.open(loki97.key, loki97.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var SAFERPLUS;
(function () {
    var saferplus = {};
    SAFERPLUS = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    saferplus.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    saferplus.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    saferplus.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    saferplus.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    saferplus.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    saferplus.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('saferplus', 'cbc');
                        cipher.open(saferplus.key, saferplus.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('saferplus', 'cfb');
                        cipher.open(saferplus.key, saferplus.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('saferplus', 'ecb');
                        cipher.open(saferplus.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('saferplus', 'ofb');
                        cipher.open(saferplus.key, saferplus.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('saferplus', 'ctr');
                        cipher.open(saferplus.key, saferplus.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('saferplus', 'cbc');
                        cipher.open(saferplus.key, saferplus.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('saferplus', 'cfb');
                        cipher.open(saferplus.key, saferplus.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('saferplus', 'ecb');
                        cipher.open(saferplus.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('saferplus', 'ofb');
                        cipher.open(saferplus.key, saferplus.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('saferplus', 'ctr');
                        cipher.open(saferplus.key, saferplus.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var XTEA;
(function () {
    var xtea = {};
    XTEA = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    xtea.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    xtea.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    xtea.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    xtea.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    xtea.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    xtea.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('xtea', 'cbc');
                        cipher.open(xtea.key, xtea.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('xtea', 'cfb');
                        cipher.open(xtea.key, xtea.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('xtea', 'ecb');
                        cipher.open(xtea.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('xtea', 'ofb');
                        cipher.open(xtea.key, xtea.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('xtea', 'ctr');
                        cipher.open(xtea.key, xtea.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('xtea', 'cbc');
                        cipher.open(xtea.key, xtea.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('xtea', 'cfb');
                        cipher.open(xtea.key, xtea.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('xtea', 'ecb');
                        cipher.open(xtea.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('xtea', 'ofb');
                        cipher.open(xtea.key, xtea.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('xtea', 'ctr');
                        cipher.open(xtea.key, xtea.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var WAKE;
(function () {
    var wake = {};
    WAKE = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    wake.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    wake.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    wake.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    wake.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    wake.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    wake.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = new MCrypt('wake', 'stream');
                cipher.open(wake.key); // we are set the key;
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                    case "NoPadding":
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = new MCrypt('wake', 'stream');
                cipher.open(wake.key); // we are set the key;
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(0, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(0, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(0, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(0, src);
                        break;
                    case "NoPadding":
                        srcs = src;
                        break;
                    default:
                        srcs = pad.zeropadding(0, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CAST128;
(function () {
    var cast128 = {};
    CAST128 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    cast128.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    cast128.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    cast128.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    cast128.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    cast128.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    cast128.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('cast-128', 'cbc');
                        cipher.open(cast128.key, cast128.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('cast-128', 'cfb');
                        cipher.open(cast128.key, cast128.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('cast-128', 'ecb');
                        cipher.open(cast128.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('cast-128', 'ofb');
                        cipher.open(cast128.key, cast128.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('cast-128', 'ctr');
                        cipher.open(cast128.key, cast128.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('cast-128', 'cbc');
                        cipher.open(cast128.key, cast128.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('cast-128', 'cfb');
                        cipher.open(cast128.key, cast128.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('cast-128', 'ecb');
                        cipher.open(cast128.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('cast-128', 'ofb');
                        cipher.open(cast128.key, cast128.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('cast-128', 'ctr');
                        cipher.open(cast128.key, cast128.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var CAST256;
(function () {
    var cast256 = {};
    CAST256 = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    cast256.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    cast256.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    cast256.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    cast256.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    cast256.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    cast256.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('cast-256', 'cbc');
                        cipher.open(cast256.key, cast256.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('cast-256', 'cfb');
                        cipher.open(cast256.key, cast256.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('cast-256', 'ecb');
                        cipher.open(cast256.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('cast-256', 'ofb');
                        cipher.open(cast256.key, cast256.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('cast-256', 'ctr');
                        cipher.open(cast256.key, cast256.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.decrypt(Buffer.from(srcs, "base64"));
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new MCrypt('cast-256', 'cbc');
                        cipher.open(cast256.key, cast256.iv); // we are set the key
                        break;
                    case "CFB":
                        cipher = new MCrypt('cast-256', 'cfb');
                        cipher.open(cast256.key, cast256.iv); // we are set the key
                        break;
                    case "ECB":
                        cipher = new MCrypt('cast-256', 'ecb');
                        cipher.open(cast256.key);
                        break;
                    case "OFB":
                        cipher = new MCrypt('cast-256', 'ofb');
                        cipher.open(cast256.key, cast256.iv);
                        break;
                    case "CTR":
                        cipher = new MCrypt('cast-256', 'ctr');
                        cipher.open(cast256.key, cast256.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(16, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(16, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(16, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(16, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.encrypt(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.encrypt(srcs).toString("hex");
                        baseStr = cipher.encrypt(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.encrypt(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var THREEWAY;
(function () {
    var threeway = {};
    THREEWAY = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    threeway.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    threeway.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    threeway.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    threeway.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    threeway.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    threeway.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var algo = new algorithm.Threeway();
                algo.setKey(threeway.key);
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new mode.cbc.Decipher(algo, threeway.iv);
                        break;
                    case "CFB":
                        cipher = new mode.cfb.Decipher(algo, threeway.iv);
                        break;
                    case "ECB":
                        cipher = new mode.ecb.Decipher(algo, threeway.iv);
                        break;
                    case "OFB":
                        cipher = new mode.ofb.Decipher(algo, threeway.iv);
                        break;
                    case "CTR":
                        cipher = new mode.ctr.Decipher(algo, threeway.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.transform(Buffer.from(srcs, "base64")).toString("utf8");
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algo = new algorithm.Threeway();
                algo.setKey(threeway.key);
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new mode.cbc.Cipher(algo, threeway.iv);
                        break;
                    case "CFB":
                        cipher = new mode.cfb.Cipher(algo, threeway.iv);
                        break;
                    case "ECB":
                        cipher = new mode.ecb.Cipher(algo, threeway.iv);
                        break;
                    case "OFB":
                        cipher = new mode.ofb.Cipher(algo, threeway.iv);
                        break;
                    case "CTR":
                        cipher = new mode.ctr.Cipher(algo, threeway.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(12, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(12, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(12, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(12, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.transform(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.transform(srcs).toString("hex");
                        baseStr = cipher.transform(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.transform(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();

var SAFER;
(function () {
    var safer = {};
    SAFER = {

        init: function (key, iv, keyType, IvType) {
            switch (keyType) {
                case "Text":
                    safer.key = Buffer.from(key, "utf8");
                    break;
                case "Base64":
                    safer.key = Buffer.from(key, "base64");
                    break;
                case "Hex":
                    safer.key = Buffer.from(key, "hex");
                    break;
            }
            switch (IvType) {
                case "Text":
                    safer.iv = Buffer.from(iv, "utf8");
                    break;
                case "Base64":
                    safer.iv = Buffer.from(iv, "base64");
                    break;
                case "Hex":
                    safer.iv = Buffer.from(iv, "hex");
                    break;
            }
        },
        decrypt: function (src, de_padding, de_mode, type, result_code) {
            try {
                var algo = new algorithm.Safer();
                algo.setKey(safer.key);
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new mode.cbc.Decipher(algo, safer.iv);
                        break;
                    case "CFB":
                        cipher = new mode.cfb.Decipher(algo, safer.iv);
                        break;
                    case "ECB":
                        cipher = new mode.ecb.Decipher(algo, safer.iv);
                        break;
                    case "OFB":
                        cipher = new mode.ofb.Decipher(algo, safer.iv);
                        break;
                    case "CTR":
                        cipher = new mode.ctr.Decipher(algo, safer.iv);
                        break;
                }
                var srcs = src;

                if (type === "hex") {
                    var encryptedHexStr = CryptoJS.enc.Hex.parse(src);
                    srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
                }
                var value = "";
                value = cipher.transform(Buffer.from(srcs, "base64")).toString("utf8");
                switch (de_padding) {
                    case "Pkcs7":
                        value = pad.un_pkcs7(value);
                        break;
                    case "AnsiX923":
                        value = pad.un_ansix923(value);
                        break;
                    case "Iso10126":
                        value = pad.un_iso10126(value);
                        break;
                    case "ZeroPadding":
                        value = pad.un_zeropadding(value);
                        break;
                }
                return Buffer.from(value, "utf8").toString(result_code);
            } catch (e) {
                return e.toString();
            }

        },
        encrypt: function (src, de_padding, de_mode, type, isFile, plain_code) {
            try {
                var algo = new algorithm.Safer();
                algo.setKey(safer.key);
                var cipher = null;
                switch (de_mode) {
                    case "CBC":
                        cipher = new mode.cbc.Cipher(algo, safer.iv);
                        break;
                    case "CFB":
                        cipher = new mode.cfb.Cipher(algo, safer.iv);
                        break;
                    case "ECB":
                        cipher = new mode.ecb.Cipher(algo, safer.iv);
                        break;
                    case "OFB":
                        cipher = new mode.ofb.Cipher(algo, safer.iv);
                        break;
                    case "CTR":
                        cipher = new mode.ctr.Cipher(algo, safer.iv);
                        break;
                }
                var srcs = Buffer.from(src, "utf8");
                if (isFile) {
                    src = src.substring(src.indexOf("base64,") + 7);
                    src = Buffer.from(src, "base64");
                } else {
                    src = Buffer.from(src, plain_code);
                }
                switch (de_padding) {
                    case "Pkcs7":
                        srcs = pad.pkcs7(8, src);
                        break;
                    case "AnsiX923":
                        srcs = pad.ansix923(8, src);
                        break;
                    case "Iso10126":
                        srcs = pad.iso10126(8, src);
                        break;
                    case "ZeroPadding":
                        srcs = pad.zeropadding(8, src);
                        break;
                }
                var value = "";
                switch (type) {
                    case "hex":
                        value = cipher.transform(srcs).toString("hex");
                        return value;
                    case "Both":
                        var oldHexStr2 = "";
                        var baseStr = "";
                        oldHexStr2 = cipher.transform(srcs).toString("hex");
                        baseStr = cipher.transform(srcs).toString("base64");
                        const result = "Hex :" + "\n" + oldHexStr2 + "\n\n" + "Base64 :" + "\n" + baseStr;
                        return result;
                    default:
                        value = cipher.transform(srcs).toString("base64");
                        return value;
                }
            } catch (e) {
                return e.toString();
            }
        }
    }
})();
/*

const {dialog} = require('electron').remote
dialog.showOpenDialog({properties: ['openFile']}, function (files) {
    });

 */
