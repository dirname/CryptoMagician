const crypto = require('crypto');
const {crc1, crc8, crc81wire, crc16, crc16ccitt, crc16modbus, crc16kermit, crc16xmodem, crc24, crc32, crcjam} = require('crc');
const fs = require('fs');


function hashed(algo, data, encode, code) {
    try{
        var str = Buffer.from(data, code);
        var result = "";
        switch (encode) {
            default:
                result = crypto.createHash(algo).update(str).digest('hex');
                break;
            case "Base64":
                result = crypto.createHash(algo).update(str).digest('base64');
                break;
            case "Both":
                result = "Hex :" + "\n" + crypto.createHash(algo).update(str).digest('hex') + "\n\n" + "Base64 :" + "\n" + crypto.createHash(algo).update(str).digest('base64');
                break;
        }
        return result;
    }catch (e) {
        return e.toString();
    }
}

function hmac_hash(algo, data, encode, key, key_code, code){
    var str = Buffer.from(data, code);
    var result = "";
    switch (encode) {
        default:
            result = crypto.createHmac(algo, Buffer.from(key, key_code)).update(str).digest('hex');
            break;
        case "Base64":
            result = crypto.createHmac(algo, Buffer.from(key, key_code)).update(str).digest('base64');
            break;
        case "Both":
            result = "Hex :" + "\n" + crypto.createHmac(algo, key).update(str).update(str).digest('hex') + "\n\n" + "Base64 :" + "\n" + crypto.createHmac(algo, key).update(str).update(str).digest('base64');
            break;
    }
    return result;
}

function get_files(path, algo, encode){
    try{
        var hash = crypto.createHash(algo);
        var stream = fs.createReadStream(path);
        var str = "";
        var promise = new Promise(function(resolve, reject){
            stream.on('data', function(chunk) {
                hash.update(chunk);
            });
            stream.on('end', function() {
                switch (encode) {
                    default:
                        str = hash.digest("hex");
                        break;
                    case "Base64":
                        str = hash.digest("base64");
                        break;
                    case "Both":
                        str = "Hex :" + "\n" + hash.digest("hex") + "\n\n" + "Base64 :" + "\n" + hash.digest("base64");
                        break;
                }
                resolve(str);
            });
            stream.on('error', function (err) {
                resolve(err.stack);
            })
        });
        return promise;
    }catch(e){
        return e.toString();
    }

}

function get_file_crc(path, algo, encode){
    try{
        var stream = fs.createReadStream(path);
        var str = "";
        var promise = new Promise(function(resolve, reject){
            stream.on('data', function(chunk) {
                switch (algo) {
                    case "crc1":
                        str = crc1(chunk, str);
                        break;
                    case "crc8":
                        str = crc8(chunk, str);
                        break;
                    case "crc81wire":
                        str = crc81wire(chunk, str);
                        break;
                    case "crc16":
                        str = crc16(chunk, str);
                        break;
                    case "crc16ccitt":
                        str = crc16ccitt(chunk, str);
                        break;
                    case "crc16modbus":
                        str = crc16modbus(chunk, str);
                        break;
                    case "crc16kermit":
                        str = crc16kermit(chunk, str);
                        break;
                    case "crc16xmodem":
                        str = crc16xmodem(chunk, str);
                        break;
                    case "crc24":
                        str = crc24(chunk, str);
                        break;
                    case "crc32":
                        str = crc32(chunk, str);
                        break;
                    case "crcjam":
                        str = crcjam(chunk, str);
                        break;
                }
            });
            stream.on('end', function() {
                switch (encode) {
                    default:
                        str = str.toString(16);
                        break;
                    case "Base64":
                        str = Buffer.from(str.toString(16), "hex").toString('base64');
                        break;
                    case "Both":
                        str = "Hex :" + "\n" + str.toString(16) + "\n\n" + "Base64 :" + "\n" + Buffer.from(str.toString(16), "hex").toString('base64');
                        break;
                }
                resolve(str);
            });
            stream.on('error', function (err) {
                resolve(err.stack);
            })
        });
        return promise;
    }catch(e){
        return e.toString();
    }
}

function get_files_hmac(path, algo, encode, key){
    try{
        var hash = crypto.createHmac(algo, key);
        var stream = fs.createReadStream(path);
        var str = "";
        var promise = new Promise(function(resolve, reject){
            stream.on('data', function(chunk) {
                hash.update(chunk);
            });
            stream.on('end', function() {
                switch (encode) {
                    default:
                        str = hash.digest("hex");
                        break;
                    case "Base64":
                        str = hash.digest("base64");
                        break;
                    case "Both":
                        str = "Hex :" + "\n" + hash.digest("hex") + "\n\n" + "Base64 :" + "\n" + hash.digest("base64");
                        break;
                }
                resolve(str);
            });
            stream.on('error', function (err) {
                resolve(err.stack);
            })
        });
        return promise;
    }catch(e){
        return e.toString();
    }

}

function crc(str, mode, encode, code){
    try{
        var result = "";
        str = Buffer.from(str, code);
        switch (mode) {
            case "crc1":
                result = crc1(str);
                break;
            case "crc8":
                result = crc8(str);
                break;
            case "crc81wire":
                result = crc81wire(str);
                break;
            case "crc16":
                result = crc16(str);
                break;
            case "crc16ccitt":
                result = crc16ccitt(str);
                break;
            case "crc16modbus":
                result = crc16modbus(str);
                break;
            case "crc16kermit":
                result = crc16kermit(str);
                break;
            case "crc16xmodem":
                result = crc16xmodem(str);
                break;
            case "crc24":
                result = crc24(str);
                break;
            case "crc32":
                result = crc32(str);
                break;
            case "crcjam":
                result = crcjam(str);
                break;
        }
        switch (encode) {
            default:
                result = result.toString(16);
                break;
            case "Base64":
                result = Buffer.from(result.toString(16), "hex").toString('base64');
                break;
            case "Both":
                result = "Hex :" + "\n" + result.toString(16) + "\n\n" + "Base64 :" + "\n" + Buffer.from(result.toString(16), "hex").toString('base64');
        }
        return result;
    }catch (e) {
        return e.toString();
    }

}

module.exports = {
    hashed,
    hmac_hash,
    get_files,
    get_files_hmac,
    crc,
    get_file_crc
};



