const KeyUtils = require('js-crypto-key-utils');
const rsa = require('node-rsa');

const crypto = require('crypto');
const assert = require('assert');

let keyBytes =
    {
        'DES-EDE3-CBC': 24,
        'DES-CBC': 8,
        'AES-128-CBC': 16,
        'AES-192-CBC': 24,
        'AES-256-CBC': 32
    };

function formatOut(data, outEnc)
{
    let result;
    switch (outEnc)
    {
        case 'base64':
            result = data;
            break;

        case 'buffer':
            result = Buffer.from(data, 'base64');
            break;

        default:
            result = Buffer.from(data, 'base64').toString(outEnc);
            break;
    }
    return result;
}

function decrypt(encData, type, passphrase, iv, outEnc)
{
    let key = passphraseToKey(type, passphrase, iv);
    let dec = crypto.createDecipheriv(type, key, iv);
    dec.setAutoPadding(false);
    let data = '';
    data += dec.update(encData, 'base64', 'base64');
    data += dec.final('base64');
    console.log(data);
    return formatOut(data, outEnc);
}

// port of EVP_BytesToKey, as used when decrypting PEM keys
function passphraseToKey(type, passphrase, salt)
{
    let nkey = keyBytes[type];

    if (!nkey)
    {
        var allowed = Object.keys(keyBytes);
        throw new TypeError('Unsupported type. Allowed: ' + allowed);
    }

    let niv = salt.length;
    let saltLen = 8;
    if (salt.length !== saltLen)
        salt = salt.slice(0, saltLen);
    var mds = 16;
    var addmd = false;
    var md_buf;
    var key = Buffer.alloc(nkey);
    var keyidx = 0;

    while (true)
    {
        var c = crypto.createHash('md5');

        if (addmd)
            c.update(md_buf);
        else
            addmd = true;

        if (!Buffer.isBuffer(passphrase))
            c.update(passphrase, 'ascii');
        else
            c.update(passphrase);

        c.update(salt);
        md_buf = c.digest('buffer');

        console.log(md_buf.toString("hex"));

        var i = 0;
        while (nkey && i < mds)
        {
            key[keyidx++] = md_buf[i];
            nkey--;
            i++;
        }

        var steps = Math.min(niv, mds - i);
        niv -= steps;
        i += steps;

        if ((nkey === 0) && (niv === 0)) break;
    }

    return key
}

function decrypt_pkcs1_private(data, passphrase, format, outEnc)
{
    let result;
    try{
        if (Buffer.isBuffer(data))
        {
            data = data.toString('ascii');
        }

        if (!outEnc)
        {
            outEnc = 'buffer';
        }

        // Make sure it looks like a RSA private key before moving forward
        let lines = data.trim().split('\n');
        assert.strictEqual(lines[0], '-----BEGIN RSA PRIVATE KEY-----');
        assert.strictEqual(lines[lines.length - 1], '-----END RSA PRIVATE KEY-----');

        if (lines[1] === 'Proc-Type: 4,ENCRYPTED')
        {
            let dekInfo = lines[2];
            assert.strictEqual(dekInfo.slice(0, 10), 'DEK-Info: ');
            dekInfo = dekInfo.slice(10).split(',');
            let type = dekInfo[0];
            let iv = Buffer.from(dekInfo[1], 'hex');
            assert.strictEqual(lines[3], '');
            let encData = lines.slice(4, -1).join('');
            result = decrypt(encData, type, passphrase, iv, outEnc);
        }
        else
        {
            let data = lines.slice(1, -1).join('');
            result = formatOut(data, outEnc);
        }

        let privateKey = new rsa();
        privateKey.importKey(result,'pkcs1-der');
        result = privateKey.exportKey(format + "-private");
    }catch(e){
        result = e.toString();
    }

    return new Promise(function (resolve) {
        resolve(result);
    });
}

function encrypt_pkcs1_private(data, passphrase, type){
    let result;
    try{
        const iv =  Buffer.from(crypto.randomBytes(Math.ceil(32 / 2)).toString('hex').slice(0, type.toString().indexOf("AES") >= 0 ? 32: 16).toUpperCase(), "hex");
        const encKey = passphraseToKey(type, passphrase, iv);
        let lines = data.trim().split('\n');
        assert.strictEqual(lines[0], '-----BEGIN RSA PRIVATE KEY-----');
        assert.strictEqual(lines[lines.length - 1], '-----END RSA PRIVATE KEY-----');
        let encData = lines.slice(1, -1).join('');
        let enc = crypto.createCipheriv(type,  encKey, iv);
        enc.setAutoPadding(true);
        let output = '';
        let dek = "DEK-Info: " + type + "," + Buffer.from(iv, "hex").toString("hex").toUpperCase();
        result = "-----BEGIN RSA PRIVATE KEY-----\n" + "Proc-Type: 4,ENCRYPTED\n" + dek + "\n\n";
        output += enc.update(encData, 'base64', 'base64');
        output += enc.final('base64');
        for(let i = 0; i < output.length; i = i + 64){
            result += output.substring(i, i + 64) + "\n";
        }
        result += "-----END RSA PRIVATE KEY-----";
    }catch (e) {
        result = e.toString();
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

async function decrypt_pkcs8_private(data, passphrase, format) {
    let result = "";
    try{
        const keyObj = new KeyUtils.Key('pem', data);
        await keyObj.decrypt(passphrase);
        result = await keyObj.export("pem");
        let privateKey = new rsa();
        privateKey.importKey(result,'pkcs8-pem');
        result = privateKey.exportKey(format + "-private");
    }catch (e) {
        result = e.toString();
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

async function encrypt_pkcs8_private(data, passphrase, type){
    let result = "";
    try{
        const keyObj = new KeyUtils.Key('pem', data);
        result = await keyObj.export('pem', {
            encryptParams: {
                passphrase: passphrase,
                cipher: type
            }
        });
    }catch (e) {
        result = e.toString();
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

async function generate_keypair(b, e){
    return new Promise(function (resolve, reject) {
        try{
            resolve(new rsa({b: b, e: e}));
            console.log("finish")
        }catch(e){
            reject(e.toString());
        }
    })
}

function getPrivateFormat(privateKey) {
    const lines = privateKey.trim().split('\n');
    if (lines[0] === "-----BEGIN RSA PRIVATE KEY-----"){
        return "pkcs1";
    } else if (lines[0] === "-----BEGIN PRIVATE KEY-----" || lines[0] === "-----BEGIN ENCRYPTED PRIVATE KEY-----"){
        return "pkcs8"
    } else {
        return null;
    }
}

function getPublicFormat(privateKey) {
    const lines = privateKey.trim().split('\n');
    if (lines[0] === "-----BEGIN RSA PUBLIC KEY-----"){
        return "pkcs1";
    } else if (lines[0] === "-----BEGIN PUBLIC KEY-----"){
        return "pkcs8"
    } else {
        return null;
    }
}

function getKeyType(key) {
    const lines = key.trim().split('\n');
    if (lines[0] === "-----BEGIN RSA PUBLIC KEY-----" || lines[0] === "-----BEGIN PUBLIC KEY-----"){
        return "public";
    } else if (lines[0] === "-----BEGIN PRIVATE KEY-----" || lines[0] === "-----BEGIN ENCRYPTED PRIVATE KEY-----" || lines[0] === "-----BEGIN RSA PRIVATE KEY-----"){
        return "private"
    } else {
        return "unknown";
    }
}

function private_converter(data, format, new_format){
    try{
        let privateKey = new rsa();
        privateKey.importKey(data,format + '-pem');
        return  privateKey.exportKey(new_format + "-private");
    }catch (e) {
        return e.toString();
    }
}

function public_converter(data, format, new_format){
    try{
        let privateKey = new rsa();
        privateKey.importKey(data, format + '-public-pem');
        return  privateKey.exportKey(new_format + "-public");
    }catch (e) {
        return e.toString();
    }
}

function extract_public(data, format, out_format){
    try{
        let privateKey = new rsa();
        privateKey.importKey(data, format + '-pem');
        return  privateKey.exportKey(out_format + "-public");
    }catch (e) {
        return e.toString();
    }
}

async function privateToJWK(data) {
    let result;
    try {
        const keyObj = new KeyUtils.Key('pem', data);
        result = {
            private: await keyObj.export('jwk'),
            public: await keyObj.export('jwk', {outputPublic: true})
        };
    } catch (e) {
        result = {
            private: e.toString(),
            public: e.toString()
        };
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

module.exports = {
    decrypt_pkcs1_private,
    generate_keypair,
    encrypt_pkcs8_private,
    encrypt_pkcs1_private,
    getPrivateFormat,
    decrypt_pkcs8_private,
    private_converter,
    getKeyType,
    public_converter,
    extract_public,
    getPublicFormat,
    privateToJWK
};