const crypto = require('crypto');
const { BrowserWindow } = require('electron').remote;
const {ipcRenderer} = require('electron');
const rsa = require('node-rsa');
const KeyUtils = require('js-crypto-key-utils');
const assert = require('assert');

function public_encrypt(pubkey, data, inEncode, outEncode, padding) {
    try{
        const key = new rsa(pubkey);
        key.setOptions({encryptionScheme: padding});
        //data = Buffer.from(data, inEncode);
        let result = "";
        switch (outEncode) {
            case "hex":
                result = key.encrypt(data, outEncode, inEncode);
                break;
            case "base64":
                result = key.encrypt(data, outEncode, inEncode);
                break;
            case "Both":
                result = "Hex :" + "\n" + key.encrypt(data, "hex", inEncode) + "\n\n" + "Base64 :" + "\n" + key.encrypt(data, "base64", inEncode);
                break;
        }
        if (data.length > key.getMaxMessageSize()){
            return result + "\n\n" + Language.get("this_public_only_support") + key.getMaxMessageSize().toString() + Language.get("your_data_bytes_is") + data.length.toString() + " " + Language.get("bytes")
        } else {
            return result;
        }
    }catch(e){
        return e.toString();
    }
}

function public_decrypt(pubkey, data, inEncode, outEncode, padding) {
    try{
        const key = new rsa(pubkey);
        key.setOptions({encryptionScheme: padding});
        data = Buffer.from(data, inEncode);
        return key.decryptPublic(Buffer.from(data), outEncode);
    }catch(e){
        return e.toString();
    }
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

async function pkcs8_private_encrypt_passphrase(privateKey, data, inEncode, outEncode, padding, passphrase){
    let result = "";
    try{
        const keyObj = new KeyUtils.Key('pem', privateKey);
        await keyObj.decrypt(passphrase);
        result = await keyObj.export("pem");
        const key = new rsa(result);
        key.setOptions({encryptionScheme: padding});
        result = key.encryptPrivate(Buffer.from(data, inEncode), outEncode, inEncode);
    }catch (e) {
        result = e.toString();
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

async function pkcs8_private_decrypt_passphrase(privateKey, data, inEncode, outEncode, padding, passphrase){
    let result = "";
    try{
        const keyObj = new KeyUtils.Key('pem', privateKey);
        await keyObj.decrypt(passphrase);
        result = await keyObj.export("pem");
        const key = new rsa(result);
        key.setOptions({encryptionScheme: padding});
        result = key.decrypt(Buffer.from(data, inEncode), outEncode);
    }catch (e) {
        result = e.toString();
    }
    return new Promise(function (resolve) {
        resolve(result);
    });
}

function private_encrypt(privateKey, data, inEncode, outEncode, padding){
    try{
        const key = new rsa(privateKey);
        key.setOptions({encryptionScheme: padding});
        //data = Buffer.from(data, inEncode);
        let result = "";
        switch (outEncode) {
            case "hex":
                result = key.encryptPrivate(data, outEncode, inEncode);
                break;
            case "base64":
                result = key.encryptPrivate(data, outEncode, inEncode);
                break;
            case "Both":
                result = "Hex :" + "\n" + key.encryptPrivate(data, "hex", inEncode) + "\n\n" + "Base64 :" + "\n" + key.encryptPrivate(data, "base64", inEncode);
                break;
        }
        if (data.length > key.getMaxMessageSize()){
            return result + "\n\n" + Language.get("this_public_only_support") + key.getMaxMessageSize().toString() + Language.get("your_data_bytes_is") + data.length.toString() + " " + Language.get("bytes")
        } else {
            return result;
        }
    }catch (e) {
        return e.toString();
    }
}

function private_decrypt(privateKey, data, inEncode, outEncode, padding) {
    try{
        const key = new rsa(privateKey);
        key.setOptions({encryptionScheme: padding});
        data = Buffer.from(data, inEncode);
        return key.decrypt(Buffer.from(data), outEncode);
    }catch(e){
        return e.toString();
    }
}

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

function decrypt_pkcs1_private(data, passphrase, outEnc)
{
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
    assert.equal(lines[0], '-----BEGIN RSA PRIVATE KEY-----');
    assert.equal(lines[lines.length - 1], '-----END RSA PRIVATE KEY-----');

    let result;
    if (lines[1] === 'Proc-Type: 4,ENCRYPTED')
    {
        let dekInfo = lines[2];
        assert.equal(dekInfo.slice(0, 10), 'DEK-Info: ');
        dekInfo = dekInfo.slice(10).split(',');
        let type = dekInfo[0];
        let iv = Buffer.from(dekInfo[1], 'hex');
        assert.equal(lines[3], '');
        let encData = lines.slice(4, -1).join('');
        result = decrypt(encData, type, passphrase, iv, outEnc);
    }
    else
    {
        let data = lines.slice(1, -1).join('');
        result = formatOut(data, outEnc);
    }

    return result;
}

function pkcs1_private_encrypt_passphrase(privateKey, data, inEncode, outEncode, padding, passphrase){
    try{
        const key = new rsa();
        key.importKey(decrypt_pkcs1_private(privateKey, passphrase),'pkcs1-der');
        key.setOptions({encryptionScheme: padding});
        return key.encryptPrivate(Buffer.from(data, inEncode), outEncode, inEncode);
    }catch (e) {
        return e.toString();
    }
}

function pkcs1_private_decrypt_passphrase(privateKey, data, inEncode, outEncode, padding, passphrase){
    try{
        const key = new rsa();
        key.importKey(decrypt_pkcs1_private(privateKey, passphrase),'pkcs1-der');
        key.setOptions({encryptionScheme: padding});
        return key.decrypt(Buffer.from(data, inEncode), outEncode);
    }catch (e) {
        return e.toString();
    }
}


function open_keypair(){
    ipcRenderer.send('openKeyPair');
}




module.exports = {
    public_encrypt,
    public_decrypt,
    getPrivateFormat,
    pkcs8_private_encrypt_passphrase,
    private_encrypt,
    pkcs1_private_encrypt_passphrase,
    private_decrypt,
    pkcs8_private_decrypt_passphrase,
    pkcs1_private_decrypt_passphrase,
    open_keypair
};