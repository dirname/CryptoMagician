function pkcs7(blksize, text){
    const count = Buffer.from(text).length;
    const add = blksize - (count % blksize);
    return text + String.fromCharCode(add).repeat(add)
}

function un_pkcs7(text){
    var buffer = Buffer.from(text);
    var last_bytes = buffer[buffer.length - 1];
    return buffer.slice(0, -last_bytes).toString()
}

function ansix923(blksize, text){
    const count = Buffer.from(text).length;
    const add = blksize - (count % blksize);
    console.log(add);
    return text + String.fromCharCode(0).repeat(add - 1) + String.fromCharCode(add)
}

function un_ansix923(text){
    var buffer = Buffer.from(text);
    var last_bytes = buffer[buffer.length - 1];
    return buffer.slice(0, -last_bytes).toString()
}

function iso10126(blksize, text){
    const count = Buffer.from(text).length;
    const add = blksize - (count % blksize);
    var add_text = ""
    for(var i = 0; i < add - 1; i++){
        add_text += String.fromCharCode(Math.floor(Math.random() * 10));
    }
    return text + add_text + String.fromCharCode(add)
}

function un_iso10126(text) {
    var buffer = Buffer.from(text);
    var last_bytes = buffer[buffer.length - 1];
    return buffer.slice(0, -last_bytes).toString()
}

function zeropadding(blksize, text) {
    const count = Buffer.from(text).length;
    const add = blksize - (count % blksize);
    return text + String.fromCharCode(0).repeat(add)
}

function un_zeropadding(text){
    const buffer = Buffer.from(text);
    console.log(buffer);
    var index = 0;
    for(var i = text.length - 1;i > 0; i--){
        if (buffer[i] > 0){
            index = i;
            break
        }
    }
    return buffer.slice(0, -index).toString()
}

module.exports = {
    pkcs7,
    un_pkcs7,
    ansix923,
    un_ansix923,
    iso10126,
    un_iso10126,
    zeropadding,
    un_zeropadding
};