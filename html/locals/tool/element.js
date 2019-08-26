var form, $, upload, layer, element = null;
const {dialog} = require('electron').remote;
const assert = require('assert');
const rsa = require("node-rsa");
const crypto = require('crypto');
const KeyUtils = require('js-crypto-key-utils');
const X509Utils = require('js-x509-utils');
const X509Cert = require('x509-certificate');
const https = require('https');

function setEvent(f, j, u, l, e) {
    form = f;
    $ = j;
    upload = u;
    layer = l;
    element = e;
}

function listen() {
    form.verify({
        check_key: [
            /\S+/
            , Language.get("key_not_empty")
        ],
        check_src: [
            /\S+/
            , Language.get("plain_text_not_empty")
        ],
        check_iv: [
            /\S+/
            , Language.get("iv_not_empty")
        ],
        check_public: [
            /\S+/
            , Language.get("public_key_not_empty")
        ],
        check_private: [
            /\S+/
            , Language.get("private_key_not_empty")
        ],
        check_passphrase: [
            /\S+/
            , Language.get("passphrase_not_empty")
        ],
        check_key: [
            /\S+/
            , Language.get("convert_key_not_empty")
        ],
        check_sign: [
            /\S+/
            , Language.get("sign_not_empty")
        ],
        check_host: [
            /\S+/
            , Language.get("host_not_empty")
        ],
        check_port: [
            /\S+/
            , Language.get("port_not_empty")
        ],
        check_days: [
            /\S+/
            , Language.get("day_not_empty")
        ],
        check_salt: [
            /\S+/
            , Language.get("salt_not_empty")
        ],
        check_info: [
            /\S+/
            , Language.get("info_not_empty")
        ],
        check_cert: [
            /\S+/
            , Language.get("cert_not_empty")
        ],
    });

    $("#generate_reset").click(function () {
        $("#generate_div_public").attr("hidden");
        $("#generate_div_private").attr("hidden");
        $("#div_generate_passphrase").attr("hidden", true);
        $("#generate_passphrase").attr("lay-verify", "");
        $("#keypair_generate_algorithm_select").html('<option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="des-cbc">DES-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-192">AES-192-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>');
        form.render("select");
    });

    $("#passphrase_reset").click(function () {
        $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result" hidden></blockquote>');
        $("#keypair_passphrase_algorithm_select").html('<option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="des-cbc">DES-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-192">AES-192-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>');
        form.render("select");
    });

    $("#convert_reset").click(function () {
        $("#convert_result_box").html('');
        $("#div_keypair_private_convert").attr("hidden", true);
        $("#convert_passphrase").removeAttr("lay-verify", "");
        layer.closeAll();
        form.render("select");
    });

    $("#extract_reset").click(function () {
        $("#extract_result_box").html('');
        $("#div_extract_key").attr("hidden", true);
        $("#extract_passphrase").removeAttr("lay-verify", "");
        layer.closeAll();
        form.render("select");
    });

    $("#check_reset").click(function () {
        layer.closeAll();
    });

    $("#parse_reset").click(function () {
        $("#parse_result_box").html('');
        $("#keypair_salt_len").attr("disabled", true);
    });

    $("#sign_reset").click(function () {
        $("#sign_result_box").html('');
        $("#div_parse_passphrase").attr("hidden", true);
        $("#parse_passphrase").removeAttr("lay-verify", "");
        $("#sign_private_key").attr("lay-verify", "check_private");
        $("#div_sign_private").removeAttr("hidden");
        $("#div_sign_passphrase").removeAttr("hidden");
        $("#sign_public_key").removeAttr("lay-verify");
        $("#div_sign_public").attr("hidden", true);
        $("#keypair_salt_len").attr("disabled", true);
        form.render('select');
    });

    $("#x509_host_reset").click(function () {
        $("#x509_result_box").html('');
    });

    $("#x509_default_info").click(() => {
        $("#x509_private_info").val('{\n' +
            '\t"countryName": "JP",\n' +
            '\t"stateOrProvinceName": "Tokyo",\n' +
            '\t"localityName": "Chiyoda",\n' +
            '\t"organizationName": "example",\n' +
            '\t"organizationalUnitName": "Research",\n' +
            '\t"commonName": "example.com"\n' +
            '}');
    });

    $("#x509_private_reset").click(() => {
        $("#x509_result_box").html('');
        $("#keypair_x509_cert_salt").attr("lay-verify", "");
        $("#keypair_x509_cert_salt").attr("disabled", true);
        $("#keypair_x509_cert_salt").attr("class", "layui-input layui-disabled");
        document.getElementById('keypair_x509_cert_salt').setAttribute("placeholder", Language.get('no_need_salt'));
        document.getElementById("x509_cert_algorithm").innerHTML = "<option value=\"ecdsa-with-sha256\">ECDSAWithSHA256</option>\n" +
            "                <option value=\"ecdsa-with-sha384\">ECDSAWithSHA384</option>\n" +
            "                <option value=\"ecdsa-with-sha512\">ECDSAWithSHA512</option>\n" +
            "                <option value=\"ecdsa-with-sha1\">ECDSAWithSHA1</option>";
        form.render("select");
    });

    $("#x509_public_reset").click(() => {
        $("#x509_result_box").html('');
    });

    form.on('select(keypair_generate_passphrase)', function (data) {
        if (data.value === "enabled") {
            $("#div_generate_passphrase").removeAttr("hidden");
            $("#generate_passphrase").attr("lay-verify", "check_passphrase");
        } else {
            $("#div_generate_passphrase").attr("hidden", true);
            $("#generate_passphrase").attr("lay-verify", "");
        }
    });

    form.on('select(keypair_generate_format)', function (data) {
        data.value === "pkcs1" ? $("#keypair_generate_algorithm_select").html('<option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="des-cbc">DES-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-192">AES-192-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>') : $("#keypair_generate_algorithm_select").html('                <option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>');
        form.render("select");
    });

    form.on('submit(generate_keypair_do)', function (data) {
        let isPassphrase = data.field.isPassphrase;
        let key_exponent = data.field.key_exponent;
        let key_size = data.field.key_size;
        const keypair_generate_format = data.field.keypair_generate_format;
        const passphrase = data.field.passphrase;
        const keypair_generate_algorithm = data.field.keypair_generate_algorithm;
        if (key_exponent === "" || isNaN(parseInt(key_exponent))) {
            key_exponent = ""
        }
        if (key_size === "" || isNaN(parseInt(key_size))) {
            key_size = "";
        }
        isPassphrase = isPassphrase === "enabled";
        $("#generating_keypair").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#generating_keypair")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_generate_loading', '25%');
        setTimeout(function () {
            generate_keypair(key_size, key_exponent).then(function (data) {
                element.progress('keypair_generate_loading', '50%');
                setTimeout(function () {
                    let private_key = data.exportKey(keypair_generate_format + "-private");
                    const public_key = data.exportKey(keypair_generate_format + "-public");
                    let algorithm = "";
                    if (!isPassphrase) {
                        element.progress('keypair_generate_loading', '100%');
                        $("#generate_div_public").removeAttr("hidden");
                        $("#generate_publicKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + public_key + '</textarea>');
                        $("#generate_div_private").removeAttr("hidden");
                        $("#generate_privateKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + private_key + '</textarea>');
                        const h = $(document).height() - $(window).height();
                        $(document).scrollTop(h);
                        setTimeout(function () {
                            layer.close(index);
                            element.progress('keypair_generate_loading', '0%');
                            document.getElementById("generating_keypair").style.display = "none";
                        }, 500);

                    } else {
                        element.progress('keypair_generate_loading', '75%');
                        if (keypair_generate_format === "pkcs8") {
                            switch (keypair_generate_algorithm) {
                                case "des-ede3":
                                    algorithm = "des-ede3-cbc";
                                    break;
                                case "aes-128":
                                    algorithm = "aes128-cbc";
                                    break;
                                case "aes-192":
                                    algorithm = "aes192-cbc";
                                    break;
                                case "aes-256":
                                    algorithm = "aes256-cbc";
                                    break;
                                default:
                                    break;
                            }
                            encrypt_pkcs8_private(private_key, passphrase, algorithm).then(function (data) {
                                private_key = data;
                                $("#generate_div_public").removeAttr("hidden");
                                $("#generate_publicKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + public_key + '</textarea>');
                                $("#generate_div_private").removeAttr("hidden");
                                $("#generate_privateKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + private_key + '</textarea>');
                                const h = $(document).height() - $(window).height();
                                $(document).scrollTop(h);
                                element.progress('keypair_generate_loading', '100%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_generate_loading', '0%');
                                    document.getElementById("generating_keypair").style.display = "none";
                                }, 500);
                            })
                        } else {
                            switch (keypair_generate_algorithm) {
                                case "des-ede3":
                                    algorithm = "DES-EDE3-CBC";
                                    break;
                                case "aes-128":
                                    algorithm = "AES-128-CBC";
                                    break;
                                case "aes-192":
                                    algorithm = "AES-192-CBC";
                                    break;
                                case "aes-256":
                                    algorithm = "AES-256-CBC";
                                    break;
                                case "des-cbc":
                                    algorithm = "DES-CBC";
                                    break;
                                default:
                                    break;
                            }
                            encrypt_pkcs1_private(private_key, passphrase, algorithm).then(function (data) {
                                private_key = data;
                                $("#generate_div_public").removeAttr("hidden");
                                $("#generate_publicKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + public_key + '</textarea>');
                                $("#generate_div_private").removeAttr("hidden");
                                $("#generate_privateKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + private_key + '</textarea>');
                                const h = $(document).height() - $(window).height();
                                $(document).scrollTop(h);
                                element.progress('keypair_generate_loading', '100%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_generate_loading', '0%');
                                    document.getElementById("generating_keypair").style.display = "none";
                                }, 500);
                            })
                        }
                    }
                }, 100);

            }).catch(function (reason) {
                $("#generate_div_public").removeAttr("hidden");
                $("#generate_publicKey").html('<textarea name="keypair_generate_publicKey_result" readonly class="layui-textarea">' + reason + '</textarea>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                setTimeout(function () {
                    layer.close(index);
                    element.progress('keypair_generate_loading', '0%');
                    document.getElementById("generating_keypair").style.display = "none";
                }, 500);
            });
        }, 100);
        return false;
    });

    form.on('select(keypair_passphrase_format)', function (data) {
        data.value === "pkcs1" ? $("#keypair_passphrase_algorithm_select").html('<option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="des-cbc">DES-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-192">AES-192-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>') : $("#keypair_passphrase_algorithm_select").html('                <option value="des-ede3">DES-EDE3-CBC</option>\n' +
            '                <option value="aes-128">AES-128-CBC</option>\n' +
            '                <option value="aes-256">AES-256-CBC</option>');
        form.render("select");
    });

    form.on('submit(passphrase_keypair_modify)', function (data) {
        const keypair_passphrase_algorithm = data.field.keypair_passphrase_algorithm;
        const keypair_passphrase_format = data.field.keypair_passphrase_format;
        let new_passphrase = data.field.passphrase;
        let private_key = data.field.passphrase_private_key;
        let passphrase = data.field.private_passphrase;
        let result = "";
        let algorithm = "";
        const format = getPrivateFormat(private_key);
        if (format === null) {
            result = Language.get("error_format_key_not_supported");
            $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            return false;
        }
        $("#keypair_passphrase_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#keypair_passphrase_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_passphrase_loading', '25%');
        setTimeout(function () {
            if (new_passphrase === "" && passphrase === "") {
                result = private_key;
            } else if (new_passphrase === "" && passphrase !== "") {
                // Clear Passphrase
                switch (format) {
                    case "pkcs1":
                        decrypt_pkcs1_private(private_key, passphrase, keypair_passphrase_format).then(function (data) {
                            result = data;
                            $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        });
                        break;
                    case "pkcs8":
                        decrypt_pkcs8_private(private_key, passphrase, keypair_passphrase_format).then(function (data) {
                            result = data;
                            $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        });
                        break;
                }
            } else if (new_passphrase !== "" && passphrase === "") {
                // Add passphrase
                private_key = private_converter(private_key, format, keypair_passphrase_format);
                switch (keypair_passphrase_format) {
                    case "pkcs1":
                        switch (keypair_passphrase_algorithm) {
                            case "des-ede3":
                                algorithm = "DES-EDE3-CBC";
                                break;
                            case "aes-128":
                                algorithm = "AES-128-CBC";
                                break;
                            case "aes-192":
                                algorithm = "AES-192-CBC";
                                break;
                            case "aes-256":
                                algorithm = "AES-256-CBC";
                                break;
                            case "des-cbc":
                                algorithm = "DES-CBC";
                                break;
                            default:
                                break;
                        }
                        encrypt_pkcs1_private(private_key, new_passphrase, algorithm).then(function (data) {
                            result = data;
                            $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        });
                        break;
                    case "pkcs8":
                        switch (keypair_passphrase_algorithm) {
                            case "des-ede3":
                                algorithm = "des-ede3-cbc";
                                break;
                            case "aes-128":
                                algorithm = "aes128-cbc";
                                break;
                            case "aes-192":
                                algorithm = "aes192-cbc";
                                break;
                            case "aes-256":
                                algorithm = "aes256-cbc";
                                break;
                            default:
                                break;
                        }
                        encrypt_pkcs8_private(private_key, new_passphrase, algorithm).then(function (data) {
                            result = data;
                            $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        })
                }
            } else if (new_passphrase !== "" && passphrase !== "") {
                // Modify Passphrase
                switch (format) {
                    case "pkcs1":
                        decrypt_pkcs1_private(private_key, passphrase, keypair_passphrase_format).then(function (data) {
                            result = data;
                            switch (keypair_passphrase_format) {
                                case "pkcs1":
                                    switch (keypair_passphrase_algorithm) {
                                        case "des-ede3":
                                            algorithm = "DES-EDE3-CBC";
                                            break;
                                        case "aes-128":
                                            algorithm = "AES-128-CBC";
                                            break;
                                        case "aes-192":
                                            algorithm = "AES-192-CBC";
                                            break;
                                        case "aes-256":
                                            algorithm = "AES-256-CBC";
                                            break;
                                        case "des-cbc":
                                            algorithm = "DES-CBC";
                                            break;
                                        default:
                                            break;
                                    }
                                    encrypt_pkcs1_private(data, new_passphrase, algorithm).then(function (final) {
                                        result = final;
                                        $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                    break;
                                case "pkcs8":
                                    switch (keypair_passphrase_algorithm) {
                                        case "des-ede3":
                                            algorithm = "des-ede3-cbc";
                                            break;
                                        case "aes-128":
                                            algorithm = "aes128-cbc";
                                            break;
                                        case "aes-192":
                                            algorithm = "aes192-cbc";
                                            break;
                                        case "aes-256":
                                            algorithm = "aes256-cbc";
                                            break;
                                        default:
                                            break;
                                    }
                                    encrypt_pkcs8_private(data, new_passphrase, algorithm).then(function (final) {
                                        result = final;
                                        $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                    break;
                            }
                        });
                        break;
                    case "pkcs8":
                        decrypt_pkcs8_private(private_key, passphrase, keypair_passphrase_format).then(function (data) {
                            result = data;
                            switch (keypair_passphrase_format) {
                                case "pkcs1":
                                    switch (keypair_passphrase_algorithm) {
                                        case "des-ede3":
                                            algorithm = "DES-EDE3-CBC";
                                            break;
                                        case "aes-128":
                                            algorithm = "AES-128-CBC";
                                            break;
                                        case "aes-192":
                                            algorithm = "AES-192-CBC";
                                            break;
                                        case "aes-256":
                                            algorithm = "AES-256-CBC";
                                            break;
                                        case "des-cbc":
                                            algorithm = "DES-CBC";
                                            break;
                                        default:
                                            break;
                                    }
                                    encrypt_pkcs1_private(data, new_passphrase, algorithm).then(function (final) {
                                        result = final;
                                        $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                    break;
                                case "pkcs8":
                                    switch (keypair_passphrase_algorithm) {
                                        case "des-ede3":
                                            algorithm = "des-ede3-cbc";
                                            break;
                                        case "aes-128":
                                            algorithm = "aes128-cbc";
                                            break;
                                        case "aes-192":
                                            algorithm = "aes192-cbc";
                                            break;
                                        case "aes-256":
                                            algorithm = "aes256-cbc";
                                            break;
                                        default:
                                            break;
                                    }
                                    encrypt_pkcs8_private(data, new_passphrase, algorithm).then(function (final) {
                                        result = final;
                                        $("#passphrase_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="passphrase_result"><textarea name="keypair_passphrase_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                    break;
                            }
                        });
                        break;
                }
            }
        }, 500);
        return false;
    });

    form.on('select(keypair_convert_passphrase)', function (data) {
        if (data.value === "enabled") {
            $("#div_keypair_private_convert").removeAttr("hidden");
            $("#convert_passphrase").attr("lay-verify", "check_passphrase");
        } else {
            $("#div_keypair_private_convert").attr("hidden", true);
            $("#convert_passphrase").removeAttr("lay-verify", "");
        }
    });

    form.on('select(keypair_convert_decrypt)', function (data) {
        if (data.value === "no") {
            layer.tips(Language.get("keep_encrypted_tips"), data.othis, {
                tips: [1, '#3595CC'],
                time: 6000
            });
        }
    });

    form.on('submit(convert_keypair_do)', function (data) {
        const convert_private_key = data.field.convert_private_key;
        const isPassphrase = data.field.isPassphrase === "enabled";
        const keypair_convert_decrypt = data.field.keypair_convert_decrypt === "yes";
        const keypair_generate_format = data.field.keypair_generate_format;
        const passphrase = data.field.passphrase;
        const key_type = getKeyType(convert_private_key);
        let result = "";
        if (key_type === "unknown") {
            result = Language.get("error_format_key_not_supported");
            $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            return false;
        }
        $("#converting_keypair").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#converting_keypair")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_convert_loading', '25%');
        if (!isPassphrase && key_type === "private") {
            switch (keypair_generate_format) {
                case "pkcs1":
                    element.progress('keypair_convert_loading', '50%');
                    result = private_converter(convert_private_key, "pkcs1", "pkcs8");
                    break;
                case "pkcs8":
                    element.progress('keypair_convert_loading', '50%');
                    result = private_converter(convert_private_key, "pkcs8", "pkcs1");
                    break;
            }
            element.progress('keypair_convert_loading', '75%');
            $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            element.progress('keypair_passphrase_loading', '100%');
            setTimeout(function () {
                layer.close(index);
                element.progress('keypair_passphrase_loading', '0%');
                document.getElementById("keypair_passphrase_loading").style.display = "none";
            }, 500);
        } else if (!isPassphrase && key_type === "public") {
            switch (keypair_generate_format) {
                case "pkcs1":
                    element.progress('keypair_convert_loading', '50%');
                    result = public_converter(convert_private_key, "pkcs1", "pkcs8");
                    break;
                case "pkcs8":
                    result = public_converter(convert_private_key, "pkcs8", "pkcs1");
                    break;
            }
            element.progress('keypair_convert_loading', '75%');
            $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            element.progress('keypair_passphrase_loading', '100%');
            setTimeout(function () {
                layer.close(index);
                element.progress('keypair_passphrase_loading', '0%');
                document.getElementById("keypair_passphrase_loading").style.display = "none";
            }, 500);
        } else if (isPassphrase) {
            // Encrypted Private Key
            if (key_type === "public") {
                switch (keypair_generate_format) {
                    case "pkcs1":
                        element.progress('keypair_convert_loading', '50%');
                        result = public_converter(convert_private_key, "pkcs1", "pkcs8");
                        break;
                    case "pkcs8":
                        result = public_converter(convert_private_key, "pkcs8", "pkcs1");
                        break;
                }
                element.progress('keypair_convert_loading', '75%');
                $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                element.progress('keypair_passphrase_loading', '100%');
                setTimeout(function () {
                    layer.close(index);
                    element.progress('keypair_passphrase_loading', '0%');
                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                }, 500);
            } else if (key_type === "private") {
                const private_format = getPrivateFormat(convert_private_key);
                switch (private_format) {
                    case "pkcs1":
                        if (keypair_convert_decrypt) {
                            decrypt_pkcs1_private(convert_private_key, passphrase, "pkcs8").then(function (data) {
                                element.progress('keypair_convert_loading', '75%');
                                $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + data + '</textarea></blockquote>');
                                const h = $(document).height() - $(window).height();
                                $(document).scrollTop(h);
                                element.progress('keypair_passphrase_loading', '100%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_passphrase_loading', '0%');
                                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                                }, 500);
                            });
                        } else {
                            decrypt_pkcs1_private(convert_private_key, passphrase, "pkcs8").then(function (data) {
                                element.progress('keypair_convert_loading', '50%');
                                setTimeout(function () {
                                    encrypt_pkcs8_private(data, passphrase, "aes256-cbc").then(function (final) {
                                        element.progress('keypair_convert_loading', '75%');
                                        $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + final + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                }, 500)
                            });
                        }
                        break;
                    case "pkcs8":
                        if (keypair_convert_decrypt) {
                            decrypt_pkcs8_private(convert_private_key, passphrase, "pkcs1").then(function (data) {
                                element.progress('keypair_convert_loading', '75%');
                                $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + data + '</textarea></blockquote>');
                                const h = $(document).height() - $(window).height();
                                $(document).scrollTop(h);
                                element.progress('keypair_passphrase_loading', '100%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_passphrase_loading', '0%');
                                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                                }, 500);
                            });
                        } else {
                            decrypt_pkcs8_private(convert_private_key, passphrase, "pkcs1").then(function (data) {
                                element.progress('keypair_convert_loading', '50%');
                                setTimeout(function () {
                                    encrypt_pkcs1_private(data, passphrase, "AES-256-CBC").then(function (final) {
                                        element.progress('keypair_convert_loading', '75%');
                                        $("#convert_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="convert_result"><textarea name="keypair_convert_result_text" readonly class="layui-textarea">' + final + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        element.progress('keypair_passphrase_loading', '100%');
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    });
                                }, 500)
                            });
                        }
                        break;
                }
            }
        }
        return false;
    });

    form.on('select(keypair_extract_passphrase)', function (data) {
        if (data.value === "enabled") {
            $("#extract_passphrase").attr("lay-verify", "check_passphrase");
            $("#div_extract_key").removeAttr("hidden");
        } else {
            $("#div_extract_key").attr("hidden", true);
            $("#extract_passphrase").removeAttr("lay-verify");
        }
    });

    form.on('submit(extract_keypair_do)', function (data) {
        const extract_private_key = data.field.extract_private_key;
        const isPassphrase = data.field.isPassphrase;
        const keypair_extract_format = data.field.keypair_extract_format;
        const private_passphrase = data.field.private_passphrase;
        let result = "";
        const key_format = getPrivateFormat(extract_private_key);
        if (key_format === null) {
            result = Language.get("error_format_key_not_supported");
            $("#extract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="extract_result"><textarea name="keypair_extract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            return false;
        }
        $("#keypair_extract_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#keypair_extract_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('extract_passphrase_loading', '25%');
        if (isPassphrase) {
            switch (key_format) {
                case "pkcs1":
                    decrypt_pkcs1_private(extract_private_key, private_passphrase, key_format).then(function (data) {
                        setTimeout(function () {
                            result = extract_public(data, key_format, keypair_extract_format);
                            element.progress('extract_passphrase_loading', '75%');
                            $("#extract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="extract_result"><textarea name="keypair_extract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        }, 500);
                    });
                    break;
                case "pkcs8":
                    decrypt_pkcs8_private(extract_private_key, private_passphrase, key_format).then(function (data) {
                        setTimeout(function () {
                            result = extract_public(data, key_format, keypair_extract_format);
                            element.progress('extract_passphrase_loading', '75%');
                            $("#extract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="extract_result"><textarea name="keypair_extract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                            const h = $(document).height() - $(window).height();
                            $(document).scrollTop(h);
                            element.progress('keypair_passphrase_loading', '100%');
                            setTimeout(function () {
                                layer.close(index);
                                element.progress('keypair_passphrase_loading', '0%');
                                document.getElementById("keypair_passphrase_loading").style.display = "none";
                            }, 500);
                        }, 500);
                    });
                    break;

            }
        } else {
            setTimeout(function () {
                result = extract_public(extract_private_key, key_format, keypair_extract_format);
                element.progress('extract_passphrase_loading', '75%');
                $("#extract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="extract_result"><textarea name="keypair_extract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                element.progress('keypair_passphrase_loading', '100%');
                setTimeout(function () {
                    layer.close(index);
                    element.progress('keypair_passphrase_loading', '0%');
                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                }, 500);
            }, 500);
        }

        return false;
    });

    form.on('submit(check_keypair_do)', function (data) {
        const check_private_key = data.field.check_private_key;
        const check_public_key = data.field.check_public_key;
        const private_passphrase = data.field.private_passphrase;
        let result = "";
        const publicKey_format = getPublicFormat(check_public_key);
        const private_format = getPrivateFormat(check_private_key);
        if (publicKey_format === null || private_format === null) {
            result = Language.get("error_format_key_not_supported");
            layer.msg(result, function () {
                return false;
            });
            return false;
        }
        $("#keypair_check_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#keypair_check_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('check_passphrase_loading', '25%');
        if (private_passphrase.trim() === "") {
            setTimeout(function () {
                result = extract_public(check_private_key, private_format, publicKey_format);
                let matched = false;
                element.progress('check_passphrase_loading', '50%');
                setTimeout(function () {
                    try {
                        let newPublic = new rsa();
                        newPublic.importKey(result, publicKey_format + '-public-pem');
                        let oldPublic = new rsa();
                        oldPublic.importKey(check_public_key, publicKey_format + '-public-pem');
                        assert.strictEqual(newPublic.exportKey(publicKey_format + "-public").trim(), oldPublic.exportKey(publicKey_format + "-public").trim());
                        matched = true;
                        result = Language.get("check_is_matched");
                    } catch (e) {
                        e instanceof assert.AssertionError ? result = Language.get("check_not_matched") : result = e.toString();
                        matched = false;
                    }
                    element.progress('extract_passphrase_loading', '75%');
                    setTimeout(function () {
                        layer.close(index);
                        element.progress('keypair_passphrase_loading', '0%');
                        document.getElementById("keypair_passphrase_loading").style.display = "none";
                        if (matched) {
                            layer.msg(result);
                        } else {
                            layer.msg(result, function () {
                                return false;
                            });
                        }
                    }, 500);
                }, 500);
            }, 500);
        } else {
            switch (private_format) {
                case "pkcs1":
                    decrypt_pkcs1_private(check_private_key, private_passphrase, private_format).then(function (data) {
                        setTimeout(function () {
                            result = extract_public(data, private_format, publicKey_format);
                            let matched = false;
                            element.progress('check_passphrase_loading', '50%');
                            setTimeout(function () {
                                try {
                                    let newPublic = new rsa();
                                    newPublic.importKey(result, publicKey_format + '-public-pem');
                                    let oldPublic = new rsa();
                                    oldPublic.importKey(check_public_key, publicKey_format + '-public-pem');
                                    assert.strictEqual(newPublic.exportKey(publicKey_format + "-public").trim(), oldPublic.exportKey(publicKey_format + "-public").trim());
                                    matched = true;
                                    result = Language.get("check_is_matched");
                                } catch (e) {
                                    e instanceof assert.AssertionError ? result = Language.get("check_not_matched") : result = e.toString();
                                    matched = false;
                                }
                                element.progress('extract_passphrase_loading', '75%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_passphrase_loading', '0%');
                                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                                    if (matched) {
                                        layer.msg(result);
                                    } else {
                                        layer.msg(result, function () {
                                            return false;
                                        });
                                    }
                                }, 500);
                            }, 500);
                        }, 500);
                    });
                    break;
                case "pkcs8":
                    decrypt_pkcs8_private(check_private_key, private_passphrase, private_format).then(function (data) {
                        setTimeout(function () {
                            result = extract_public(data, private_format, publicKey_format);
                            let matched = false;
                            element.progress('check_passphrase_loading', '50%');
                            setTimeout(function () {
                                try {
                                    let newPublic = new rsa();
                                    newPublic.importKey(result, publicKey_format + '-public-pem');
                                    let oldPublic = new rsa();
                                    oldPublic.importKey(check_public_key, publicKey_format + '-public-pem');
                                    assert.strictEqual(newPublic.exportKey(publicKey_format + "-public").trim(), oldPublic.exportKey(publicKey_format + "-public").trim());
                                    matched = true;
                                    result = Language.get("check_is_matched");
                                } catch (e) {
                                    e instanceof assert.AssertionError ? result = Language.get("check_not_matched") : result = e.toString();
                                    matched = false;
                                }
                                element.progress('extract_passphrase_loading', '75%');
                                setTimeout(function () {
                                    layer.close(index);
                                    element.progress('keypair_passphrase_loading', '0%');
                                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                                    if (matched) {
                                        layer.msg(result);
                                    } else {
                                        layer.msg(result, function () {
                                            return false;
                                        });
                                    }
                                }, 500);
                            }, 500);
                        }, 500);
                    });
                    break;
            }
        }
        return false;
    });

    form.on('select(keypair_parse_passphrase)', function (data) {
        if (data.value === "enabled") {
            $("#div_parse_passphrase").removeAttr("hidden");
            $("#parse_passphrase").attr("lay-verify", "check_passphrase");
        } else {
            $("#div_parse_passphrase").attr("hidden", true);
            $("#parse_passphrase").removeAttr("lay-verify", "");
        }
    });

    form.on('submit(parse_keypair_do)', function (data) {
        const isPassphrase = data.field.isPassphrase === "enabled";
        const keypair_modulus_format = data.field.keypair_modulus_format;
        const parse_passphrase = data.field.parse_passphrase;
        const parse_private_key = data.field.parse_private_key;
        const key_type = getKeyType(parse_private_key);
        let format = null;
        let result = "";
        let key_size = "";
        let Max_size = "";
        let key_n = "";
        let key_e = "";
        if (key_type === "unknown") {
            result = Language.get("error_format_key_not_supported");
            $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            return false;
        }
        $("#parsing_keypair").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#parsing_keypair")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_parse_loading', '25%');
        switch (key_type) {
            case "private":
                format = getPrivateFormat(parse_private_key);
                if (format === null) {
                    result = Language.get("error_format_key_not_supported");
                    $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                    return false;
                }
                if (isPassphrase) {
                    switch (format) {
                        case "pkcs1":
                            element.progress('keypair_parse_loading', '50%');
                            setTimeout(function () {
                                decrypt_pkcs1_private(parse_private_key, parse_passphrase, format).then(function (data) {
                                    try {
                                        const key = new rsa();
                                        key.importKey(data, format + "-pem");
                                        key_size = key.getKeySize() + " bits";
                                        Max_size = Language.get("max_encrypted_size_before") + key.getMaxMessageSize() + Language.get("for_encrypt_in_bytes");
                                        key_e = key.keyPair.e.toString(10) + "(0x" + key.keyPair.e.toString(16) + ")";
                                        switch (keypair_modulus_format) {
                                            case "Hex":
                                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                                break;
                                            case "Base64":
                                                key_n = key.keyPair.n.toBuffer().toString("base64");
                                                break;
                                            default:
                                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                                break;
                                        }
                                        element.progress('keypair_parse_loading', '75%');
                                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result">\n' +
                                            '            <table class="layui-table">\n' +
                                            '                <tbody>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_key_size"><script>document.getElementById(\'td_key_size\').innerText = Language.get(\'key_size\')</script></td>\n' +
                                            '                    <td>' + key_size + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_modulus"><script>document.getElementById(\'td_modulus\').innerText = Language.get(\'modulus\')</script></td>\n' +
                                            '                    <td>' + key_n + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_exponent"><script>document.getElementById(\'td_exponent\').innerText = Language.get(\'exponent\')</script></td>\n' +
                                            '                    <td>' + key_e + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_max_size"><script>document.getElementById(\'td_max_size\').innerText = Language.get(\'max_encrypted_size\')</script></td>\n' +
                                            '                    <td>' + Max_size + '</td>\n' +
                                            '                </tr>\n' +
                                            '                </tbody>\n' +
                                            '            </table>\n' +
                                            '        </blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    } catch (e) {
                                        result = e.toString();
                                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        layer.close(index);
                                        element.progress('keypair_passphrase_loading', '0%');
                                        document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        return false;
                                    }
                                });
                            }, 500);
                            break;
                        case "pkcs8":
                            element.progress('keypair_parse_loading', '50%');
                            setTimeout(function () {
                                decrypt_pkcs8_private(parse_private_key, parse_passphrase, format).then(function (data) {
                                    try {
                                        const key = new rsa();
                                        key.importKey(data, format + "-pem");
                                        key_size = key.getKeySize() + " bits";
                                        Max_size = Language.get("max_encrypted_size_before") + key.getMaxMessageSize() + Language.get("for_encrypt_in_bytes");
                                        key_e = key.keyPair.e.toString(10) + "(0x" + key.keyPair.e.toString(16) + ")";
                                        switch (keypair_modulus_format) {
                                            case "Hex":
                                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                                break;
                                            case "Base64":
                                                key_n = key.keyPair.n.toBuffer().toString("base64");
                                                break;
                                            default:
                                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                                break;
                                        }
                                        element.progress('keypair_parse_loading', '75%');
                                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result">\n' +
                                            '            <table class="layui-table">\n' +
                                            '                <tbody>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_key_size"><script>document.getElementById(\'td_key_size\').innerText = Language.get(\'key_size\')</script></td>\n' +
                                            '                    <td>' + key_size + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_modulus"><script>document.getElementById(\'td_modulus\').innerText = Language.get(\'modulus\')</script></td>\n' +
                                            '                    <td>' + key_n + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_exponent"><script>document.getElementById(\'td_exponent\').innerText = Language.get(\'exponent\')</script></td>\n' +
                                            '                    <td>' + key_e + '</td>\n' +
                                            '                </tr>\n' +
                                            '                <tr>\n' +
                                            '                    <td id="td_max_size"><script>document.getElementById(\'td_max_size\').innerText = Language.get(\'max_encrypted_size\')</script></td>\n' +
                                            '                    <td>' + Max_size + '</td>\n' +
                                            '                </tr>\n' +
                                            '                </tbody>\n' +
                                            '            </table>\n' +
                                            '        </blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        setTimeout(function () {
                                            layer.close(index);
                                            element.progress('keypair_passphrase_loading', '0%');
                                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        }, 500);
                                    } catch (e) {
                                        result = e.toString();
                                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        layer.close(index);
                                        element.progress('keypair_passphrase_loading', '0%');
                                        document.getElementById("keypair_passphrase_loading").style.display = "none";
                                        return false;
                                    }
                                });
                            }, 500);
                            break;
                    }
                } else {
                    try {
                        const key = new rsa();
                        key.importKey(parse_private_key, format + "-pem");
                        key_size = key.getKeySize() + " bits";
                        Max_size = Language.get("max_encrypted_size_before") + key.getMaxMessageSize() + Language.get("for_encrypt_in_bytes");
                        key_e = key.keyPair.e.toString(10) + "(0x" + key.keyPair.e.toString(16) + ")";
                        switch (keypair_modulus_format) {
                            case "Hex":
                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                break;
                            case "Base64":
                                key_n = key.keyPair.n.toBuffer().toString("base64");
                                break;
                            default:
                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                break;
                        }
                        element.progress('keypair_parse_loading', '75%');
                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result">\n' +
                            '            <table class="layui-table">\n' +
                            '                <tbody>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_key_size"><script>document.getElementById(\'td_key_size\').innerText = Language.get(\'key_size\')</script></td>\n' +
                            '                    <td>' + key_size + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_modulus"><script>document.getElementById(\'td_modulus\').innerText = Language.get(\'modulus\')</script></td>\n' +
                            '                    <td>' + key_n + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_exponent"><script>document.getElementById(\'td_exponent\').innerText = Language.get(\'exponent\')</script></td>\n' +
                            '                    <td>' + key_e + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_max_size"><script>document.getElementById(\'td_max_size\').innerText = Language.get(\'max_encrypted_size\')</script></td>\n' +
                            '                    <td>' + Max_size + '</td>\n' +
                            '                </tr>\n' +
                            '                </tbody>\n' +
                            '            </table>\n' +
                            '        </blockquote>');
                        const h = $(document).height() - $(window).height();
                        $(document).scrollTop(h);
                        setTimeout(function () {
                            layer.close(index);
                            element.progress('keypair_passphrase_loading', '0%');
                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                        }, 500);
                    } catch (e) {
                        result = e.toString();
                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                        layer.close(index);
                        element.progress('keypair_passphrase_loading', '0%');
                        document.getElementById("keypair_passphrase_loading").style.display = "none";
                        return false;
                    }
                }
                break;
            case "public":
                format = getPublicFormat(parse_private_key);
                if (format === null) {
                    result = Language.get("error_format_key_not_supported");
                    $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                    layer.close(index);
                    element.progress('keypair_passphrase_loading', '0%');
                    document.getElementById("keypair_passphrase_loading").style.display = "none";
                    return false;
                } else {
                    try {
                        const key = new rsa();
                        key.importKey(parse_private_key, format + "-public-pem");
                        key_size = key.getKeySize() + " bits";
                        Max_size = Language.get("max_encrypted_size_before") + key.getMaxMessageSize() + Language.get("for_encrypt_in_bytes");
                        key_e = key.keyPair.e.toString(10) + "(0x" + key.keyPair.e.toString(16) + ")";
                        switch (keypair_modulus_format) {
                            case "Hex":
                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                break;
                            case "Base64":
                                key_n = key.keyPair.n.toBuffer().toString("base64");
                                break;
                            default:
                                key_n = key.keyPair.n.toBuffer().toString("hex");
                                break;
                        }
                        element.progress('keypair_parse_loading', '75%');
                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result">\n' +
                            '            <table class="layui-table">\n' +
                            '                <tbody>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_key_size"><script>document.getElementById(\'td_key_size\').innerText = Language.get(\'key_size\')</script></td>\n' +
                            '                    <td>' + key_size + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_modulus"><script>document.getElementById(\'td_modulus\').innerText = Language.get(\'modulus\')</script></td>\n' +
                            '                    <td>' + key_n + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_exponent"><script>document.getElementById(\'td_exponent\').innerText = Language.get(\'exponent\')</script></td>\n' +
                            '                    <td>' + key_e + '</td>\n' +
                            '                </tr>\n' +
                            '                <tr>\n' +
                            '                    <td id="td_max_size"><script>document.getElementById(\'td_max_size\').innerText = Language.get(\'max_encrypted_size\')</script></td>\n' +
                            '                    <td>' + Max_size + '</td>\n' +
                            '                </tr>\n' +
                            '                </tbody>\n' +
                            '            </table>\n' +
                            '        </blockquote>');
                        const h = $(document).height() - $(window).height();
                        $(document).scrollTop(h);
                        setTimeout(function () {
                            layer.close(index);
                            element.progress('keypair_passphrase_loading', '0%');
                            document.getElementById("keypair_passphrase_loading").style.display = "none";
                        }, 500);
                    } catch (e) {
                        result = e.toString();
                        $("#parse_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="parse_result"><textarea name="keypair_parse_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                        return false;
                    }
                }
                break;
        }

        return false;
    });

    form.on('select(keypair_padding)', function (data) {
        if (data.value === "6") {
            $("#keypair_salt_len").removeAttr("disabled");
        } else {
            $("#keypair_salt_len").attr("disabled", true);
        }
        form.render('select');
    });

    form.on('select(keypair_sign_operate)', function (data) {
        if (data.value === "sign") {
            $("#sign_private_key").attr("lay-verify", "check_private");
            $("#div_sign_private").removeAttr("hidden");
            $("#div_sign_passphrase").removeAttr("hidden");
            $("#sign_public_key").removeAttr("lay-verify");
            $("#div_sign_public").attr("hidden", true);
            $("#div_signature").attr("hidden", true);
            $("#sign_signature").removeAttr("lay-verify");
            //$("#div_sign_encode").attr("hidden", true);
        } else {
            $("#div_sign_public").removeAttr("hidden");
            $("#sign_public_key").attr("lay-verify", "check_public");
            $("#div_sign_passphrase").attr("hidden", true);
            $("#sign_private_key").removeAttr("lay-verify");
            $("#div_sign_private").attr("hidden", true);
            $("#div_signature").removeAttr("hidden");
            $("#sign_signature").attr("lay-verify", "check_sign");
            //$("#div_sign_encode").removeAttr("hidden");
        }
        form.render('select');
    });

    form.on('submit(sign_keypair_do)', function (data) {
        const keypair_padding = parseInt(data.field.keypair_padding);
        const keypair_salt_len = parseInt(data.field.keypair_salt_len);
        const keypair_sign_algorithm = data.field.keypair_sign_algorithm;
        const keypair_sign_in_coding = data.field.keypair_sign_in_coding;
        const keypair_sign_operate = data.field.keypair_sign_operate;
        const keypair_sign_out_coding = data.field.keypair_sign_out_coding;
        const sign_message = data.field.sign_message;
        const sign_passphrase = data.field.sign_passphrase;
        const sign_private_key = data.field.sign_private_key;
        const sign_public_key = data.field.sign_public_key;
        const sign_signature = data.field.sign_signature;
        let result = "";
        switch (keypair_sign_operate) {
            case "sign":
                const sign = crypto.createSign(keypair_sign_algorithm);
                sign.update(Buffer.from(sign_message, keypair_sign_in_coding));
                let signature;
                try {
                    if (keypair_padding === 1) {
                        signature = sign.sign({
                            key: sign_private_key,
                            passphrase: sign_passphrase,
                            padding: keypair_padding
                        }, keypair_sign_out_coding);
                        result = signature;
                    } else {
                        signature = sign.sign({
                            key: sign_private_key,
                            passphrase: sign_passphrase,
                            padding: keypair_padding,
                            saltLength: keypair_salt_len
                        }, keypair_sign_out_coding);
                        result = signature;
                    }
                } catch (e) {
                    result = e.toString();
                }
                break;
            case "verify":
                try {
                    const verify = crypto.createVerify(keypair_sign_algorithm);
                    verify.update(Buffer.from(sign_message, keypair_sign_in_coding));
                    const isVerify = verify.verify(sign_public_key, sign_signature, keypair_sign_out_coding);
                    if (isVerify) {
                        result = Language.get("verify_result") + ": True";
                    } else {
                        result = Language.get("verify_result") + ": False";
                    }
                } catch (e) {
                    result = e.toString();
                }
                break;
        }
        $("#sign_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="sign_result"><textarea name="keypair_sign_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        return false;
    });

    form.on(('select(x509_cert_format)'), function (data) {
        let element = "";

        $("#keypair_x509_cert_salt").attr("lay-verify", "");
        $("#keypair_x509_cert_salt").attr("disabled", true);
        $("#keypair_x509_cert_salt").val("");
        $("#keypair_x509_cert_salt").attr("class", "layui-input layui-disabled");

        document.getElementById('keypair_x509_cert_salt').setAttribute("placeholder", Language.get('no_need_salt'));
        switch (data.value) {
            case "1":
                element = "<option value=\"ecdsa-with-sha256\">ECDSAWithSHA256</option>\n" +
                    "                <option value=\"ecdsa-with-sha384\">ECDSAWithSHA384</option>\n" +
                    "                <option value=\"ecdsa-with-sha512\">ECDSAWithSHA512</option>\n" +
                    "                <option value=\"ecdsa-with-sha1\">ECDSAWithSHA1</option>";
                break;
            case "3":
                element = "<option value=\"sha256WithRSAEncryption\">SHA256WithRSA</option>\n" +
                    "                <option value=\"sha384WithRSAEncryption\">SHA384WithRSA</option>\n" +
                    "                <option value=\"sha512WithRSAEncryption\">SHA512WithRSA</option>\n" +
                    "                <option value=\"sha1WithRSAEncryption\">SHA1WithRSA</option>";
                break;
            case "2":
                element = "<option value=\"SHA-1\">SHA-1</option>\n" +
                    "                <option value=\"SHA-256\">SHA-256</option>\n" +
                    "                <option value=\"SHA-384\">SHA-382</option>\n" +
                    "                <option value=\"SHA-512\">SHA-512</option>";
                $("#keypair_x509_cert_salt").attr("lay-verify", "check_salt");
                $("#keypair_x509_cert_salt").attr("class", "layui-input");
                $("#keypair_x509_cert_salt").removeAttr("disabled");
                document.getElementById('keypair_x509_cert_salt').setAttribute("placeholder", Language.get('salt_tips'));
                break;
        }
        document.getElementById("x509_cert_algorithm").innerHTML = element;
        form.render("select");
    });

    form.on('submit(x509_host_keypair_do)', function (data) {
        const x509_host = data.field.x509_host;
        let x509_port = "";
        data.field.x509_port === "" ? x509_port = "443" : x509_port = data.field.x509_port;
        const rejectUnauthorized = data.field.rejectunauthorized === "on";
        let result = "";
        $("#x509_keypair_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#x509_keypair_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_x509_loading', '25%');
        try {
            element.progress('keypair_x509_loading', '50%');

            const options = {
                hostname: x509_host,
                port: parseInt(x509_port),
                path: '/',
                method: 'GET'
            };

            const req = https.request(options, (res) => {
                element.progress('keypair_x509_loading', '75%');
                X509Cert(parseInt(x509_port), x509_host, {
                    rejectUnauthorized: rejectUnauthorized,
                    servername: x509_host
                }, (err, certificate) => {
                    if (err) {
                        result = err.toString();
                    }
                    result = certificate;
                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
                    const h = $(document).height() - $(window).height();
                    $(document).scrollTop(h);
                    layer.close(index);
                    element.progress('keypair_sign_loading', '0%');
                    document.getElementById("signing_keypair").style.display = "none";
                });
            });

            req.on('error', (e) => {
                result = e.toString();
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                layer.close(index);
                element.progress('keypair_sign_loading', '0%');
                document.getElementById("signing_keypair").style.display = "none";
            });
            req.end();
        } catch (e) {
            result = Language.get(e.toString());
            $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            layer.close(index);
            element.progress('keypair_sign_loading', '0%');
            document.getElementById("signing_keypair").style.display = "none";
        }

        return false;

    });

    form.on('submit(x509_private_keypair_do)', function (data) {
        const x509_passphrase = data.field.x509_passphrase;
        const x509_private_key = data.field.x509_private_key;
        const x509_cert_algorithm = data.field.x509_cert_algorithm;
        const x509_cert_format = data.field.x509_cert_format;
        const x509_cert_info = data.field.x509_cert_info;
        const x509_days = data.field.x509_days;
        const x509_salt = data.field.x509_salt;
        const format = getPrivateFormat(x509_private_key);
        const encrypted = x509_passphrase !== "";
        let info;
        let result = "";
        if (format === null) {
            result = Language.get("error_format_key_not_supported");
            $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            return false;
        }
        try {
            info = JSON.parse(x509_cert_info);
            let pass = undefined;
            info["countryName"] === undefined ? pass = Language.get("info_not_parse") + " countryName" : pass = undefined;
            info["stateOrProvinceName"] === undefined ? pass = Language.get("info_not_parse") + " stateOrProvinceName" : pass = undefined;
            info["localityName"] === undefined ? pass = Language.get("info_not_parse") + " localityName" : pass = undefined;
            info["organizationName"] === undefined ? pass = Language.get("info_not_parse") + " organizationName" : pass = undefined;
            info["organizationalUnitName"] === undefined ? pass = Language.get("info_not_parse") + " organizationalUnitName" : pass = undefined;
            info["commonName"] === undefined ? pass = Language.get("info_not_parse") + " commonName" : pass = undefined;
            if (pass !== undefined) {
                result = pass.toString();
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                return false;
            }
        } catch (e) {
            result = e.toString();
            $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            return false;
        }
        $("#x509_keypair_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#x509_keypair_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('keypair_x509_loading', '25%');
        if (encrypted) {
            try {
                switch (format) {
                    case "pkcs1":
                        decrypt_pkcs1_private(x509_private_key, x509_passphrase, "pkcs8").then(function (data) {
                            element.progress('keypair_x509_loading', '75%');
                            setTimeout(() => {
                                privateToJWK(data).then(function (jwk) {
                                    try {
                                        switch (x509_cert_format) {
                                            default:
                                                X509Utils.fromJwk(
                                                    jwk["public"],
                                                    jwk["private"],
                                                    'pem',
                                                    {
                                                        signature: x509_cert_algorithm, // signature algorithm
                                                        days: parseInt(x509_days), // expired in days
                                                        issuer: info, // issuer
                                                        subject: info // assume that issuer = subject, i.e., self-signed certificate
                                                    },
                                                    'pem' // output signature is in PEM. DER-encoded signature is available with 'der'.
                                                ).then((cert) => {
                                                    // now you get the certificate in PEM string
                                                    result = cert;
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                }).catch(() => {
                                                    result = Language.get("jwk_error");
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                });
                                                break;
                                            case "2":
                                                X509Utils.fromJwk(
                                                    jwk["public"],
                                                    jwk["private"],
                                                    'pem',
                                                    {
                                                        signature: 'rsassaPss',
                                                        days: parseInt(x509_days),
                                                        issuer: info,
                                                        subject: info,
                                                        pssParams: {
                                                            saltLength: parseInt(x509_salt), // if unspecified, 20 will be applied as default value
                                                            hash: x509_cert_algorithm // if unspecified, 'SHA-1' will be applied as default value (but I do not not recommend SHA-1)
                                                        }
                                                    }
                                                ).then((cert) => {
                                                    // now you get a certificate
                                                    result = cert;
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                }).catch(() => {
                                                    result = Language.get("jwk_error");
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                });
                                                break;
                                        }
                                    } catch (e) {
                                        result = e.toString();
                                        $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        layer.close(index);
                                        element.progress('keypair_x509_loading', '0%');
                                        document.getElementById("x509_keypair_loading").style.display = "none";
                                    }

                                })
                            }, 500);
                        });
                        break;
                    case "pkcs8":
                        decrypt_pkcs8_private(x509_private_key, x509_passphrase, "pkcs8").then(function (data) {
                            element.progress('keypair_x509_loading', '75%');
                            setTimeout(() => {
                                privateToJWK(data).then(function (jwk) {
                                    try {
                                        switch (x509_cert_format) {
                                            default:
                                                X509Utils.fromJwk(
                                                    jwk["public"],
                                                    jwk["private"],
                                                    'pem',
                                                    {
                                                        signature: x509_cert_algorithm, // signature algorithm
                                                        days: parseInt(x509_days), // expired in days
                                                        issuer: info, // issuer
                                                        subject: info // assume that issuer = subject, i.e., self-signed certificate
                                                    },
                                                    'pem' // output signature is in PEM. DER-encoded signature is available with 'der'.
                                                ).then((cert) => {
                                                    // now you get the certificate in PEM string
                                                    result = cert;
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                }).catch(() => {
                                                    result = Language.get("jwk_error");
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                });
                                                break;
                                            case "2":
                                                X509Utils.fromJwk(
                                                    jwk["public"],
                                                    jwk["private"],
                                                    'pem',
                                                    {
                                                        signature: 'rsassaPss',
                                                        days: parseInt(x509_days),
                                                        issuer: info,
                                                        subject: info,
                                                        pssParams: {
                                                            saltLength: parseInt(x509_salt), // if unspecified, 20 will be applied as default value
                                                            hash: x509_cert_algorithm // if unspecified, 'SHA-1' will be applied as default value (but I do not not recommend SHA-1)
                                                        }
                                                    }
                                                ).then((cert) => {
                                                    // now you get a certificate
                                                    result = cert;
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                }).catch(() => {
                                                    result = Language.get("jwk_error");
                                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                    const h = $(document).height() - $(window).height();
                                                    $(document).scrollTop(h);
                                                    layer.close(index);
                                                    element.progress('keypair_x509_loading', '0%');
                                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                                });
                                                break;
                                        }
                                    } catch (e) {
                                        result = e.toString();
                                        $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                        const h = $(document).height() - $(window).height();
                                        $(document).scrollTop(h);
                                        layer.close(index);
                                        element.progress('keypair_x509_loading', '0%');
                                        document.getElementById("x509_keypair_loading").style.display = "none";
                                    }

                                })
                            }, 500);
                        });
                        break;
                }
            } catch (e) {
                result = e.toString();
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                layer.close(index);
                element.progress('keypair_x509_loading', '0%');
                document.getElementById("x509_keypair_loading").style.display = "none";
            }
        } else {
            try {
                switch (format) {
                    case "pkcs1":
                        const data = private_converter(x509_private_key, "pkcs1", "pkcs8");
                        element.progress('keypair_x509_loading', '75%');
                        setTimeout(() => {
                            privateToJWK(data).then(function (jwk) {
                                try {
                                    switch (x509_cert_format) {
                                        default:
                                            X509Utils.fromJwk(
                                                jwk["public"],
                                                jwk["private"],
                                                'pem',
                                                {
                                                    signature: x509_cert_algorithm, // signature algorithm
                                                    days: parseInt(x509_days), // expired in days
                                                    issuer: info, // issuer
                                                    subject: info // assume that issuer = subject, i.e., self-signed certificate
                                                },
                                                'pem' // output signature is in PEM. DER-encoded signature is available with 'der'.
                                            ).then((cert) => {
                                                // now you get the certificate in PEM string
                                                result = cert;
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            }).catch(() => {
                                                result = Language.get("jwk_error");
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            });
                                            break;
                                        case "2":
                                            X509Utils.fromJwk(
                                                jwk["public"],
                                                jwk["private"],
                                                'pem',
                                                {
                                                    signature: 'rsassaPss',
                                                    days: parseInt(x509_days),
                                                    issuer: info,
                                                    subject: info,
                                                    pssParams: {
                                                        saltLength: parseInt(x509_salt), // if unspecified, 20 will be applied as default value
                                                        hash: x509_cert_algorithm // if unspecified, 'SHA-1' will be applied as default value (but I do not not recommend SHA-1)
                                                    }
                                                }
                                            ).then((cert) => {
                                                // now you get a certificate
                                                result = cert;
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            }).catch(() => {
                                                result = Language.get("jwk_error");
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            });
                                            break;
                                    }
                                } catch (e) {
                                    result = e.toString();
                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                    const h = $(document).height() - $(window).height();
                                    $(document).scrollTop(h);
                                    layer.close(index);
                                    element.progress('keypair_x509_loading', '0%');
                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                }

                            })
                        }, 500);
                        break;
                    case "pkcs8":
                        element.progress('keypair_x509_loading', '75%');
                        setTimeout(() => {
                            privateToJWK(x509_private_key).then(function (jwk) {
                                try {
                                    switch (x509_cert_format) {
                                        default:
                                            X509Utils.fromJwk(
                                                jwk["public"],
                                                jwk["private"],
                                                'pem',
                                                {
                                                    signature: x509_cert_algorithm, // signature algorithm
                                                    days: parseInt(x509_days), // expired in days
                                                    issuer: info, // issuer
                                                    subject: info // assume that issuer = subject, i.e., self-signed certificate
                                                },
                                                'pem' // output signature is in PEM. DER-encoded signature is available with 'der'.
                                            ).then((cert) => {
                                                // now you get the certificate in PEM string
                                                result = cert;
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            }).catch(() => {
                                                result = Language.get("jwk_error");
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            });
                                            break;
                                        case "2":
                                            X509Utils.fromJwk(
                                                jwk["public"],
                                                jwk["private"],
                                                'pem',
                                                {
                                                    signature: 'rsassaPss',
                                                    days: parseInt(x509_days),
                                                    issuer: info,
                                                    subject: info,
                                                    pssParams: {
                                                        saltLength: parseInt(x509_salt), // if unspecified, 20 will be applied as default value
                                                        hash: x509_cert_algorithm // if unspecified, 'SHA-1' will be applied as default value (but I do not not recommend SHA-1)
                                                    }
                                                }
                                            ).then((cert) => {
                                                // now you get a certificate
                                                result = cert;
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            }).catch(() => {
                                                result = Language.get("jwk_error");
                                                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                                const h = $(document).height() - $(window).height();
                                                $(document).scrollTop(h);
                                                layer.close(index);
                                                element.progress('keypair_x509_loading', '0%');
                                                document.getElementById("x509_keypair_loading").style.display = "none";
                                            });
                                            break;
                                    }
                                } catch (e) {
                                    result = e.toString();
                                    $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                    const h = $(document).height() - $(window).height();
                                    $(document).scrollTop(h);
                                    layer.close(index);
                                    element.progress('keypair_x509_loading', '0%');
                                    document.getElementById("x509_keypair_loading").style.display = "none";
                                }

                            })
                        }, 500);
                        break;
                }
            } catch (e) {
                result = e.toString();
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                layer.close(index);
                element.progress('keypair_x509_loading', '0%');
                document.getElementById("x509_keypair_loading").style.display = "none";
            }
        }
        return false;
    });

    form.on('submit(x509_public_keypair_do)', function (data) {
        const x509_public = data.field.x509_public;
        const x509_format_out = data.field.x509_format_out;
        let result = "";
        try {
            X509Utils.toJwk(x509_public, 'pem').then(function (value) {
                let key = new rsa();
                key.importKey({
                    n: Buffer.from(value.n, "base64"),
                    e: Buffer.from(value.e, "base64")
                }, 'components-public');
                result = key.exportKey(x509_format_out + "-public");
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
            }).catch(function (err) {
                result = err.toString();
                $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
            });
        } catch (e) {
            result = e.toString();
            $("#x509_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="x509_result"><textarea name="keypair_x509_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
        }
        return false;
    });

    $("#ecdh_generate").click(function () {
        const curve = $("#select_ecdh_curves").val();
        const private_type = $("#ecdh_private_type").val();
        const public_type = $("#ecdh_public_type").val();
        let private_result = "";
        let public_result = "";
        if (curve.trim() === ""){
            layer.msg(Language.get("curves_select"));
            return false;
        }
        try{
            const ecdh  = crypto.createECDH(curve);
            ecdh.generateKeys();
            private_result = ecdh.getPrivateKey(private_type);
            public_result = ecdh.getPublicKey(public_type);
            $("#keypair_ecdh_public").val(public_result);
            $("#keypair_ecdh_private").val(private_result);
            layer.msg(Language.get("success"));
            return true;
        }catch (e) {
            layer.msg(e.toString());
            return false;
        }

    });

    form.on('submit(ecdh_do)', function (data) {
        const ecdh_curves = data.field.ecdh_curves;
        const ecdh_other_type = data.field.ecdh_other_type;
        const ecdh_out_type = data.field.ecdh_out_type;
        const ecdh_private_type = data.field.ecdh_private_type;
        const ecdh_public_type = data.field.ecdh_public_type;
        const keypair_ecdh_private = data.field.keypair_ecdh_private;
        const keypair_ecdh_public = data.field.keypair_ecdh_public;
        const keypair_other_public = data.field.keypair_other_public;
        let result;
        try{
            const ecdh = crypto.createECDH(ecdh_curves);
            ecdh.setPrivateKey(keypair_ecdh_private, ecdh_private_type);
            ecdh.setPublicKey(keypair_ecdh_public, ecdh_public_type);
            result = ecdh.computeSecret(keypair_other_public, ecdh_other_type, ecdh_out_type).toString();
        }catch (e) {
            result = e.toString();
        }
        $("#ecdh_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="ecdh_result"><textarea name="keypair_ecdh_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        return false;
    });

    $("#ecdh_reset").click(() => {
        layer.closeAll();
        $("#ecdh_result_box").html('');
    });
}