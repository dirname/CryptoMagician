var form, $, upload, layer, element, laydate = null;
const { dialog } = require('electron').remote;
const {ipcRenderer} = require('electron');
const scrypt = require('scrypt');
const iconv = require('iconv-lite');

function setEvent(f, j, u, l, e, d) {
    form = f;
    $ = j;
    upload = u;
    layer = l;
    element = e;
    laydate = d;
}

function listen () {
    //Symmetric Algorithm
    form.on('select(algorithm)', function (data) {
        $("#no_mode").attr('disabled', true);
        $("#ecb_mode").prop('selected', 'selected');
        $("#cbc_mode").removeAttr('disabled');
        $("#ofb_mode").removeAttr('disabled');
        $("#ecb_mode").removeAttr('disabled');
        $("#cfb_mode").removeAttr('disabled');
        $("#ctr_mode").removeAttr('disabled');
        $("#gladman_mode").removeAttr('disabled');
        $("#iso97971").removeAttr('disabled');
        $("#no_padding").removeAttr('disabled');
        $("#no_padding").prop('selected', 'selected');
        openssl_ciphers = ["Blowfish", "IDEA", "SEED", "RC2", "CAST5"];
        mcrypt_ciphers = ["GOST", "TWOFISH", "Blowfish-Compat", "SERPENT", "LOKI97", "SAFER", "SAFER+", "XTEA", "3WAY", "CAST128", "CAST256"];
        if ($.inArray(data.value, openssl_ciphers) > -1) {
            $("#ctr_mode").attr('disabled', true);
            $("#gladman_mode").attr('disabled', true);
            $("#iso97971").attr('disabled', true);
            $("#no_padding").attr('disabled', true);
            $("#no_padding").removeAttr("selected", "");
            setMode($("#mode").val());
        } else if ($.inArray(data.value, mcrypt_ciphers) > -1) {
            $("#gladman_mode").attr('disabled', true);
            $("#iso97971").attr('disabled', true);
            $("#no_padding").attr('disabled', true);
            $("#no_padding").removeAttr("selected", "");
            setMode($("#mode").val());
        } else {
            if (data.value === 'CAMELLIA') {
                $("#iso97971").attr('disabled', true);
                $("#no_padding").attr('disabled', true);
                $("#no_padding").removeAttr("selected", "");
                $("#gladman_mode").attr('disabled', true);
            }
            if (data.value === 'CAST') {
                $("#iv").attr({"placeholder": Language.get("please_input_iv")});
                $("#iv").val("");
                $("#cbc_mode").removeAttr('disabled');
                $("#cbc_mode").prop('selected', 'selected');
                $("#gladman_mode").attr('disabled', true);
                $("#ecb_mode").attr('disabled', true);
                $("#cfb_mode").attr('disabled', true);
                $("#ofb_mode").attr('disabled', true);
                $("#ctr_mode").attr('disabled', true);
                $("#gladman_mode").attr('disabled', true);
                $("#ctr_mode").attr('disabled', true);
                $("#gladman_mode").attr('disabled', true);
                $("#iso97971").attr('disabled', true);
                $("#no_padding").attr('disabled', true);
                $("#no_padding").removeAttr("selected", "");
            }
            if (data.value.indexOf('RIJNDAEL') >= 0) {
                $("#gladman_mode").attr('disabled', true);
                $("#iso97971").attr('disabled', true);
                $("#no_padding").attr('disabled', true);
                $("#no_padding").removeAttr("selected", "");
            }
            if (data.value.indexOf("RC4") >= 0) {
                if (data.value === "RC4Drop") {
                    $("#drop_numbers").removeAttr('hidden')
                } else {
                    $("#drop_numbers").attr('hidden', true)
                }
                $("#no_mode").removeAttr('disabled');
                $("#no_mode").prop('selected', 'selected');
                $("#cbc_mode").attr('disabled', true);
                $("#ofb_mode").attr('disabled', true);
                $("#ecb_mode").attr('disabled', true);
                $("#cfb_mode").attr('disabled', true);
                $("#ctr_mode").attr('disabled', true);
                $("#gladman_mode").attr('disabled', true);
                $("#padding").val('NoPadding');
                $("#iv").attr("class", "layui-input layui-disabled");
                $("#iv").attr("disabled", "true");
                $("#iv").removeAttr("lay-verify");
                $("#iv").val(Language.get("mode_not"));
            } else if (data.value.indexOf("Rabbit") >= 0) {
                $("#drop_numbers").attr('hidden', true);
                $("#no_mode").removeAttr('disabled');
                $("#no_mode").prop('selected', 'selected');
                $("#iv").attr("class", "layui-input layui-disabled");
                $("#iv").attr("disabled", "true");
                $("#iv").removeAttr("lay-verify");
                $("#padding").val('NoPadding');
                $("#iv").val(Language.get("mode_not"));
            } else if (data.value.indexOf("CHACHA20") >= 0 || data.value === "WAKE") {
                $("#no_mode").removeAttr('disabled');
                $("#no_mode").prop('selected', 'selected');
                $("#cbc_mode").attr('disabled', true);
                $("#ofb_mode").attr('disabled', true);
                $("#ecb_mode").attr('disabled', true);
                $("#cfb_mode").attr('disabled', true);
                $("#ctr_mode").attr('disabled', true);
                $("#gladman_mode").attr('disabled', true);
                $("#padding").val('NoPadding');
                if (data.value === "WAKE") {
                    $("#iv").val(Language.get("mode_not"));
                    $("#iv").attr("class", "layui-input layui-disabled");
                    $("#iv").attr("disabled", "true");
                    $("#iv").removeAttr("lay-verify");
                } else {
                    $("#iv").removeAttr("disabled");
                    $("#iv").attr({"placeholder": Language.get("please_input_iv"), "class": "layui-input"});
                    $("#iv").attr("lay-verify", "check_iv");
                    $("#iv").val("");
                }
            } else {
                $("#drop_numbers").attr('hidden', true);
                $("#no_mode").attr('disabled', true);
                $("#no_mode").removeAttr("selected", "");
                $("#key").removeAttr("disabled");
                $("#key").attr({"placeholder": Language.get("please_input_key"), "class": "layui-input"});
                $("#key").attr("lay-verify", "check_key");
                $("#key").val("");
                setMode($("#mode").val());
            }
        }
        form.render('select');
    });

    var isFile = false;

    $("#clear-file").click(function () {
        isFile = false;
        $("#textOrFile").html(Language.get("plain_text"));
        $("#action_text").val("");
        $("#action_text").removeAttr("disabled");
        $("#file_tips").remove();
        $("#result_box").html('');
    });

    $("#reset").click(function () {
        isFile = false;
        $("#textOrFile").html(Language.get("plain_text"));
        $("#action_text").val("");
        $("#action_text").removeAttr("disabled");
        $("#file_tips").remove();
        $("#result_box").html('');
        $("#iv").attr("class", "layui-input layui-disabled");
        $("#iv").attr("disabled", "true");
        $("#iv").removeAttr("lay-verify");
        $("#iv").val(Language.get("ecb_not"));
    });

    form.on('select(mode)', function (data) {
        setMode(data.value);
    });

    function setMode(select_value) {
        if (select_value === "No"){
            $("#iv").attr("class", "layui-input layui-disabled");
            $("#iv").attr("disabled", "true");
            $("#iv").removeAttr("lay-verify");
            $("#iv").val(Language.get("mode_not"));
            return
        }
        if (select_value !== "ECB" && $('#algo').val() !== "WAKE") {
            $("#iv").removeAttr("disabled");
            $("#iv").attr({"placeholder": Language.get("please_input_iv"), "class": "layui-input"});
            $("#iv").attr("lay-verify", "check_iv");
            if ($("#iv").val() === "" || $("#iv").val() === Language.get("ecb_not") || $("#iv").val() === Language.get("mode_not")) {
                $("#iv").val("");
            }
        } else {
            $("#iv").attr("class", "layui-input layui-disabled");
            $("#iv").attr("disabled", "true");
            $("#iv").removeAttr("lay-verify");
            $("#iv").val(Language.get("ecb_not"));
        }
    }

    form.on('select(action)', function (data) {
        if (data.value === "Encrypt") {
            $("#code_type_div").html('<select name="code_type" lay-filter="code_type" class="select" lay-verify="type" id="code_type">\n' +
                '                <option value="utf8" id="symmetric_plain_encode_utf8"><script>document.getElementById("symmetric_plain_encode_utf8").innerText = Language.get("utf8")</script></option>\n' +
                '                <option value="base64" id="symmetric_plain_encode_base64"><script>document.getElementById("symmetric_plain_encode_base64").innerText = Language.get("base64")</script></option>\n' +
                '                <option value="hex" id="symmetric_plain_encode_hex"><script>document.getElementById("symmetric_plain_encode_hex").innerText = Language.get("hex")</script></option>\n' +
                '            </select>');
            $("#result_code_type").html(' <option value="base64" id="symmetric_cipher_base64"><script>document.getElementById("symmetric_cipher_base64").innerText = Language.get("base64")</script></option>\n' +
                '                <option value="hex" id="symmetric_cipher_hex"><script>document.getElementById("symmetric_cipher_hex").innerText = Language.get("hex")</script></option>\n' +
                '                <option value="Both" id="symmetric_cipher_both"><script>document.getElementById("symmetric_cipher_both").innerText = Language.get("hex_and_base64")</script></option>');
            document.getElementById("symmetric_cipher_text").innerText = Language.get("cipher_text");
            document.getElementById("symmetric_plain_text").innerText = Language.get("plain_text");
            $("#textOrFile").html(Language.get("plain_text"));
            document.getElementById("action_text").setAttribute("placeholder", Language.get("please_input_encrypt_text"));
            $("#upload_file").html(' <label class="layui-form-label" id="symmetric_upload_file"><script>document.getElementById("symmetric_upload_file").innerText = Language.get("file")</script></label>\n' +
                '        <div class="layui-upload-drag layui-inline" id="upload_drag">\n' +
                '            <i class="layui-icon"></i>\n' +
                '            <p id="upload_file_name"><script>document.getElementById("upload_file_name").innerText = Language.get("file_tips")</script></p>\n' +
                '        </div>');
            uploadListen();
            form.render('select');
        } else {
            $("#code_type_div").html('<select name="code_type" lay-filter="code_type" class="select" lay-verify="type" id="code_type">\n' +
                '                <option value="base64" id="symmetric_plain_encode_base64"><script>document.getElementById("symmetric_plain_encode_base64").innerText = Language.get("base64")</script></option>\n' +
                '                <option value="hex" id="symmetric_plain_encode_hex"><script>document.getElementById("symmetric_plain_encode_hex").innerText = Language.get("hex")</script></option>\n' +
                '            </select>');
            $("#result_code_type").html('<option value="utf8" id="symmetric_cipher_utf8"><script>document.getElementById("symmetric_cipher_utf8").innerText = Language.get("utf8")</script></option>\n' +
                '                <option value="hex" id="symmetric_cipher_hex"><script>document.getElementById("symmetric_cipher_hex").innerText = Language.get("hex")</script></option>\n' +
                '                <option value="base64" id="symmetric_cipher_base64"><script>document.getElementById("symmetric_cipher_base64").innerText = Language.get("base64")</script></option>');
            form.render('select');
            document.getElementById("symmetric_cipher_text").innerText = Language.get("plain_text");
            document.getElementById("symmetric_plain_text").innerText = Language.get("cipher_text");
            $("#textOrFile").html(Language.get("cipher_text"));
            document.getElementById("action_text").setAttribute("placeholder", Language.get("please_input_decrypt_text"));
            $("#upload_file").html(' <label class="layui-form-label" id="symmetric_upload_file"><script>document.getElementById("symmetric_upload_file").innerText = Language.get("file")</script></label>\n' +
                '        <div class="layui-upload-drag layui-inline" id="upload_drag_disabled">\n' +
                '            <i class="layui-icon"></i>\n' +
                '            <p id="upload_file_name"><script>document.getElementById("upload_file_name").innerText = Language.get("file_not_decrypt_tips")</script></p>\n' +
                '        </div>');
            if (isFile) {
                $("#action_text").val("");
            }
            isFile = false;
            $("#action_text").removeAttr("disabled");
            $("#file_tips").remove();
            $("#result_box").html('');
        }
    });

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
        check_passphrase:[
            /\S+/
            , Language.get("passphrase_not_empty")
        ],
        check_key_len:[
            /\S+/
            , Language.get("key_len_not_empty")
        ],
        check_iterations: [
            /\S+/
            , Language.get("iterations_not_empty")
        ],
        check_plain_radix: [
            /\S+/
            , Language.get("radix_plain_not_empty")
        ],
        check_out_radix: [
            /\S+/
            , Language.get("out_radix_not_empty")
        ],
        check_data: [
            /\S+/
            , Language.get("data_not_empty")
        ],
        check_param: [
            /\S+/
            , Language.get("param_not_empty")
        ],
    });
    //拖拽上传
    function uploadListen(){
        upload.render({
            elem: '#upload_drag'
            , auto: false
            , accept: 'file' //普通文件
            , size: 51200
            , done: function (res) {
            }
            , choose: function (obj) {
                //预读本地文件，如果是多文件，则会遍历。(不支持ie8/9)
                var loading = layer.load(0, {shade: false});
                obj.preview(function (index, file, result) {
                    $("#action_text").val(result);
                    $("#action_text").attr("disabled", "");
                    $("#textOrFile").html(Language.get("file_base64"));
                    $("#upload_file").append('<span class="layui-inline layui-upload-choose" id="file_tips">' + file.name.toString() + '</span>');
                    isFile = true;
                    layer.close(loading)
                });
            }
        });
    }

    uploadListen();

    form.on('submit(do)', function (data) {
        const algorithm = data.field.algorithm;
        const key = data.field.key;
        const iv = data.field.iv;
        const action = data.field.action;
        const isKeyBase64 = data.field.key_code;
        const isIvBase64 = data.field.iv_code;
        var KeyType = "Text";
        var IvType = "Text";
        if (isKeyBase64 === "isKeyBase64") {
            KeyType = "Base64"
        } else if (isKeyBase64 === "isKeyHex") {
            KeyType = "Hex"
        }
        if (isIvBase64 === "isIvBase64") {
            IvType = "Base64"
        } else if (isIvBase64 === "isIvHex") {
            IvType = "Hex"
        }
        var result = "Failed !";
        var index = layer.load(1, {
            shade: [0.1, '#fff'] //0.1透明度的白色背景
        });
        switch (algorithm) {
            case "AES":
                AES.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = AES.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = AES.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "DES":
                DES.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = DES.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = DES.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "3DES":
                TripleDES.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = TripleDES.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = TripleDES.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RC4":
                RC4.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RC4.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RC4.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RC4Drop":
                RC4Drop.init(key, iv, KeyType, IvType);
                if (data.field.drop === "") {
                    data.field.drop = 768;
                }
                if (action === "Encrypt") {
                    result = RC4Drop.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, data.field.drop, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RC4Drop.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.drop, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "Rabbit":
                Rabbit.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = Rabbit.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = Rabbit.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RabbitLegacy":
                RabbitLegacy.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RabbitLegacy.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RabbitLegacy.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "Blowfish":
                Blowfish.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = Blowfish.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = Blowfish.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "IDEA":
                IDEA.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = IDEA.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = IDEA.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "SEED":
                SEED.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = SEED.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = SEED.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RC2":
                RC2.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RC2.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RC2.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CAST5":
                CAST5.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CAST5.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CAST5.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CAST":
                CAST.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CAST.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CAST.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CAMELLIA":
                CAMELLIA.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CAMELLIA.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CAMELLIA.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CHACHA20":
                CHACHA20.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CHACHA20.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CHACHA20.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CHACHA20-POLY1305":
                POLY1305.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = POLY1305.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = POLY1305.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RIJNDAEL128":
                RIJNDAEL128.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RIJNDAEL128.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RIJNDAEL128.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RIJNDAEL192":
                RIJNDAEL192.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RIJNDAEL192.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RIJNDAEL192.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "RIJNDAEL256":
                RIJNDAEL256.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = RIJNDAEL256.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = RIJNDAEL256.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "GOST":
                GOST.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = GOST.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = GOST.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "TWOFISH":
                TWOFISH.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = TWOFISH.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = TWOFISH.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "SERPENT":
                SERPENT.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = SERPENT.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = SERPENT.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "LOKI97":
                LOKI97.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = LOKI97.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = LOKI97.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "SAFER+":
                SAFERPLUS.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = SAFERPLUS.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = SAFERPLUS.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "XTEA":
                XTEA.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = XTEA.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = XTEA.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "WAKE":
                WAKE.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = WAKE.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = WAKE.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CAST128":
                CAST128.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CAST128.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CAST128.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "CAST256":
                CAST256.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = CAST256.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = CAST256.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "3WAY":
                THREEWAY.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = THREEWAY.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = THREEWAY.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "SAFER":
                SAFER.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = SAFER.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = SAFER.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
            case "Blowfish-Compat":
                BLOWFISHCOMPAT.init(key, iv, KeyType, IvType);
                if (action === "Encrypt") {
                    result = BLOWFISHCOMPAT.encrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.result_code_type, isFile, data.field.code_type);
                    if (result === "") {
                        result = "Non-conforming encryption."
                    }
                } else {
                    result = BLOWFISHCOMPAT.decrypt(data.field.action_text, data.field.padding, data.field.mode, data.field.code_type, data.field.result_code_type);
                    if (result === "") {
                        result = "Non-conforming decryption."
                    }
                }
                break;
        }
        $("#result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="result"><textarea name="result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        layer.close(index);
        return false; //阻止表单跳转。如果需要表单跳转，去掉这段即可。
    });

    //Abstract Algorithm

    function reset(){
        $("#abstract_result_box").html('');
        $("#hmac_key").attr("class", "layui-input layui-disabled");
        $("#hmac_key").attr("disabled", "true");
        $("#hmac_key").removeAttr("lay-verify");
        $("#hmac_key").val(Language.get("hmac_is_disabled"));
        $('#abstract_res').text("Result");
    }

    $('#abstract_reset').click(function () {
        reset();
        $("#div_hmac_key").attr("hidden", true);
        $("#div_hmac_encode").attr("hidden", true);
    });

    function setKeyOff(){
        $("#hmac_key").attr("class", "layui-input layui-disabled");
        $("#hmac_key").attr("disabled", "true");
        $("#hmac_key").val(Language.get("hmac_is_disabled"));
        $("#div_hmac_key").attr("hidden", true);
        $("#div_hmac_encode").attr("hidden", true);
    }

    function setKeyOn(){
        $("#hmac_key").removeAttr("disabled");
        $("#hmac_key").attr({"placeholder": Language.get("please_input_hmac"), "class": "layui-input"});
        if ($("#hmac_key").val() === "" || $("#hmac_key").val().indexOf('HMAC is disabled') >= 0) {
            $("#hmac_key").val("");
        }
        $("#div_hmac_key").removeAttr("hidden");
        $("#div_hmac_encode").removeAttr("hidden");
    }

    form.on('select(abstract_algo)', function (data) {
        if (data.value.indexOf("crc") >= 0){
            $("#hmac").attr('disabled', true);
            $("#hmac").val("disabled");
            setKeyOff();
        }else{
            $("#hmac").removeAttr('disabled');
            $("#hmac").val("disabled");
            setKeyOff();
        }
        form.render('select');
    });

    form.on('submit(abstract_file)', function(data){
        var start = new Date().getTime();
        var finish = new Date().getTime();
        var result = "";
        dialog.showOpenDialog({properties: ['openFile', 'multiSelections', 'showHiddenFiles', 'treatPackageAsDirectory']}, function (files) {
            $("#file_hashing").css("display", " ");
            if (files === undefined){
                layer.msg(Language.get("no_file_selected"));
            } else {
                var index = layer.open({
                    type:1
                    ,title:false
                    ,resize:false
                    ,closeBtn: 0
                    ,area: ['500px','18px']
                    ,content:$("#file_hashing")
                });
                layer.style(index,{"background-color":"rgba(255,255,255,0)","border-radius":"20px;"});
                var count = 0;

                start = new Date().getTime();
                for (const file in files){
                    const filename = files[file].substr(files[file].lastIndexOf('\\')+1);
                    if (data.field.abstract_algorithm.indexOf("crc") >= 0){
                        var str = "";
                        if (data.field.hmac === "disabled"){
                            result = require('../lib/abstract').get_file_crc(files[file], data.field.abstract_algorithm, data.field.abstract_code_type).then(function (value) {
                                count++;
                                str += filename + ": " + value + "\n";
                                element.progress('abstract_loading', (count / files.length * 100).toFixed(2) + '%');
                                if (count === files.length) {
                                    finish = (new Date().getTime() - start) / 1000.00;
                                    $('#abstract_res').text(Language.get("result") + " (" + files.length.toString() + " " + Language.get("files_in") + " " + finish + Language.get("second") + ")");
                                    element.progress('abstract_loading', '100%');
                                    layer.close(index);
                                    element.progress('abstract_loading', '0%');
                                    $("#abstract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="abstract_result"><textarea name="abstract_result_text" readonly class="layui-textarea">' + str + '</textarea></blockquote>');
                                    document.getElementById("file_hashing").style.display = "none";
                                    const h = $(document).height() - $(window).height();
                                    $(document).scrollTop(h);
                                }
                            })
                        }
                    }else {
                        if (data.field.hmac === "disabled") {
                            require('../lib/abstract').get_files(files[file], data.field.abstract_algorithm, data.field.abstract_code_type).then(function (value) {
                                count++;
                                result += filename + ": " + value + "\n";
                                element.progress('abstract_loading', (count / files.length * 100).toFixed(2) + '%');
                                if (count === files.length) {
                                    finish = (new Date().getTime() - start) / 1000.00;
                                    $('#abstract_res').text(Language.get("result") + " (" + files.length.toString() + " " + Language.get("files_in") + " " + finish + Language.get("second") + ")");
                                    element.progress('abstract_loading', '100%');
                                    layer.close(index);
                                    element.progress('abstract_loading', '0%');
                                    $("#abstract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="abstract_result"><textarea name="abstract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                    document.getElementById("file_hashing").style.display = "none";
                                    const h = $(document).height() - $(window).height();
                                    $(document).scrollTop(h);
                                }
                            })
                        } else {
                            require('../lib/abstract').get_files_hmac(files[file], data.field.abstract_algorithm, data.field.abstract_code_type, data.field.hmac_key).then(function (value) {
                                count++;
                                result += filename + ": " + value + "\n";
                                element.progress('abstract_loading', (count / files.length * 100).toFixed(2) + '%');
                                if (count === files.length) {
                                    finish = (new Date().getTime() - start) / 1000.00;
                                    $('#abstract_res').text(Language.get("result") + " (" + files.length.toString() + " " + Language.get("files_in") + " " + finish + Language.get("second") + ")");
                                    element.progress('abstract_loading', '100%');
                                    layer.close(index);
                                    element.progress('abstract_loading', '0%');
                                    $("#abstract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="abstract_result"><textarea name="abstract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                                    document.getElementById("file_hashing").style.display = "none";
                                    const h = $(document).height() - $(window).height();
                                    $(document).scrollTop(h);
                                }
                            })
                        }
                    }
                }
            }
        });
        return false; //阻止表单跳转。如果需要表单跳转，去掉这段即可。
    });

    form.on('select(hmac)', function (data) {
        if (data.value === "disabled"){
            setKeyOff();
        }else if (data.value === "enabled"){
            setKeyOn();
        }
    });

    form.on('submit(abstract_do)', function (data) {
        $('#abstract_res').text(Language.get("result"));
        var result= "Failed !";
        var index = layer.load(1, {
            shade: [0.1, '#fff'] //0.1透明度的白色背景
        });
        if (data.field.abstract_algorithm.indexOf("crc") >= 0){
            if (data.field.hmac === "disabled"){
                result = require('../lib/abstract').crc(data.field.abstract_text, data.field.abstract_algorithm, data.field.abstract_code_type, data.field.abstract_plain_type);
            }
        }else{
            if (data.field.hmac === "disabled"){
                result = require('../lib/abstract').hashed(data.field.abstract_algorithm, data.field.abstract_text, data.field.abstract_code_type, data.field.abstract_plain_type);
            } else if (data.field.hmac === "enabled") {
                result = require('../lib/abstract').hmac_hash(data.field.abstract_algorithm, data.field.abstract_text, data.field.abstract_code_type, data.field.hmac_key, data.field.abstract_hmac_type, data.field.abstract_plain_type);
            }
        }
        $("#abstract_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="abstract_result"><textarea name="abstract_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        layer.close(index);
        return false; //阻止表单跳转。如果需要表单跳转，去掉这段即可。
    });

    //asymmetric

    $("#asymmetric_reset").click(function () {
        $("#asymmetric_result_box").html('');
    });

    $("#keypair_tool").click(function () {
        open_keypair();
    });

    form.on('select(asymmetric_private_encrypted)', function (data) {
        if (data.value === "true"){
            $("#private_key").removeAttr("disabled");
            $("#private_key").attr({"placeholder": Language.get("passphrase_tips"), "class": "layui-input"});
            if ($("#private_key").val() === "" || $("#private_key").val().indexOf('private key has no passphrase') >= 0) {
                $("#private_key").val("");
            }
        }else if (data.value === "false"){
            $("#private_key").attr("class", "layui-input layui-disabled");
            $("#private_key").attr("disabled", "true");
            $("#private_key").val(Language.get("private_no_password"));
        }
    });

    form.on('select(asymmetric_operate)', function (data) {
        if (data.value.indexOf("public") >= 0){
            $("#asymmetric_private_item").attr("hidden", true);
            $("#asymmetric_private_password_item").attr("hidden", true);
            $("#asymmetric_public_item").removeAttr("hidden", true);
            $("#asymmetric_private_encrypt_select").attr("disabled", true);
            $("#private_key_text").removeAttr("required lay-verify");
            $("#public_key_text").attr({"required": "true", "lay-verify": "check_public"});
        }else if (data.value.indexOf("private") >= 0){
            $("#private_key_text").attr({"required": "true", "lay-verify": "check_private"});
            $("#public_key_text").removeAttr("required lay-verify");
            $("#asymmetric_private_item").removeAttr("hidden");
            $("#asymmetric_private_password_item").removeAttr("hidden");
            $("#asymmetric_public_item").attr("hidden", true);
            $("#asymmetric_private_encrypt_select").removeAttr("disabled");
        }
        if (data.value.indexOf("encrypt") >= 0){
            document.getElementById("asymmetric_in_coding").innerText = Language.get("input_text");
            document.getElementById("asymmetric_cipher_text").innerText = Language.get("cipher_text");
            $("#asymmetric_in_encode").html("<option value=\"utf8\" id=\"asymmetric_plain_encode_utf8\">\n" +
                "                    <script>document.getElementById(\"asymmetric_plain_encode_utf8\").innerText = Language.get(\"utf8\")</script>\n" +
                "                </option>\n" +
                "                <option value=\"base64\" id=\"asymmetric_plain_encode_base64\">\n" +
                "                    <script>document.getElementById(\"asymmetric_plain_encode_base64\").innerText = Language.get(\"base64\")</script>\n" +
                "                </option>\n" +
                "                <option value=\"hex\" id=\"asymmetric_plain_encode_hex\">\n" +
                "                    <script>document.getElementById(\"asymmetric_plain_encode_hex\").innerText = Language.get(\"hex\")</script>\n" +
                "                </option>");
            $("#asymmetric_out_encode").html('<option value="base64" id="asymmetric_cipher_base64">\n' +
                '                    <script>document.getElementById("asymmetric_cipher_base64").innerText = Language.get("base64")</script>\n' +
                '                </option>\n' +
                '                <option value="hex" id="asymmetric_cipher_hex">\n' +
                '                    <script>document.getElementById("asymmetric_cipher_hex").innerText = Language.get("hex")</script>\n' +
                '                </option>\n' +
                '                <option value="Both" id="asymmetric_cipher_both">\n' +
                '                    <script>document.getElementById("asymmetric_cipher_both").innerText = Language.get("hex_and_base64")</script>\n' +
                '                </option>');
        } else if (data.value.indexOf("decrypt") >= 0) {
            document.getElementById("asymmetric_in_coding").innerText = Language.get("cipher_text");
            document.getElementById("asymmetric_cipher_text").innerText = Language.get("output_text");
            $("#asymmetric_in_encode").html("<option value=\"base64\" id=\"asymmetric_plain_encode_base64\">\n" +
                "                    <script>document.getElementById(\"asymmetric_plain_encode_base64\").innerText = Language.get(\"base64\")</script>\n" +
                "                </option>\n" +
                "                <option value=\"hex\" id=\"asymmetric_plain_encode_hex\">\n" +
                "                    <script>document.getElementById(\"asymmetric_plain_encode_hex\").innerText = Language.get(\"hex\")</script>\n" +
                "                </option>");
            $("#asymmetric_out_encode").html('<option value="utf8" id="asymmetric_out_encode_utf8">\n' +
                '                    <script>document.getElementById("asymmetric_out_encode_utf8").innerText = Language.get("utf8")</script>\n' +
                '                </option>\n' +
                '                <option value="base64" id="asymmetric_out_encode_base64">\n' +
                '                    <script>document.getElementById("asymmetric_out_encode_base64").innerText = Language.get("base64")</script>\n' +
                '                </option>\n' +
                '                <option value="hex" id="asymmetric_out_encode_hex">\n' +
                '                    <script>document.getElementById("asymmetric_out_encode_hex").innerText = Language.get("hex")</script>\n' +
                '                </option>');
        }
        form.render("select");
    });

    form.on('submit(asymmetric_do)', function (data) {
        let result = "Failed !";
        if (data.field.asymmetric_operate === "private_encrypt") {
            const format = getPrivateFormat(data.field.private_key);
            const isEncrypted = data.field.asymmetric_private_encrypted;
            if (format === "pkcs8"){
                if (isEncrypted === "true"){
                    $("#asymmetric_result_box").html('');
                    const index2 = layer.load(1, {
                        shade: [0.1, '#fff'] //0.1透明度的白色背景
                    });
                    pkcs8_private_encrypt_passphrase(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding, data.field.private_key_password).then(function (value) {
                        $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + value + '</textarea></blockquote>');
                        const h = $(document).height() - $(window).height();
                        $(document).scrollTop(h);
                        layer.close(index2);
                    });
                } else {
                    const index = layer.load(1, {
                        shade: [0.1, '#fff'] //0.1透明度的白色背景
                    });
                    result = private_encrypt(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                    $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                    const h = $(document).height() - $(window).height();
                    $(document).scrollTop(h);
                    layer.close(index);
                }
            }else {
                const index = layer.load(1, {
                    shade: [0.1, '#fff'] //0.1透明度的白色背景
                });
                if (format === "pkcs1"){
                    if (isEncrypted === "true"){
                        console.log("true");
                        result = pkcs1_private_encrypt_passphrase(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding, data.field.private_key_password);
                    } else {
                        result = private_encrypt(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                    }
                }else {
                    result = Language.get("private_key_null_tips");
                }
                $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                layer.close(index);
            }
        } else if (data.field.asymmetric_operate === "private_decrypt") {
            const format = getPrivateFormat(data.field.private_key);
            const isEncrypted = data.field.asymmetric_private_encrypted;
            if (format === "pkcs8"){
                if (isEncrypted === "true"){
                    $("#asymmetric_result_box").html('');
                    const index2 = layer.load(1, {
                        shade: [0.1, '#fff'] //0.1透明度的白色背景
                    });
                    pkcs8_private_decrypt_passphrase(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding, data.field.private_key_password).then(function (value) {
                        $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + value + '</textarea></blockquote>');
                        const h = $(document).height() - $(window).height();
                        $(document).scrollTop(h);
                        layer.close(index2);
                    });
                } else {
                    const index = layer.load(1, {
                        shade: [0.1, '#fff'] //0.1透明度的白色背景
                    });
                    result = private_decrypt(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                    $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                    const h = $(document).height() - $(window).height();
                    $(document).scrollTop(h);
                    layer.close(index);
                }
            }else {
                const index = layer.load(1, {
                    shade: [0.1, '#fff'] //0.1透明度的白色背景
                });
                if (format === "pkcs1"){
                    if (isEncrypted === "true"){
                        result = pkcs1_private_decrypt_passphrase(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding, data.field.private_key_password);
                    } else {
                        result = private_decrypt(data.field.private_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                    }
                }else {
                    result = Language.get("private_key_null_tips");
                }
                $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
                const h = $(document).height() - $(window).height();
                $(document).scrollTop(h);
                layer.close(index);
            }
        } else {
            const index = layer.load(1, {
                shade: [0.1, '#fff'] //0.1透明度的白色背景
            });
            if (data.field.asymmetric_operate === "public_encrypt"){
                result = public_encrypt(data.field.public_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                if (result === "") {
                    result = "Non-conforming encryption."
                }
            } else if (data.field.asymmetric_operate === "public_decrypt") {
                result = public_decrypt(data.field.public_key, data.field.asymmetric_text, data.field.asymmetric_in_coding, data.field.asymmetric_out_coding, data.field.asymmetric_padding);
                if (result === "") {
                    result = "Non-conforming decryption."
                }
            }
            $("#asymmetric_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="asymmetric_result"><textarea name="asymmetric_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            layer.close(index);
        }
        return false;
    });

    // Hash

    $("#pbkdf_reset").click(function () {
        $("#hash_result_box").html('');
    });

    $("#scrypt_reset").click(function () {
        $("#hash_result_box").html('');
        $("#scrypt_salt_type_select").removeAttr("disabled");
        $("#scrypt_salt").attr({"class": "layui-input", "placeholder": Language.get("please_input_salt"), "disabled": false});
        form.render('select');
    });

    let maxmem_tips_index = null;
    $("#scrypt_maxmem").hover(function () {
        maxmem_tips_index = layer.tips(Language.get("maxmem_tips"), $("#scrypt_maxmem"), {
            tips: [1, '#3595CC'],
            time: 6000
        });
    }, function () {
        try{
            layer.close(maxmem_tips_index);
        }catch (e) {
            // Pass exception
        }
    });

    let cost_tips_index = null;
    $("#scrypt_cost").hover(function () {
        cost_tips_index = layer.tips(Language.get("cost_msg"), $("#scrypt_cost"), {
            tips: [1, '#3595CC'],
            time: 6000
        });
    }, function () {
        try{
            layer.close(cost_tips_index);
        }catch (e) {
            // Pass exception
        }
    });

    form.on('submit(pbkdf_do)', function (data) {
        const pbkdf_algorithm = data.field.pbkdf_algorithm;
        const pbkdf_iterations = parseInt(data.field.pbkdf_iterations);
        const pbkdf_key_len = parseInt(data.field.pbkdf_key_len);
        const pbkdf_out_text = data.field.pbkdf_out_text;
        const pbkdf_password = data.field.pbkdf_password;
        const pbkdf_password_type = data.field.pbkdf_password_type;
        const pbkdf_salt = data.field.pbkdf_salt;
        const pbkdf_salt_type = data.field.pbkdf_salt_type;
        let result = "";
        $("#hash_execute_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#hash_execute_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('execute_hash_loading', '25%');
        setTimeout(function () {
            try{
                result = require('crypto').pbkdf2Sync(Buffer.from(pbkdf_password, pbkdf_password_type), Buffer.from(pbkdf_salt, pbkdf_salt_type), pbkdf_iterations, pbkdf_key_len, pbkdf_algorithm).toString(pbkdf_out_text);
            }catch (e) {
                result = e.toString();
            }
            element.progress('execute_hash_loading', '50%');
            $("#hash_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="hash_result"><textarea name="hash_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            layer.close(index);
            element.progress('execute_hash_loading', '100%');
            document.getElementById("hash_execute_loading").style.display = "none";
        }, 500);
        return false;
    });

    form.on('select(scrypt_operate)', function (data) {
        if (data.value === "hash"){
            $("#scrypt_salt_type_select").removeAttr("disabled");
            $("#scrypt_salt").attr({"class": "layui-input", "placeholder": Language.get("please_input_salt"), "disabled": false});
        }else{
            $("#scrypt_salt_type_select").attr("disabled", true);
            $("#scrypt_salt").attr({"class": "layui-input layui-disabled", "placeholder": Language.get("kdf_not_salt"), "disabled": true});
        }
        form.render('select');
    });

    form.on('submit(scrypt_do)', function (data) {
        console.log(data.field);
        let scrypt_block;
        let scrypt_cost;
        let scrypt_parallel;
        data.field.scrypt_block.trim() === "" ? scrypt_block = 8 : scrypt_block = parseInt(data.field.scrypt_block);
        data.field.scrypt_cost.trim() === "" ? scrypt_cost = 16384 : scrypt_cost = parseInt(data.field.scrypt_cost);
        const scrypt_key_len = parseInt(data.field.scrypt_key_len);
        const scrypt_operate = data.field.scrypt_operate;
        const scrypt_out_text = data.field.scrypt_out_text;
        data.field.scrypt_parallel.trim() === "" ? scrypt_parallel = 1 : scrypt_parallel = parseInt(data.field.scrypt_parallel);
        const scrypt_password = data.field.scrypt_password;
        const scrypt_password_type = data.field.scrypt_password_type;
        const scrypt_salt = data.field.scrypt_salt;
        const scrypt_salt_type = data.field.scrypt_salt_type;
        let result = "";
        $("#hash_execute_loading").css("display", " ");
        const index = layer.open({
            type: 1
            , title: false
            , resize: false
            , closeBtn: 0
            , area: ['500px', '18px']
            , content: $("#hash_execute_loading")
        });
        layer.style(index, {"background-color": "rgba(255,255,255,0)", "border-radius": "20px;"});
        element.progress('execute_hash_loading', '25%');
        setTimeout(function () {
            try{
                switch (scrypt_operate) {
                    case "hash":
                        result = scrypt.hashSync(Buffer.from(scrypt_password, scrypt_password_type), {N: scrypt_cost, r: scrypt_block, p: scrypt_parallel}, scrypt_key_len, Buffer.from(scrypt_salt, scrypt_salt_type)).toString(scrypt_out_text);
                        break;
                    case "kdf":
                        result = scrypt.kdfSync(Buffer.from(scrypt_password, scrypt_password_type), {N: scrypt_cost, r: scrypt_block, p: scrypt_parallel}).toString(scrypt_out_text);
                        break;
                    default:
                        break;
                }

            }catch (e) {
                result = e.toString();
            }
            element.progress('execute_hash_loading', '50%');
            $("#hash_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="hash_result"><textarea name="hash_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
            const h = $(document).height() - $(window).height();
            $(document).scrollTop(h);
            layer.close(index);
            element.progress('execute_hash_loading', '100%');
            document.getElementById("hash_execute_loading").style.display = "none";
        },500);
        return false;
    });

    //radix

    let plain_tips_index = null;
    $("#radix_convert_input").hover(function () {
        plain_tips_index = layer.tips(Language.get("plain_radix_tips"), $("#radix_convert_input"), {
            tips: [1, '#3595CC'],
            time: 6000
        });
    }, function () {
        try{
            layer.close(plain_tips_index);
        }catch (e) {
            // Pass exception
        }
    });

    let out_tips_index = null;
    $("#radix_convert_out").hover(function () {
        out_tips_index = layer.tips(Language.get("plain_radix_tips"), $("#radix_convert_out"), {
            tips: [1, '#3595CC'],
            time: 6000
        });
    }, function () {
        try{
            layer.close(out_tips_index);
        }catch (e) {
            // Pass exception
        }
    });

    form.on('submit(radix_convert_do)', function (data) {
        const radix_convert_data = data.field.radix_convert_data;
        const radix_convert_input = data.field.radix_convert_input;
        const radix_convert_out = data.field.radix_convert_out;
        let result = "";
        try{
            result = radixConvert(radix_convert_input, radix_convert_out, radix_convert_data);
        }catch (e) {
            result = e.toString();
        }
        $("#radix_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="radix_result"><textarea name="radix_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        return false;
    });

    $("#radix_convert_reset").click(function () {
        $("#radix_result_box").html('');
    });

    $("#radix_calculation_reset").click(function () {
        $("#radix_result_box").html('');
    });

    function radixConvert(inText, outText, content){
        let chars = inText,
            radix = chars.length,
            number_code = String(content),
            len = number_code.length,
            i = 0,
            origin_number = 0;
        while (i < len) {
            origin_number += Math.pow(radix, i++) * chars.indexOf(number_code.charAt(len - i) || 0);
        }
        chars = outText.split('');
        radix = chars.length;
        let qutient = +origin_number,
            arr = [];
        do {
            mod = qutient % radix;
            qutient = (qutient - mod) / radix;
            arr.unshift(chars[mod]);
        } while (qutient);
        return arr.join('');
    }

    form.on('submit(radix_calculation_do)', function (data) {
        const radix_calculation_input = data.field.radix_calculation_input;
        const radix_calculation_operate = data.field.radix_calculation_operate;
        const radix_calculation_out = data.field.radix_calculation_out;
        const radix_param_one = data.field.radix_param_one;
        const radix_param_two = data.field.radix_param_two;
        let dec_one;
        let dec_two;
        let cache_result;
        let result = "";
        try{
            dec_one = radixConvert(radix_calculation_input, "0123456789", radix_param_one);
            dec_two = radixConvert(radix_calculation_input, "0123456789", radix_param_two);
            cache_result = eval(dec_one + radix_calculation_operate + dec_two);
            result = radixConvert("0123456789", radix_calculation_out, cache_result);
        }catch (e) {
            result = e.toString();
        }
        $("#radix_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="radix_result"><textarea name="radix_result_text" readonly class="layui-textarea">' + result.toString() + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        return false;
    });

    // other
    form.on('submit(stamp_do)', function (data) {
        const the_date = data.field.datetime;
        if (the_date === ""){
            layer.msg(Language.get("invalid_date"));
            return false;
        }
        const date = new Date(the_date);
        const stamp = (date.getTime()).toString();
        $("#timestamp").val(stamp);
       return false;
    });

    form.on('submit(now_stamp)', function (data) {
        const now = new Date().getTime();
        $("#timestamp").val(now.toString());
        return false;
    });

    form.on('submit(date_do)', function (data) {
        let timestamp = data.field.timestamp;
        if (timestamp === ""){
            layer.msg(Language.get("invalid_stamp"));
            return false;
        }
        const silly = require('silly-datetime');
        let to = 13 - timestamp.length;
        if (to > 3){
            layer.msg(Language.get("invalid_stamp"));
            return false;
        } else if (to < 0){
            layer.msg(Language.get("invalid_stamp"));
            return false;
        }
        const convert_date = new Date(timestamp * Math.pow(10, to));
        const result = silly.format(convert_date, "YYYY-MM-DD HH:mm:ss");
        $("#date_select").val(result);
        return false;
    });

    form.on('submit(random_do)', function (data) {
        let random_size = data.field.random_size;
        const random_out_type = data.field.random_out_type;
        let result;
        if (random_size === "") {
            random_size = 16;
        }
        try{
            result = require('crypto').randomBytes(parseInt(random_size)).toString(random_out_type);
        }catch (e) {
            result = e.toString();
        }
        $("#random_text_result").val(result);
        return false;
    });
}

function openEncoding(){
    ipcRenderer.send('openEncoding');
}