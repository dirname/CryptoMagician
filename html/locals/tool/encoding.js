let form, $, upload, layer, element = null;
const { dialog } = require('electron').remote;
const {ipcRenderer} = require('electron');
const encoding = require('iconv-lite');

function setEvent(f, j, u, l, e) {
    form = f;
    $ = j;
    upload = u;
    layer = l;
    element = e;
}

function listen() {


    form.verify({
        check_encoding: [
            /\S+/
            , Language.get("encoding_not_empty")
        ],
        check_text: [
            /\S+/
            , Language.get("text_not_empty")
        ],
    });

    form.on('submit()', function (data) {
        const encoding_text = data.field.encoding_text;
        const from_encoding = data.field.from_encoding;
        const out_encoding = data.field.out_encoding;
        let result;
        try{
            result = encoding.decode(encoding.encode(encoding_text, from_encoding), out_encoding).toString();
        }catch (e) {
            result = e.toString();
        }
        $("#encoding_result_box").html('<blockquote class="layui-elem-quote layui-quote-nm" id="encoding_result"><textarea name="encoding_result_text" readonly class="layui-textarea">' + result + '</textarea></blockquote>');
        const h = $(document).height() - $(window).height();
        $(document).scrollTop(h);
        return false;
    })
}