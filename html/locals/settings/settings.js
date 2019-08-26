const { dialog } = require('electron').remote;
const { ipcRenderer } = require('electron');
let form, $, upload, layer, element, laydate = null;

function setEvent(f, j, u, l, e, d) {
    form = f;
    $ = j;
    upload = u;
    layer = l;
    element = e;
    laydate = d;
}

function setValue() {
    $("#settings_shortcut").val(config.get("shortcut", ""));
    if (config.get("auto_launch", false)){
        $("#settings_auto_launch").attr("checked", true);
    }
    if (config.get("tray_start", false)){
        $("#settings_tray_launch").attr("checked", true);
    }
    form.render("checkbox")
}

function listen() {
    let tips_index;
    let shortcut = "";

    setValue();
    form.on('submit(settings_apply)', function (data) {
        shortcut = data.field.shortcut;
        if (shortcut === "" || shortcut === undefined){
            shortcut = "Alt+Shift+C";
        }
        let auto_launch = data.field.auto_launch === "on";
        let tray_launch = data.field.tray_launch === "on";
        ipcRenderer.send('settings', [shortcut, auto_launch, tray_launch]);
        return false;
    });


    $("#settings_reset").click(function () {
        setValue();
    });

    /*
    $("#settings_shortcut").click(function (e) {
        tips_index = layer.tips(Language.get("press_shortcut"), $("#settings_shortcut"), {
            tips: [1, '#3595CC'],
            time: 6000
        });
        shortcut = "";
    });
    $("#settings_shortcut").blur(function () {
        layer.close(tips_index);
    });
    $('#settings_shortcut').keydown(function(event){
        if ($('#settings_shortcut').focus()){
            if (event.key.match('^[a-zA-Z]{1}$')){
                event.key = event.key.toUpperCase();
            }
            shortcut += event.key + "+";
        }
    });
    $('#settings_shortcut').keyup(function(event){
        if ($('#settings_shortcut').focus()) {
            if (shortcut !== "") {
                $("#settings_shortcut").val(shortcut.substring(0, shortcut.length - 1));
                shortcut = "";
                console.log(shortcut.substring(0, shortcut.length - 1));
            }
        }
    });*/
}