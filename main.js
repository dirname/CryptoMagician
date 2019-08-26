// Modules to control application life and create native browser window

const {app, BrowserWindow, Menu, autoUpdater, Tray, globalShortcut, ipcMain, MenuItem, contentTracing, ipcRenderer, dialog, nativeImage} = require('electron');
const sd = require('silly-datetime');
const os = require('os');
const crypto = require('crypto');
const ProtoBufJs = require("protobufjs");

const electron = require('electron');
const Config = require('electron-store');
const config = new Config();
const AutoLaunch = require('auto-launch');
let value = "";
let language = "";
// Keep a global reference of the window object, if you don't, the window will
// be closed automatically when the JavaScript object is garbage collected.
let mainWindow = null;

let showTrayTips = true;
let ShortCut = "Alt+Shift+C";
let tray = null;
let keypair_win = null;
let encoding_win = null;
let tray_start = false;
let auto_launch = false;
let settings_win = null;


let app_lang = app.getLocale();
let is_zh;
app_lang = config.get('lang', app_lang);
ShortCut = config.get('shortcut', ShortCut);
tray_start = config.get("tray_start", tray_start);
auto_launch = config.get("auto_launch", auto_launch);
config.set("shortcut", ShortCut);

load_language();
const auto_launch_app = new AutoLaunch({
    name: language["app"],
    //path: '/Applications/Minecraft.app',
});

if (auto_launch){
    auto_launch_app.enable();
}else{
    auto_launch_app.disable();
}

function load_language() {
    try {
        value = require('./html/locals/lang/' + app_lang).f();
    } catch (e) {
        app_lang = "en-US";
        value = require('./html/locals/lang/en').f();
    }
    language = JSON.parse(value);
}


function get_menu() {
    return [
        // { role: 'appMenu' }
        ...(process.platform === 'darwin' ? [{
            label: app.getName(),
            submenu: [
                {role: 'about', label: language["about_app"]},
                {type: 'separator'},
                {role: 'services', label: language["services"]},
                {type: 'separator'},
                {role: 'hide', label: language["hide_app"]},
                {role: 'hideothers', label: language["hide_others"]},
                {role: 'unhidden', label: language["show_all"]},
                {type: 'separator'},
                {role: 'quit', label: language["quit_app"]}
            ]
        }] : []),
        // { role: 'fileMenu' }
        {
            label: language["file"],
            submenu: [
                {
                    label: language["settings"], click: function () {
                        openSettings()
                    }
                },
                ...(process.platform === 'darwin' ? [
                    {role: 'close', label: language["close_window"]}
                ] : [
                    {role: 'quit', label: language["exit"]}
                ])
            ]
            /*
            submenu: [
                {role: 'undo', label: language["undo"]},
                ...(process.platform === 'darwin' ? {role: 'close', label: language["close_window"]} : {
                    role: 'quit',
                    label: language["exit"]
                })
            ]*/
        },
        // { role: 'editMenu' }
        {
            label: language["edit"],
            submenu: [
                {role: 'undo', label: language["undo"]},
                {role: 'redo', label: language["redo"]},
                {type: 'separator'},
                {role: 'cut', label: language["cut"]},
                {role: 'copy', label: language["copy"]},
                {role: 'paste', label: language["paste"]},
                ...(process.platform === 'darwin' ? [
                    {role: 'pasteAndMatchStyle', label:language["paste_match_style"]},
                    {role: 'delete', label:language["delete"]},
                    {role: 'selectAll', label:language["select_all"]},
                    {type: 'separator'},
                    {
                        label:language["speech"],
                        submenu: [
                            {role: 'startspeaking', label:language["start_speaking"]},
                            {role: 'stopspeaking', label:language["stop_speaking"]}
                        ]
                    }
                ] : [
                    {role: 'delete', label: language["delete"]},
                    {type: 'separator'},
                    {role: 'selectAll', label: language["select_all"]}
                ])
            ]
        },
        // { role: 'viewMenu' }
        {
            label: language["view"],
            submenu: [
                {role: 'reload', label: language["reload"]},
                {role: 'forcereload', label: language["force_reload"]},
                {role: 'toggledevtools', label: language["toggle_dev_tools"]},
                {type: 'separator'},
                {role: 'resetzoom', label: language["reset_zoom"]},
                {role: 'zoomin', label: language["zoom_in"]},
                {role: 'zoomout', label: language["zoom_out"]},
                {type: 'separator'},
                {role: 'togglefullscreen', label: language["toggle_full_screen"]},
                {type: 'separator'},
                {
                    label: language["language"],
                    submenu: [{
                        label: language["simplified_chinese"], type: 'radio', checked: app_lang === "zh-CN", click() {
                            app_lang = 'zh-CN';
                            config.set('lang', 'zh-CN');
                            app.relaunch();
                            app.exit(0)
                        }
                    },
                        {
                            label: language["english"], type: 'radio', checked: app_lang === "en-US", click() {
                                app_lang = 'en-US';
                                config.set('lang', 'en-US');
                                app.relaunch();
                                app.exit(0)
                            }
                        },
                        {
                            label: language["japanese"], type: 'radio', checked: app_lang === "ja", click() {
                                app_lang = 'ja';
                                config.set('lang', 'ja');
                                app.relaunch();
                                app.exit(0)
                            }
                        }],
                }
            ]
        },
        // { role: 'windowMenu' }
        {
            label: language["window"],
            submenu: [
                {role: 'minimize', label: language["minimize"]},
                {role: 'zoom', label: language["zoom"]},
                ...(process.platform === 'darwin' ? [
                    {type: 'separator'},
                    {role: 'front', label:language["bring_all_to_front"]},
                ] : [
                    {role: 'close', label: language["close"]}
                ])
            ]
        },
        {
            label: language["help"],
            submenu: [
                {
                    label: language["push_issues"],
                    click() {
                        electron.shell.openExternal('https://github.com/dirname/CryptoMagician/issues')
                    },
                }, {
                    label: language["visit_github_page"],
                    click() {
                        electron.shell.openExternal('https://github.com/dirname/CryptoMagician')
                    },
                }
            ]
        }
    ];
}

function createWindow() {
    let menu;

    // Create the browser window.
    mainWindow = new BrowserWindow({
        width: 1016,
        height: 720,
        title: language["app"],
        show: !tray_start,
        webPreferences: {
            nodeIntegration: true
        }
    });

    // and load the index.html of the app.
    mainWindow.loadFile('./html/locals/index.html');

    global.main = mainWindow;

    menu = null;
    menu = Menu.buildFromTemplate(get_menu());

    Menu.setApplicationMenu(menu);
    app.setName(language["app"]);


    mainWindow.on('show', () => {
        tray.setHighlightMode('always')
    });
    mainWindow.on('hide', () => {
        tray.setHighlightMode('never');
        if (showTrayTips) {
            showTrayTips = false;
            tray.displayBalloon({title: language["app"], content: language["app_background_run"]});
        }
    });
    mainWindow.on("minimize", () => {
        mainWindow.hide();
    });

    mainWindow.on("closed", () => {
        tray.setHighlightMode('never');
    });

    // Open the DevTools.
    //mainWindow.webContents.openDevTools()

    // Emitted when the window is closed.
    mainWindow.on('closed', function () {
        // Dereference the window object, usually you would store windows
        // in an array if your app supports multi windows, this is the time
        // when you should delete the corresponding element.
        mainWindow = null
    })
}

function ExecuteWindow(){
    if (mainWindow !== null){
        mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
        if (keypair_win !== null) {
            !mainWindow.isVisible() ? keypair_win.hide() : keypair_win.show();
        }
        if (encoding_win !== null){
            !mainWindow.isVisible() ? encoding_win.hide() : encoding_win.show();
        }
    }else{
        createWindow();
    }
}

function openKeyPair(){
    if (keypair_win !== null){
        //keypair_win.isVisible() ? keypair_win.hide() : keypair_win.show();
        keypair_win.show();
    }else {
        keypair_win = new BrowserWindow({show: false, width: 900, title: language["keypair_title"] });
        keypair_win.loadFile('./html/locals/tool/index.html');
        keypair_win.setMenu(null);
        keypair_win.once('ready-to-show', () => {
            keypair_win.show()
        });
        keypair_win.on('closed', function () {
            // Dereference the window object, usually you would store windows
            // in an array if your app supports multi windows, this is the time
            // when you should delete the corresponding element.
            keypair_win = null
        });
    }
}

function openSettings(){
    if (settings_win !== null){
        //keypair_win.isVisible() ? keypair_win.hide() : keypair_win.show();
        settings_win.show();
    }else {
        settings_win = new BrowserWindow({show: false, width: 900, height:400, title: language["settings_title"] });
        settings_win.loadFile('./html/locals/settings/index.html');
        //settings_win.setMenu(null);
        settings_win.once('ready-to-show', () => {
            settings_win.show()
        });
        settings_win.on('closed', function () {
            // Dereference the window object, usually you would store windows
            // in an array if your app supports multi windows, this is the time
            // when you should delete the corresponding element.
            settings_win = null
        });
    }
}

function openEncoding(){
    if (encoding_win !== null){
        //encoding_win.isVisible() ? encoding_win.hide() : encoding_win.show();
        encoding_win.show();
    }else {
        encoding_win = new BrowserWindow({show: false, width: 800, height: 490, title: language["encoding_tools"] });
        encoding_win.loadFile('./html/locals/tool/encoding.html');
        encoding_win.setMenu(null);
        encoding_win.once('ready-to-show', () => {
            encoding_win.show()
        });
        encoding_win.on('closed', function () {
            // Dereference the window object, usually you would store windows
            // in an array if your app supports multi windows, this is the time
            // when you should delete the corresponding element.
            encoding_win = null
        });
    }
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
    app.quit()
} else {
    app.on('second-instance', (event, commandLine, workingDirectory) => {
        // Someone tried to run a second instance, we should focus our window.
        dialog.showMessageBox({
            title: language["single_instance"],
            message: language["single_instance_tips"],
            icon: nativeImage.createFromPath(__dirname + '/app.ico')
        })
    });

    // Create myWindow, load the rest of the app, etc...
    app.on('ready', function () {
        createWindow();

        globalShortcut.register(ShortCut, () => {
            ExecuteWindow();
            // Do stuff when Y and either Command/Control is pressed.
        });

        //set tray‹›
        tray = new Tray(__dirname + "/tray.png");
        const contextMenu = Menu.buildFromTemplate([
            /*{label: 'Item1', click() {
                    mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show()
                }},*/
            {label: language["open_app_settings"], click() {
                    openSettings();
                }},
            {label: language["open_keypair_tools"], click() {
                    openKeyPair();
                }},
            {label: language["open_encoding_tools"], click() {
                    openEncoding();
                }},
            {type: 'separator'},
            {
                label: language["exit_app"], click() {
                    app.quit();
                }
            }
        ]);
        tray.setToolTip(language["app"]);
        tray.setContextMenu(contextMenu);

        tray.on('click', () => {
            ExecuteWindow();
        });

        tray.on("balloon-click", function () {
            ExecuteWindow();
        });

        if (tray_start){
            tray.displayBalloon({title: language["app"], content: language["app_background_run"]});
        }
    });
}

// Quit when all windows are closed.
app.on('window-all-closed', function () {
    // On macOS it is common for applications and their menu bar
    // to stay active until the user quits explicitly with Cmd + Q
    if (process.platform !== 'darwin') app.quit()
});

app.on('activate', function () {

    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (mainWindow === null) createWindow()
});

ipcMain.on('settings', (event, args) => {
    ShortCut = args[0];
    auto_launch = args[1];
    tray_start = args[2];
    config.set("shortcut", ShortCut);
    config.set("tray_start", tray_start);
    config.set("auto_launch", auto_launch);
    let msg = language["shortcut"] + " : " + ShortCut + "\n" + language["auto_launch"] + " : " + auto_launch + "\n" + language["tray_launch"] + " : " + tray_start + "\n\n" + language["settings_saved"];
    const result = dialog.showMessageBox({
        title: language["settings_apply"],
        message: msg,
        icon: nativeImage.createFromPath(__dirname + '/app.ico'),
        buttons: [language["restart_app"], language["ok_know"]]
    });
    if (result === 0){
        app.relaunch();
        app.exit(0)
    }
    if (settings_win !== null){
        try{
            settings_win.close();
        }catch (e) {

        }
    }
});


ipcMain.on('openKeyPair', (event) => {
    openKeyPair();
});

ipcMain.on('openEncoding', (event) => {
    openEncoding();
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.