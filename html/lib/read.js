const app = require('electron').remote.app;
const electronConfig = require('electron-store');
const config = new electronConfig();

let res;
(function () {
    let res = {};
    let lang = config.get("lang", app.getLocale());
    Language = {
        init: function (dir) {
            let value = "";
            try{
                value = require(dir + lang).f();
            }catch (e) {
                console.log("load default lang");
                lang = "en";
                value = require(dir + lang).f();
            }
            res.result = JSON.parse(value);
        },
        get: function (key) {
            return res.result[key];
        }
    }
})();