#Android APP破解利器Frida之反调试对抗 https://blog.csdn.net/weixin_34138139/article/details/90361876
# frida -U -f sg.vantagepoint.uncrackable2 --no-pause -l uncrackable2.js

Java.perform(function() {
        exitClass = Java.use("java.lang.System");
        exitClass.exit.implementation = function() {
            console.log("[*] System.exit called");
        }
        console.log("[*] Hooking calls to System.exit");
    });