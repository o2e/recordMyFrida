//https://www.666.cq.cn/index.php/archives/191/
//替换返回值
//该网址还有调用静态函数
function hook_replace() {
    var addr_NewStringUTF = null;

    // 找到 NewStringUTF 地址
    //console.log( JSON.stringify(Process.enumerateModules()));
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i].name;
        if ((symbol.indexOf("CheckJNI") == -1) && (symbol.indexOf("JNI") >= 0)) {
            if (symbol.indexOf("NewStringUTF") >= 0) {
                console.log(symbols[i].name);
                console.log(symbols[i].address);
                addr_NewStringUTF = symbols[i].address;
            }
        }
    }
    console.log("addr_NewStringUTF:", addr_NewStringUTF);  

    // 替换
    var NewStringUTF = new NativeFunction(addr_NewStringUTF, 'pointer', ['pointer', 'pointer']); // 该函数有2个返回值 
    Java.perform(function () {
        Interceptor.replace(addr_NewStringUTF,
            new NativeCallback(
                function (parg0, parg1) {  // 该函数有2个参数
                    console.log("original args:", parg0, Memory.readCString(parg1));
                    var newParg = Memory.allocUtf8String("stringFromFridaNativeHookReplace")
                    var NS = NewStringUTF(parg0, newParg);
                    return NS;
                },
                "pointer",
                ["pointer", "pointer"]))
    })
}

function main() {
    hook_replace();
}
setImmediate(main)