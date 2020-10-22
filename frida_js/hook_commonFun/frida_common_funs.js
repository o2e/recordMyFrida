

/*
* 
* 在某些时候想要Hook的类可能还没有被加载进来，如果直接加载注入脚本可能会报找不到指定要注入的类的异常，所以应该在脚本中加入延迟方法.
* 相关函数
* setTimeout(fn, delay): 在延迟 delay 毫秒之后，调用 fn，这个调用会返回一个ID，这个ID可以传递给 clearTimeout 用来进行调用取消。
* clearTimeout(id): 取消通过 setTimeout 发起的延迟调用
* setInterval(fn, delay): 每隔 delay 毫秒调用一次 fn，返回一个ID，这个ID可以传给clearInterval 进行调用取消 
* clearInterval(id): 取消通过 setInterval 发起的调用
*/

/**
 * liart.so 的导出函数名和地址都打印出来
 * frida -U -f com.cz.babySister -l libart_exportsSync.js --no-pause > log.log
 */
function hook_exportsSync(){
    var exports = Module.enumerateExportsSync("libart.so");
    for(var i=0;i<exports.length;i++){
        send("name:"+exports[i].name+"  address:"+exports[i].address);
     }
       
}
//枚举遍历所有当前已经加载的类
function enumerateLoadedClasses(){
    Java.perform(function(){Java.enumerateLoadedClasses
        ({
          onMatch: function (name, owner) {
            console.log('onMatch:', name, owner);
          },
          onComplete: function () {
          }
        })
        })

}

/**
 * hook 代理检测 -绕过系统代理检测
 * App防护还是不行,asses目录下能找到pem文件，证书文件，转换成cer安装到手机上，root移动到系统目录即可
 */
function justTrustMe(){
    var System_Class = Java.use("java.lang.System"); 
    System_Class.getProperty.overload('java.lang.String').implementation = function(str) {
      console.log("\n");  
      console.warn("[*] Enter function  getProperty:");  
      console.log("\t[-] str: "+str);  
      if(str == "http.proxyHost" || str == "http.proxyPort"){
        console.log("\t[-] Change proxyHost or proxyPort to null.");
        console.warn("[*] Leaving Function getProperty.");  
        return null;
      }
      var retval = this.getProperty(str);
      console.log("\t[-] return value: "+retval);
      console.warn("[*] Leaving Function getProperty.");      
      return retval;      
    }

}


//打印堆栈
//android.util.Log ->public static String getStackTraceString(Throwable tr)
function showStacks() {
    Java.perform(function() {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    });
}
//打印Native堆栈
function show_native_trace(){
    var func = Module.findBaseAddress("libil2cpp.so").add(0x56FCA8);
    Interceptor.attach(func, {
        onEnter: function(args){
            console.log("called from:\n"+
                Thread.backtrace(this.context,Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        },
        onLeave: function(retval){

        }
    });
}
//HookJava中的loadLibrary并打印堆栈
function hook_library(){
    Java.perform(function() {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const VMStack = Java.use('dalvik.system.VMStack');

        System.loadLibrary.implementation = function(library) {
            try {
                console.log('System.loadLibrary("' + library + '")');
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                return loaded;
            } catch(ex) {
                console.log(ex);
            }
        };

        System.load.implementation = function(library) {
            try {
                console.log('System.load("' + library + '")');
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
                return loaded;
            } catch(ex) {
                console.log(ex);
            }
        };
    });
}
//获取方法名
function getMethodName() {
    var ret;
    Java.perform(function() {
        var Thread = Java.use("java.lang.Thread")
        ret = Thread.currentThread().getStackTrace()[2].getMethodName();
    });
    return ret;
}


/**
 * bytes2Hex 
 * java中 byte范围 -128~127
 * 16进制范围 0 ~ 255
 * @param {*} arr 
 */
function bytes2Hex(arr) {
    var str = "[";
    for (var i = 0; i < arr.length; i++) {
        var z = parseInt(arr[i]);
        if (z < 0) z = 255 + z;
        var tmp = z.toString(16);
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str = str + " " + tmp;
    }
    return (str + " ]").toUpperCase();
}
//hexToBytes
function hexToBytes(str) {
    var pos = 0;
    var len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    var hexA = new Array();
    for (var i = 0; i < len; i++) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        hexA.push(v);
        pos += 2;
    }
    return hexA;
}
function hookFunction() {
// 函数原型 encodeRequest(int i, String str, String str2, String str3, String str4, String str5, byte[] bArr, int i2, int i3, String str6, byte b, byte b2, byte[] bArr2, boolean z)
  var CodecWarpper = Java.use("xx.CodecWarpper");
  CodecWarpper.encodeRequest.implementation = function() {
      var ret = this.encodeRequest.apply(this, arguments);
     //这里可以打印参数和返回值
      return ret;
  }
}

//String转Byte
function stringToBytes(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++ ) {
        ch = str.charCodeAt(i);
        st = [];
        do {
            st.push( ch & 0xFF );
            ch = ch >> 8;
        }
        while ( ch );
        re = re.concat( st.reverse() );
    }
    return re;
}
function jstring2Str(jstring) {
   var ret;
   Java.perform(function() {
       var String = Java.use("java.lang.String");
       ret = Java.cast(jstring, String);//jstring->String
   });
   return ret;
}

function jbyteArray2Array(jbyteArray) {
   var ret;
   Java.perform(function() {
       var b = Java.use('[B');
       var buffer = Java.cast(jbyteArray, b);
       ret = Java.array('byte', buffer);
   });
   return ret;
}


//hook native 函数
function hookNativeFun(callback, funName, moduleName) {
    var time = 1000;
    moduleName = moduleName || null;
    if (!(callback && callback.onEnter && callback.onLeave)) {
        console.log("callback error");
        return
    }
    var address = Module.findExportByName(moduleName, funName);
    if (address == null) {
        setTimeout(hookNativeFun, time, callback, funName, moduleName);
    } else {
        console.log(funName + " hook ok")
        var nativePointer = new NativePointer(address);
        Interceptor.attach(nativePointer, callback);
    }
}

//获取类型
function getParamType(obj) {
    return obj == null ? String(obj) : Object.prototype.toString.call(obj).replace(/\[object\s+(\w+)\]/i, "$1") || "object";
}
//ArrayBuffer 转换
function ab2Hex(buffer) {
    var arr = Array.prototype.map.call(new Uint8Array(buffer), function (x) {return ('00' + x.toString(16)).slice(-2)}).join(" ").toUpperCase();
    return "[" + arr + "]";
}
//ArrayBuffer转String: 解决中文乱码
function ab2Str(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}
//string转ArrayBuffer
function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 每个字符占用2个字节
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
//dump 地址
function dumpAddr(address, length) {
    length = length || 1024;
    console.log(hexdump(address, {
        offset: 0,
        length: length,
        header: true,
        ansi: false
    }));
}
//字符串转Uint8Array
function stringToUint8Array(str){
  var arr = [];
  for (var i = 0, j = str.length; i < j; ++i) {
    arr.push(str.charCodeAt(i));
  }

  var tmpUint8Array = new Uint8Array(arr);
  return tmpUint8Array
}
//Uint8Array转字符串
function Uint8ArrayToString(fileData){
    console.log(fileData)
  var dataString = "";
  for (var i = 0; i < fileData.length; i++) {
    dataString += String.fromCharCode(fileData[i]);
  }

  return dataString
}


//java object 2 strJson 输出 byte[] 等 java 对象 
function jobj2strJson(jobject) {
    var ret = JSON.stringify(jobject);
    return ret;
}
//bin array 转字符串
function bin2String(array) {
    if (null == array) {
        return "null";
    }
    var result = "";
    try {
        var String_java = Java.use('java.lang.String');
        result = String_java.$new(array);
    }
    catch (e) {
        dmLogout("== use bin2String_2 ==");
        result = bin2String_2(array);
    }

    return result;
}

function bin2String_2(array) {
    var result = "";
    try {
        var tmp = 0;
        for (var i = 0; i < array.length; i++) {
            tmp = parseInt(array[i]);
            if ( tmp == 0xc0
                || (tmp < 32 && tmp != 10)
                || tmp > 126 )  {
                return result;
            }  // 不是可见字符就返回了, 换行符除外
            result += String.fromCharCode(parseInt(array[i].toString(2), 2));
        }
    }
    catch (e) {
        console.log(e);
    }
    return result;
}

// hook 所有重载函数
function hookAllOverloads(targetClass, targetMethod) {
    Java.perform(function () {
         var targetClassMethod = targetClass + '.' + targetMethod;
         var hook = Java.use(targetClass);
         var overloadCount = hook[targetMethod].overloads.length;
         for (var i = 0; i < overloadCount; i++) {
                hook[targetMethod].overloads[i].implementation = function() {
                     var retval = this[targetMethod].apply(this, arguments);
                     //这里可以打印结果和参数
                     return retval;
                 }
              }
   });
 }

//循环输出参数的值
function print_params(){
    Interceptor.attach(Module.findExportByName("libc.so", "strcat"), {
        onEnter: function (args) {
            for (var i = 0; i < args.length; i ++) {
                dmLogout("strcat args[" + i + "](" + ptr(args[i]) + "): " + Memory.readUtf8String(args[i]));
            }
        }
    });

}
function dmLogout(str){
    var threadid = Process.getCurrentThreadId();
    console.log("["+threadid+"][" + getFormatDate() + "]" + str);

}



 //输出类所有方法名
 function enumMethods(targetClass) {
     var ret;
     Java.perform(function() {
             var hook = Java.use(targetClass);
             var ret = hook.class.getDeclaredMethods();
             ret.forEach(function(s) {
                 console.log(s);
             })
     })
     return ret;
 }

 //UI thread 注入 吐丝 &获取app context
 //Java.scheduleOnMainThread(fn): run fn on the main thread of the VM.
  function toast_makeText(targetClass) {
    Java.perform(function() {
      var Toast = Java.use('android.widget.Toast');
      //获取app context
      var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
      var context = currentApplication.getApplicationContext();

      Java.scheduleOnMainThread(function() {
        Toast.makeText(context, "Hello World", Toast.LENGTH_LONG.value).show();
      })
    })
  }
//写入文件
function write2File() {
    var file = new File("/sdcard/reg.dat",'w')
    file.write("EoPAoY62@ElRD")
    file.flush()
    file.close()
}
//hook方法。主动调用和修改逻辑
function call_replace_fun() {
    Java.perform(function () {
       //这个c_getSum方法有两个int参数、返回结果为两个参数相加
       //这里用NativeFunction函数自己定义了一个c_getSum函数
       var add_method = new NativeFunction(Module.findExportByName('libhello.so', 'c_getSum'),
       'int',['int','int']);
       //输出结果 那结果肯定就是 3
       console.log("result:",add_method(1,2));
       //这里对原函数的功能进行替换实现
       Interceptor.replace(add_method, new NativeCallback(function (a, b) {
           //h不论是什么参数都返回123
            return 123;
       }, 'int', ['int', 'int']));
       //再次调用 则返回123
       console.log("result:",add_method(1,2));
    });
}
// 主线程调用 https://www.jianshu.com/p/4291ee42c412
function RunOnMain(){
    Java.perform(function(){
        var cls_main = null
        //获取Context
        Java.choose("com.lzy.ndk.MainActivity",{
            onMatch:function(clazz){
                cls_main = clazz
            },
            onComplete:function(){}
        })
        //动态注册一个类实现Runnable方法
        var cls_run = Java.registerClass({
            name:"com.lzy.frida.runnable",
            implements:[Java.use("java.lang.Runnable")],
            //创建类成员变量
            fields:{
                description: 'java.lang.String',
                limit: 'int'
            },
            //创建方法以及重载方法的用法
            methods:{
                run:function(){
                    Java.use("android.widget.Toast").makeText(cls_main,Java.use("java.lang.String").$new("this is a test Toast"),1).show()

                },
                add:[{
                    returnType:'java.lang.String',
                    argumentTypes:['java.lang.String','java.lang.String'],
                    implementation:function(str1,str2){
                        return str1+"+++"+str2
                    }
                },
                {
                    returnType:'java.lang.String',
                    argumentTypes:['java.lang.String'],
                    implementation:function(str1){
                        return str1+"==="
                    }
                }
                ]
            }
        })
        //这里的实现主线程调用方法很多，这里举例一种
        //1.随便在MainActivity找一个View，View.post(Runnable)
        cls_main.bt1.value.post(cls_run.$new())
        //2.Activity的方法runOnUiThread()
        cls_main.runOnUiThread(cls_run.$new())
        //3.new Handler(getMainLooper()).post()
        Java.use("android.os.Handler").$new(cls_main.getMainLooper()).post(cls_run.$new())
        //4.Java.scheduleOnMainThread(function(){}) 不推荐，不好用总是出问题
        Java.scheduleOnMainThread(function(){
            console.log(Java.isMainThread())
        })
    })
}
//用frida hook看一下打印日志--机没有开全局调试情况下 https://bbs.pediy.com/thread-261844.htm
function hookLog() {
    var isFirst = true
    Interceptor.attach(Module.findExportByName("liblog.so","__android_log_print"), {
        onEnter: function (args) {
            if(isFirst) {
                console.log("\n")
                isFirst = false
            }
            if(args[1].readCString().indexOf("ZZZ")!=-1)
                console.log(args[1].readCString()+"\t"+args[2].readCString()+"\t"+args[3]+"\t"+args[4]+"\t"+args[5])
        }
    });
}

//日志打印
function log(str){
    var threadid = Process.getCurrentThreadId()
    var date = new Date()
    var month = date.getMonth() + 1
    var strDate = date.getDate()
    var hour = date.getHours()
    var Minutes = date.getMinutes()
    var Seconds = date.getSeconds()
    if (month >= 1 && month <= 9) {
        month = "0" + month
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate
    }
    if (hour >= 0 && hour <= 9) {
        hour = "0" + hour
    }
    if (Minutes >= 0 && Minutes <= 9) {
        Minutes = "0" + Minutes
    }
    if (Seconds >= 0 && Seconds <= 9) {
        Second = "0" + Seconds
    }
    var currentDate = date.getFullYear() + "-" + month + "-" + strDate
            + " " + hour + ":" + Minutes + ":" + Seconds
    var log = "["+threadid+"][" + currentDate + "] --- " + str
    console.log('\x1b[3' + '6;01' + 'm', log, '\x1b[39;49;00m')
}
//console输出
//在官方API有两种打印的方式，分别是console、send
function hello_printf() {
    Java.perform(function () {
        console.log("");
        console.log("hello-log");
        console.warn("hello-warn");
        console.error("hello-error");
    });
}
//打印内存hexdump，其含义:打印内存中的地址，target参数可以是ArrayBuffer或者NativePointer,而options参数则是自定义输出格式可以填这几个参数offset、lengt、header、ansi。
function hello_printf_so() {
    var libc = Module.findBaseAddress('libc.so');
        console.log(hexdump(libc, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
        }));
}
//动态加载Dex
function loadDex(){
    //这里只是提一下可以使用Frida提供的Api加载dex，你也可以解包再打包，但是显然这个方便得多
    //手动去加载一些工具类（Gson，AndroidUtilCode，自己写的工具类等等）
    Java.openClassFile("/data/local/tmp/helper.dex").load()
    var gson = Java.use("com.google.gson.Gson").$new()
    //=============todo 后续代码。。。。。
}
//计划任务
function ScheduledTask(){
    //用在Spawn启动的时候
    setImmediate(function(){
        console.log("立即执行，只执行一次")
    })
    setTimeout(function(){
        console.log("一秒后执行，只执行一次")
    },1000)
    //Frida Api
    setInterval(function(){
        console.log("每隔一秒执行一次")
    },1000)
    // Java Api
    Java.perform(function(){
        Java.registerClass({
            name:"com.lzy.frida.tsk",
            superClass:Java.use("java.util.TimerTask"),
            methods:{
                run:function(){
                    console.log("等待两秒后每隔一秒调用一次")
                }
            }
        })
        Java.use("java.util.Timer").$new().schedule(Java.use("com.lzy.frida.tsk").$new(),2000,1000)
    })
}
