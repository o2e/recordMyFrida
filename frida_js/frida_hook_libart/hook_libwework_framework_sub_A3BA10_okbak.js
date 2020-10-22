//wework.apk
//frida -U --no-pause -f com.tencent.wework -l hook_libwework_framework_sub_A3BA10.js
//so地址获取成功、函数地址也成功
function hook_sub_A3BA10(){
    // 获取 So 地址
    var lib_addr = Module.findBaseAddress("libwework_framework.so");
        //sub_A3BA10 （.text:00A3BA10）不是导出的函数，不能用Module.findExportByName。这里用inline的方式获取
        //函数原型：int __fastcall sub_A3BA10(int a1, int a2, int a3, int a4)
        send("libwework_framework.so地址base：" + lib_addr);
        //未导出的函数我们需要手动的计算出函数地址，然后将其转化成一个NativePointer的对象然后进行hook操作
        // 函数地址 = so地址.add(偏移地址 + 1)  // 是否+1 取决于cpu平台型号
        //thumb和arm指令的区分，地址最后一位的奇偶性来进行标志，所以这里还需加1
        var sub_A3BA10_addr = lib_addr.add(0xA3BA10)  // 0x 代表 16进制
        //var myJNI_check = libJniTest_addr.add(0x0EB8+1)  // 0x 代表 16进制   text:00000EBC
        send('framework.so->sub_A3BA10地址：'+sub_A3BA10_addr)

        // hook 这个地址
        // hook 函数不需要写参数类型、参数个数
        Interceptor.attach(sub_A3BA10_addr, {
                // 进入函数前Hook
                onEnter: function(args){
                    console.log("sub_A3BA10 进来：");  //
                    console.log("参数0：", args[0].readCString());//获取指针
                    var arg_0 = args[0].readInt();
                    console.log("参数0 指针的int：", arg_0);

                    //console.log("参数0：", ptr(args[0]).readCString());////获取指针
                    console.log("参数1：", args[1].readInt());
                    var fileName = args[2].readCString();
                    if(fileName.indexOf("Info.db") != -1){
                        console.log("sub_A3BA10 参数[2]：filename",fileName);  ////正常 ：pvmerge_kv.jason ；或：pvmerge 或：redenvelopes info.db
                        console.log("native调用栈called from:\n"+
                            Thread.backtrace(this.context,Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                    console.log("参数2：", args[2].readCString());
                    console.log("参数3：", args[3]);
                    //console.log("参数4：", args[4].readCString());//乱码
                    //console.log("参数5：", args[5]);

                },
                // 完成函数hook， retval是返回值
                onLeave: function(retval){
                    console.log("sub_A3BA10 离开：",retval);  //

                }
            });
}
//ArrayBuffer转String: 解决中文乱码
function ab2Str(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}
function hook_dlopen(){
    //第一种方式（针对较老的系统版本）
    var dlopen = Module.findExportByName(null, "dlopen");
    console.log(dlopen);
    if(dlopen != null){
        Interceptor.attach(dlopen,{
            onEnter: function(args){
                var soName = args[0].readCString();
                //console.log("dlopen==>",soName);
                if(soName.indexOf("libwework_framework.so") != -1){
                    console.log("dlopen==>",soName);
                    this.hook = true;
                }
            },
            onLeave: function(retval){
                if(this.hook) {
                    dlopentodo();
                };
            }
        });
    }

    //第二种方式（针对新系统版本）
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    console.log(android_dlopen_ext);
    if(android_dlopen_ext != null){
        Interceptor.attach(android_dlopen_ext,{
            onEnter: function(args){
                var soName = args[0].readCString();
                //console.log("android_dlopen_ext==>",soName);
                if(soName.indexOf("libwework_framework.so") != -1){
                    this.hook = true;
                }
            },
            onLeave: function(retval){
                if(this.hook) {
                    dlopentodo();
                };
            }
        });
    }
}

function dlopentodo(){
    //todo ...
    hook_sub_A3BA10();
                        console.log("dlpeon ==========：");  //
}
//ArrayBuffer转String: 解决中文乱码
function ab2Str(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}
function jstring2Str(jstring) { //从frida_common_funs.js中copy出来
   var ret;
   Java.perform(function() {
       var String = Java.use("java.lang.String");
       ret = Java.cast(jstring, String);//jstring->String
   });
   return ret;
}





//setImmediate(main);

setImmediate(function() {
	//延迟1秒调用Hook方法
	//setTimeout(main, 1000);
		//setTimeout(main);
		setTimeout(hook_dlopen);

});