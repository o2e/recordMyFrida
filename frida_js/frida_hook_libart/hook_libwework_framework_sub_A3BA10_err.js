//heibaobao.apk
//frida -U --no-pause -f com.tencent.wework -l hook_libwework_framework_sub_A3BA10.js
//so地址获取成功、函数地址也成功
function hook_sub_A3BA10(){
    // 获取 So 地址
    var lib_addr = Module.findBaseAddress("libwework_framework.so");
    if (lib_addr) {
        var sub_A3BA10_fun_addr = Module.findExportByName("libwework_framework.so", "sub_A3BA10");
        console.log("sub_A3BA10 地址：", sub_A3BA10_fun_addr);
    }

        send("libwework_framework.so地址：" + lib_addr);
        //未导出的函数我们需要手动的计算出函数地址，然后将其转化成一个NativePointer的对象然后进行hook操作
        // 函数地址 = so地址.add(偏移地址 + 1)  // 是否+1 取决于cpu平台型号
        //thumb和arm指令的区分，地址最后一位的奇偶性来进行标志，所以这里还需加1
        var sub_A3BA10_addr = lib_addr.add(sub_A3BA10_fun_addr+1)  // 0x 代表 16进制   text:00000EBC
        send('framework.so->sub_A3BA10地址：'+sub_A3BA10_addr)

        // hook 这个地址
        // hook 函数不需要写参数类型、参数个数
        Interceptor.attach(sub_A3BA10_addr, {
                // 进入函数前Hook
                onEnter: function(args){
                    console.log("sub_A3BA10 进来：");  //
                    console.log("参数0：", args[0]);
                    console.log("参数1：", args[1]);

                    send(args[4])

                },
                // 完成函数hook， retval是返回值
                onLeave: function(retval){
                    console.log("sub_A3BA10 离开：");  //
                }
            });
}

function jstring2Str(jstring) { //从frida_common_funs.js中copy出来
   var ret;
   Java.perform(function() {
       var String = Java.use("java.lang.String");
       ret = Java.cast(jstring, String);//jstring->String
   });
   return ret;
}



function main() {
    hook_sub_A3BA10();
}

//setImmediate(main);

setImmediate(function() {
	//延迟1秒调用Hook方法
	setTimeout(main, 1000);
});