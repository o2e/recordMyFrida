//heibaobao.apk
//frida -U --no-pause -f demo2.jni.com.myapplication -l hook_libJniTest_check.js
//so地址获取成功、函数地址也成功
//为什么参数还没测试通过呢？？？？？？？？？
//参考文章：frida进阶-Android逆向之旅---Hook神器家族的Frida工具使用详解
//  https://blog.csdn.net/tabactivity/article/details/88313965
//frida 学习记录--看雪-堂前燕 https://bbs.pediy.com/thread-252319.htm
//frida:常用方法[Native]-Zok https://www.666.cq.cn/index.php/archives/191/
//Frida教程-qingemengyue https://blog.csdn.net/qingemengyue/article/details/80061491
//基于 Frida 的脱壳工具 https://www.666.cq.cn/index.php/archives/211/
function hook_myJNI_check(){
    // 获取 So 地址
    var libJniTest_addr = Module.findBaseAddress("libJniTest.so");
    if (libJniTest_addr) {
        var myapplication_myJNI_check = Module.findExportByName("libJniTest.so", "Java_demo2_jni_com_myapplication_myJNI_check");
        console.log("Java_demo2_jni_com_myapplication_myJNI_check 地址：", myapplication_myJNI_check);
    }

        send("libJniTest.so地址：" + libJniTest_addr);
        //未导出的函数我们需要手动的计算出函数地址，然后将其转化成一个NativePointer的对象然后进行hook操作
        // 函数地址 = so地址.add(偏移地址 + 1)  // 是否+1 取决于cpu平台型号
        //thumb和arm指令的区分，地址最后一位的奇偶性来进行标志，所以这里还需加1
        var myJNI_check = libJniTest_addr.add(0x0EB8+1)  // 0x 代表 16进制   text:00000EBC
        send('myJNI->check地址：'+myJNI_check)


        // hook 这个地址
        // hook 函数不需要写参数类型、参数个数
        Interceptor.attach(myJNI_check, {
                // 进入函数前Hook
                onEnter: function(args){
                    console.log("Java_demo2_jni_com_myapplication_myJNI_check 进来：");  //

                    console.log("参数4--密码：", args[4],"这里是jstring 的地址，所有打印该参数是需要转换为Str.");
                    console.log("参数3--用户：", jstring2Str(args[3]));
                    console.log("参数4--密码：", jstring2Str(args[4]));

                    send(args[4])
                    //输出上下文因其是一个Objection对象，需要它进行接送、转换才能正常看到值 :对象。其他处理器特定的键也可用，例如eax、rax、r0、x0等。也可以通过分配给这些键来更新寄存器值。
                    console.log('Context  : ' + JSON.stringify(this.context));
                    //返回地址，类型是NativePointer
                    console.log('Return   : ' + this.returnAddress);
                    //输出线程id
                    console.log('ThreadId : ' + this.threadId);
                    console.log('Depth    : ' + this.depth);
                    console.log('Errornr  : ' + this.err);


                },
                // 完成函数hook， retval是返回值
                onLeave: function(retval){
                    console.log("Java_demo2_jni_com_myapplication_myJNI_check 离开：");  //
                    //retval.replace("恭喜你，这是你要的返回");

                    send(retval);
                    console.log("函数返回old值：", jstring2Str(retval));
                    //构造env，然后调用env.newStringUtf创建jstring （想知道env有哪些js方法可调用，看查看frida-java-master/lib/env.js 源码）
                    var env = Java.vm.getEnv();
                    var jstring = env.newStringUtf("frida hook native 你要的jstring");
                    retval.replace(ptr(jstring));//修改返回值
                    console.log("函数返回new值：", jstring2Str(retval));
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
    hook_myJNI_check();
}

setImmediate(main);