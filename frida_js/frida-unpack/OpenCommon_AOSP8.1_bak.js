/**
 * 此脚本在以下环境测试通过
 * android os: 8.1.0 64bit  
 * 脚本来源（挤蹭菌衣-大佬）： https://bbs.pediy.com/thread-257917.htm
 * （0x指纹-大佬 ）https://bbs.pediy.com/thread-258776.htm
 * Android os 7 是找OpenMemory函数
 * frida -U -f com.cz.babySister -l OpenCommon_android8.js --no-pause
 * 
 */
function hook_OpenCommon(){
        /*  static std::unique_ptr<DexFile> OpenCommon(const uint8_t* base,
                                                size_t size,
                                                const std::string& location,
                                                uint32_t location_checksum,
                                                const OatDexFile* oat_dex_file,
                                                bool verify,
                                                bool verify_checksum,
                                                std::string* error_msg,
                                                VerifyResult* verify_result = nullptr); */
    //这里我是安卓8.1的，不同版本不一样，自己pull出libart.so，打开ida查
    var strlibart = "libart.so"
    var libart_addr = Module.findBaseAddress(strlibart);
    if (libart_addr){
        console.log("load libart.so 地址", libart_addr);

    }
    //设置OpenCommon对应的函数
    var strOpenCommon = "_ZN3art7DexFile10OpenCommonEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE";
    var OpenCommon_addr ;


    var exports = Module.enumerateExportsSync("libart.so");
    for(var i=0;i<exports.length;i++){
        //send("name:"+exports[i].name+"  address:"+exports[i].address);
        if(exports[i].name ==strOpenCommon){
            send("name:"+exports[i].name+"  address:"+exports[i].address);
            OpenCommon_addr = new NativePointer(exports[i].address);//方式3：奇怪这个好像也不行
        }

     }
    



    //var OpenCommon = Module.findExportByName(strlibart, strOpenCommon);//方式1：这个方式返回是null
    OpenCommon_addr = libart_addr.add(0x0013CEC8)//方式2：OpenCommon函数对应的相对地址0x0013CEC8

    
    if (libart_addr){
        console.log("[*] "+strOpenCommon+"函数用于调试: " + OpenCommon_addr); //?为什么打印出来是null???
    }


    console.log("[*] "+strOpenCommon+"函数 地址: " + OpenCommon_addr); //?为什么打印出来是null???
    Interceptor.attach(OpenCommon_addr, {
        onEnter: function (args) {
            console.log("[*] begin = " + args[1]);//dex文件begin的地址
            console.log("[*] size = " + args[2]);//其实有了base就可以算出size了，这个参数不用也行，这里没有用
            var begin = args[1];
                    console.log("magic : " + Memory.readUtf8String(begin)); //打印magic看下是不是dex
            var address = parseInt(begin,16) + 0x20;//通过begin计算size地址
            var dex_size = Memory.readInt(ptr(address));//读出size大小
            console.log("sizee : " + dex_size);//比较发现跟args[2]是一样的，证明有begin足够脱壳
            //var dex_file = new File("/sdcard/czgDownload/com.cz.babySister/" + dex_size.toString() + ".dex", "wb");//这里自己修改下路径，最好放在apk自己的data目录下，不然以后找不着了
            var dex_file = new File("/sdcard/czgDownload/outputdex/" + dex_size.toString() + ".dex", "wb");//这里自己修改下路径，最好放在apk自己的data目录下，不然以后找不着了
            dex_file.write(Memory.readByteArray(begin, dex_size));
            dex_file.flush();
            dex_file.close();
            console.log("dump dex success");
    
        },
        onLeave: function (retval) {
            //这里也可以通过retval获得dex_file，通过dex数据结构找到begin和size，dump出来     
        }
    });

}

setImmediate(function() {
	//延迟1秒调用Hook方法
	//setTimeout(main, 1000);
	//setTimeout(main);
		setTimeout(hook_OpenCommon);

});
