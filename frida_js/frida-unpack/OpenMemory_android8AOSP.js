'use strict';
function hook_OpenCommon(){
    var strlibart = "libart.so"
    var libart_addr = Module.findBaseAddress(strlibart);
    if (libart_addr){
        console.log("load libart.so 地址", libart_addr);

    }

    //设置OpenCommon对应的函数
    var strOpenCommon = "_ZN3art7DexFile10OpenCommonEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE";
    var OpenCommon_addr ;
    

    var exports = Module.enumerateExportsSync(strlibart);
    for(var i=0;i<exports.length;i++){
        //send("name:"+exports[i].name+"  address:"+exports[i].address);
        if(exports[i].name ==strOpenCommon){
            send("name:"+exports[i].name+"  address:"+exports[i].address);
            //OpenCommon_addr = new NativePointer(exports[i].address);//方式3：奇怪这个好像也不行
        }

    }

    Interceptor.attach(Module.findExportByName(strlibart, strOpenCommon), {
        onEnter: function (args) {
          
            //dex起始位置
            var begin = args[1]
            //打印magic
            console.log("magic : " + Memory.readUtf8String(begin))
            //dex fileSize 地址
            var address = parseInt(begin,16) + 0x20
            //dex 大小
            var dex_size = Memory.readInt(ptr(address))
    
            console.log("dex_size :" + dex_size)
            //dump dex 到/data/data/pkg/目录下
            //var file = new File("/data/data/com.cz.babySister/" + dex_size + ".dex", "wb")
            var file = new File("/sdcard/czgDownload/outputdex/" + dex_size + ".dex", "wb")
            file.write(Memory.readByteArray(begin, dex_size))
            file.flush()
            file.close()
        },
        onLeave: function (retval) {
            if (retval.toInt32() > 0) {
                /* do something */
            }
        }
    });

}

setImmediate(function() {

		setTimeout(hook_OpenCommon);

});
