'use strict';
/**
 * 此脚本在以下环境测试通过--ok
 * android os: 7.1.2 32bit青橙手机  (不同手机可能要改OpenMemory的签名)
 * legu: libshella-2.8.so
 * 360:libjiagu.so
 * 如果Module.findExportByName 获得OpenMemory签名地址返回null，那么需要切换inline hook方式hook
 *  Android 8.1 版本的可以去 hook OpenCommon 函数，
 * 再比如Android 9.0 的 OpenMemroy 的参数不一样，arg[1] 不是 dex 的内存地址，是 dex 的大小等等。 * 
 * 运行格式：frida -U -f 包名 -l OpenMemory_android7qc.js --no-pause
 * frida -U -f com.cz.babySister -l OpenMemory_android7qc.js --no-pause
 */
//Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"), {
    Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"), {
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