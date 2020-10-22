//https://www.jianshu.com/p/4291ee42c412
//frida -U --no-pause -f com.tencent.wework  -l hook_dlopen.js
//log 如下：
//  dlopen==> /data/user/0/com.tencent.wework/app_tbs/core_share/libtbs_v8.so
//  dlopen==> /data/user/0/com.tencent.wework/app_tbs/core_share/libmttwebview.so
//  dlopen==> /system/lib/libicui18n.so
//  dlopen==> /system/lib/libicuuc.so
//  dlopen==> libc.so
//  dlpeon ==========：
//  dlopen==> libc.so
//  dlpeon ==========：
function hook_dlopen(){
    //第一种方式（针对较老的系统版本）
    var dlopen = Module.findExportByName(null, "dlopen");
    console.log(dlopen);
    if(dlopen != null){
        Interceptor.attach(dlopen,{
            onEnter: function(args){
                var soName = args[0].readCString();
                console.log("dlopen==>",soName);
                //console.log(soName);
                if(soName.indexOf("libc.so") != -1){
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
                console.log("android_dlopen_ext==>",soName);
                //console.log(soName);
                if(soName.indexOf("libc.so") != -1){
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
                        console.log("dlpeon ==========：");  //
}
setImmediate(hook_dlopen);