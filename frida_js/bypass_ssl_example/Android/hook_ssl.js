//app客户端校验服务端证书
//客户端并不会默认信任系统根证书目录中的证书，而是在代码里再加一层校验，这就是证书绑定机制——SSL pinning，如果这段代码的校验过不了，那么客户端还是会报证书错误。
//  Https客户端代码校验服务器证书
//  遇到这种情况的时候，我们一般有三种方式，当然目标是一样的，都是hook住这段校验的代码，使这段判断的机制失效即可。
//  hook住checkServerTrusted，将其所有重载都置空；
function hook_ssl() {
    Java.perform(function () {
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log(len);
        for (var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
            };
        }
    });
}

setTimeout(hook_ssl, 100);