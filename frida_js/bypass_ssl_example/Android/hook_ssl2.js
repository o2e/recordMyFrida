//app客户端校验服务端证书
//客户端并不会默认信任系统根证书目录中的证书，而是在代码里再加一层校验，这就是证书绑定机制——SSL pinning，如果这段代码的校验过不了，那么客户端还是会报证书错误。
//  Https客户端代码校验服务器证书
//  遇到这种情况的时候，我们一般有三种方式，当然目标是一样的，都是hook住这段校验的代码，使这段判断的机制失效即可。
//  hook住checkServerTrusted，将其所有重载都置空；
function hook_ssl() {
    var cert_dex = Java.openClassFile("/data/local/tmp/certs.dex");

    Java.perform(function () {
        cert_dex.load();
        var certs = Java.use("com.example.certs");
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log("checkServerTrusted overloads:", len);
        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = 
        function(tm, chain, authType, engine) {
            var result = this.checkServerTrusted(tm, chain, authType, engine);
            console.log("checkServerTrusted 1 authType:", authType, " engine:", engine);
            return result;
        };

        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = 
        function(tm, chain, authType, socket) {
            var s = socket.toString();
            var addr = s.substring(s.indexOf("[") + 1, s.indexOf(","));
            var host = addr.split("=")[1].split("/")[0];
            if (host == "") {
                host = addr.split("=")[1].split("/")[1];
            }
            var r = certs.save_cert(host, chain);
            console.log("checkServerTrusted 2 authType:", authType, " socket:", socket, host);
            var tmp_chain = certs.get_cert(host);
            var result = this.checkServerTrusted(tm, tmp_chain, authType, socket);
            return result;
        };

        Platform.checkClientTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = 
        function(tm, chain, authType, engine) {
            var result = this.checkClientTrusted(tm, chain, authType, engine);
            console.log("checkClientTrusted 1 authType:", authType, " engine:", engine);
            return result;
        };

        Platform.checkClientTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = 
        function(tm, chain, authType, socket) {
            var result = this.checkClientTrusted(tm, chain, authType, socket);
            console.log("checkClientTrusted 2 authType:", authType, " socket:", socket);
            return result;
        };
        
    });
}

setTimeout(hook_ssl, 100);