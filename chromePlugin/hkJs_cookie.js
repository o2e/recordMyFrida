//收集脚本来自：js逆向技巧分享 https://zhuanlan.zhihu.com/p/108207751?from_voters_page=true
//


/**
 * 用于定位cookie中关键参数生成位置
 * 以chrome插件的方式，在匹配到关键词处插入断点
 * 当cookie中匹配到了 TSdc75a61a， 则插入断点。
 * 如要修改跟踪值，则修改关键字即可如-TSdc75a61a -》 MONITOR_WEB_ID （掘金跟踪MONITOR_WEB_ID）
 */
var code = function(){
    var org = document.cookie.__lookupSetter__('cookie');
    document.__defineSetter__("cookie",function(cookie){
        if(cookie.indexOf('MONITOR_WEB_ID')>-1){
            debugger;
        }
        org = cookie;
    });
    document.__defineGetter__("cookie",function(){return org;});
}
var script = document.createElement('script');
script.textContent = '(' + code + ')()';
(document.head||document.documentElement).appendChild(script);
script.parentNode.removeChild(script);