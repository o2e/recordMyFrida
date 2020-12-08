//收集脚本来自：js逆向技巧分享 https://zhuanlan.zhihu.com/p/108207751?from_voters_page=true



/**
 * 在console中输入如下代码，如只打印_$开头的变量值
 */
function printValuesInWindow() {
    for (var p in window) {
        if (p.substr(0, 2) !== "_$") 
            continue;
        console.log(p + " >>> " + eval(p))
    }
}



/**
 * 用于定位请求中关键参数生成位置
 * 以chrome插件的方式，在匹配到关键词处插入断点
 * 当请求的url里包含 juejin.cn 时，则插入断点
 * 
 * 很奇怪的是在hook 聚合聊天web是没有拦截成功。切换为简书web测试是ok的，具体什么原因需进一步跟踪
 */
var code = function () {
    var open = window.XMLHttpRequest.prototype.open;
    window.XMLHttpRequest.prototype.open = function (method, url, async) {
        if (url.indexOf("juejin.cn") > -1) {
            debugger;
        }
        return open.apply(this, arguments);
    };
}
var script = document.createElement('script');
script.textContent = '(' + code + ')()';
(document.head || document.documentElement).appendChild(script);
script.parentNode.removeChild(script);