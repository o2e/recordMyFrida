//收集脚本来自：js逆向技巧分享 https://zhuanlan.zhihu.com/p/108207751?from_voters_page=true
//


/**
 * 用于定位header中关键参数生成位置
 * 当header中包含Authorization时，则插入断点
 * 以chrome插件的方式，在匹配到关键词处插入断点
 */
var code = function () {
    var org = window.XMLHttpRequest.prototype.setRequestHeader;
    window.XMLHttpRequest.prototype.setRequestHeader = function (key, value) {
        if (key == 'authority') {
            debugger;
        }
        return org.apply(this, arguments);
    }
}
var script = document.createElement('script');
script.textContent = '(' + code + ')()';
(document.head || document.documentElement).appendChild(script);
script.parentNode.removeChild(script);