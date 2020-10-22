/**
 * 此脚本在以下环境测试通过
 * frida -U -f com.cz.babySister -l libart_exportsSync.js --no-pause > log.log
 * liart.so 的导出函数名和地址都打印出来
 */
function hook_exportsSync(){
    var exports = Module.enumerateExportsSync("libart.so");
    for(var i=0;i<exports.length;i++){
        send("name:"+exports[i].name+"  address:"+exports[i].address);
     }
       
}

setImmediate(function() {
	//延迟1秒调用Hook方法
	//setTimeout(main, 1000);
	//setTimeout(main);
		setTimeout(hook_exportsSync);

});
