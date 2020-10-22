/*
 * raptor_frida_android_trace.js - Code tracer for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script to trace arbitrary Java Methods and
 * Module functions for debugging and reverse engineering.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to @inode-, @federicodotta, @leonjza, and
 * @dankluev.
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_android_trace.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 * android逆向__超级好用，使用frida追踪方法  https://juejin.im/post/6844903872641630221
 * 调用例子：frida -U -f com.duomai.kikyou --no-pause -l raptor_frida_android_trace.js
 * 测试企业微信3016：老是失败 估计是有防frida :frida -U -f com.tencent.wework --no-pause -l raptor_frida_android_trace.js
 * 葫芦娃 和roysue: https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
 */

// generic trace
function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

	if (type === "module") {

		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			traceModule(target.address, target.name);
		});

	} else if (type === "java") {

		// trace Java Class
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				if (aClass.match(pattern)) {
					found = true;
					var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
					traceClass(className);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method
		if (!found) {
			try {
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
	}
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {

		hook[targetMethod].overloads[i].implementation = function() {
			console.warn("\n*** entered " + targetClassMethod);
			showStacks();

			// print backtrace
			// Java.perform(function() {
			//	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			//	console.log("\nBacktrace:\n" + bt);
			// });   

			// print args
			if (arguments.length) console.log();
			for (var j = 0; j < arguments.length; j++) {
				console.log("arg[" + j + "]: " + arguments[j]);
			}

			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting " + targetClassMethod);
			return retval;
		}
	}
}

// trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = true;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				console.log("\nretval: " + retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
}
//尝试过so层的反调试 https://bbs.pediy.com/thread-260536.htm
//hook  libc.so 的recvfrom方法，修改返回值为-1，从而无法kill掉进程。
function hook_native_libc_recvfrom(){
    var recvfrom_addr = Module.findExportByName("libc.so","recvfrom");
    console.log("recvfrom_addr:",recvfrom_addr);
    if (recvfrom_addr){
        Java.perform(function(){
            Interceptor.attach(recvfrom_addr,{
                onEnter:function(args){
                },onLeave:function(retval){
                        retval.replace(-1);
                        console.log("hook complete");
                }
            })
        })
    }
}
//hook_native_libc_recvfrom();

//打印堆栈
//android.util.Log ->public static String getStackTraceString(Throwable tr)
function showStacks() {
    Java.perform(function() {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    });
}
// usage examples

setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {
		trace("com.duomai.kikyou.task.BuildTask.sendMsgText"); //拦截企业微信插件BuildTask的sendMsgText方法


		
		//trace("com.duomai.kikyou.task.BuildTask");
		//trace("hjk.sendTextualMessage"); //拦截企业微信3016发文字的方法sendTextualMessage方法

		// trace("com.target.utils.CryptoUtils.decrypt");
		// trace("com.target.utils.CryptoUtils");
		// trace("CryptoUtils");
		// trace(/crypto/i);
		// trace("exports:*!open*");

	});   
}, 0); 
