/*
 * android逆向__超级好用，使用frida追踪方法  https://juejin.im/post/6844903872641630221
 * 调用例子：frida -U -f com.duomai.kikyou --no-pause -l raptor_frida_android_trace2.js
 * 测试企业微信3016：老是失败 估计是有防frida :frida -U -f com.tencent.wework --no-pause -l raptor_frida_android_trace.js
 
 * 企业微信hook报错 ：Process terminated，等待查的资料： https://github.com/frida/frida/issues/995
 */

var logContentArray = new Array();

var singlePrefix = "|----"


// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	// slice() 方法可提取字符串的某个部分，并以新的字符串返回被提取的部分
	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;
	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
	for (var i = 0; i < overloadCount; i++) {

		// hook方法
		hook[targetMethod].overloads[i].implementation = function() {

			var logContent_1 = "entered--"+targetClassMethod;

			var prefixStr = gainLogPrefix(logContentArray);

			logContentArray.push(prefixStr + logContent_1);

			console.warn(prefixStr + logContent_1);
			

			// print backtrace, 打印调用堆栈
			// Java.perform(function() {
			// 	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			// 	console.log(prefixStr +"Backtrace:" + bt);
			// });   

			// print args
			// if (arguments.length) console.log();

			// 打印参数
			for (var j = 0; j < arguments.length; j++) 
			{
				var tmpLogStr = prefixStr + "arg[" + j + "]: " + arguments[j];
				console.log(tmpLogStr);
				logContentArray.push(tmpLogStr);
			}
			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			// 打印返回值
			// console.log("\n"+ targetClassMethod +"--retval: " + retval);
			var tmpReturnStr = prefixStr + "retval: " + retval;
			logContentArray.push(tmpReturnStr);
			console.log(tmpReturnStr);
			//结束标志
			var logContent_ex = "exiting--" + targetClassMethod;
			logContentArray.push(prefixStr + logContent_ex);
			console.warn(prefixStr + logContent_ex);
			return retval;
		}
	}
}

// 获取打印前缀
function gainLogPrefix(theArray)
{
	var lastIndex = theArray.length - 1;

	if (lastIndex<0)
	{
		return singlePrefix;
	}
	
	for (var i = lastIndex; i >= 0; i--) 
	{
		var tmpLogContent = theArray[i];
		var cIndex = tmpLogContent.indexOf("entered--");

		if ( cIndex == -1)
		{
			var cIndex2 = tmpLogContent.indexOf("exiting--");
			if ( cIndex2 == -1)
			{
				continue;
			}
			else
			{
				//与上个方法平级
				var resultStr = tmpLogContent.slice(0,cIndex2);
				return resultStr;
			}
		}
		else
		{
			//在上个方法的内部
			var resultStr = singlePrefix + tmpLogContent.slice(0,cIndex);//replace(/entered--/, "");
			// console.log("("+tmpLogContent+")前缀是：("+resultStr+")");
			return resultStr;
			
		}
	}
	return "";
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		traceMethod("com.duomai.kikyou.task.BuildTask.sendMsgText"); //拦截企业微信插件BuildTask的sendMsgText方法
		traceMethod("com.duomai.kikyou.task.BuildTask.sendMsgImage"); //拦截企业微信插件BuildTask的sendMsgText方法

		
		//trace("hjk.sendTextualMessage"); //拦截企业微信3016发文字的方法sendTextualMessage方法

		//trace("com.test.flyer.MainActivity");
		// trace("com.test.flyer.MainActivity.gainAge");

		// trace("com.target.utils.CryptoUtils.decrypt");
		// trace("com.target.utils.CryptoUtils");
		// trace("CryptoUtils");
		// trace(/crypto/i);
		// trace("exports:*!open*");

	});   
}, 0);
