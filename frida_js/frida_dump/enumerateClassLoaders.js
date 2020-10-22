//通过enumerateClassLoaders来枚举加载进内存的classloader，再loader.findClass(xxx)寻找是否包括我们想要的interface的实现类，最后通过Java.classFactory.loader = loader来切换classloader，从而加载该实现类。
//第五关比较有趣，它的check函数是动态加载进来的。
//java里有interface的概念，是指一系列抽象的接口，需要类来实现。
//找到能实例化我们要的class的那个class loader，然后把它设置成Java的默认class factory的loader。
function ch5() {
    Java.perform(function () {
        // Java.choose("com.example.androiddemo.Activity.FridaActivity5",{
        //     onMatch:function(x){
        //         console.log(x.getDynamicDexCheck().$className)
        //     },onComplete:function(){}
        // })
        console.log("start")
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if(loader.findClass("com.example.androiddemo.Dynamic.DynamicCheck")){
                        console.log("Successfully found loader")
                        console.log(loader);
                        Java.classFactory.loader = loader ;
                    }
                }
                catch(error){
                    console.log("find error:" + error)
                }
            },
            onComplete: function () {
                console.log("end1")
            }
        })
        Java.use("com.example.androiddemo.Dynamic.DynamicCheck").check.implementation = function () {
            return true
        }
        console.log("end2")
    })
}
setImmediate(ch5)