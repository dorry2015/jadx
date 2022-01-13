//是否打印颜色，主要是写radar.log的时候打开此开关
var WITH_COLOR = true;
var INVOKEID = 0;
var jsnCls = null;
//控制台颜色控制
var COLOR = {
    Reset: "\x1b[39;49;00m",
    Black: "\x1b[30;11m",
    Red: "\x1b[31;11m",
    Green: "\x1b[32;11m",
    Yellow: "\x1b[33;11m",
    Blue: "\x1b[34;11m",
    Purple: "\x1b[35;11m",
    Cyan: "\x1b[36;11m",
    Gray: "\x1b[37;11m"
};

if (!WITH_COLOR) {
    for (let key in COLOR) {
        COLOR[key] = "";
    }
}

//Google Gson序列化
function toGSONString(javaObject) {
    // Google Gson
    // let gsonCls = Java.use('dorry.com.google.gson.Gson');
    // let toJsonMethod = gsonCls.toJson.overload("java.lang.Object");
    // return toJsonMethod.call(gsonCls.$new(), javaObject);
    // fastJson
    if(!jsnCls){
        Java.perform(function(){
            // var dexFile = '/sdcard/bhdex.dex';
            var dexFile = '/data/local/tmp/bhdex.dex';
            Java.openClassFile(dexFile).load();
            jsnCls = Java.use("bh.com.alibaba.fastjson.JSON");
        })
    }
    return jsnCls.toJSONString;
}

//打印函数详细信息
function printMethod(invokeId, stackInfo, javaObj, args, ret, methodName) {
    let printString = '\n' + COLOR.Yellow + '------------runFlag:' + invokeId + '---------------' + COLOR.Reset + '\n';
    //函数名
    printString += COLOR.Blue + methodName + COLOR.Reset + '\n';
    //参数
    if (args) {
        for (let i = 0; i < args.length; ++i) {
            printString += COLOR.Green + '[argument ' + i + ']:' + COLOR.Reset + toGSONString(args[i]) + '\n';
        }
    }
    //返回值
    if (ret != undefined) {
        printString += COLOR.Green + '[ret or val]:' + COLOR.Reset + toGSONString(ret) + '\n';
    }
    //是否打印堆栈
    if (stackInfo) {
        let currentThread = Java.use('java.lang.Thread').currentThread();
        printString += 'thread_id:' + currentThread.getId() + ',name:' + currentThread.getName() + ')';
        //获取堆栈信息很耗时
        let stackInfo = Java.use('android.util.Log').getStackTraceString(Java.use("java.lang.Exception").$new());
        printString += stackInfo.substring(20);
    }
    printString += COLOR.Yellow + '------------endFlag:' + invokeId + '---------------' + COLOR.Reset + '\n';
    //存储对象
    if (javaObj) {
        
    }
    console.log(printString);
    //WriteRadarLogFile(printString);
}