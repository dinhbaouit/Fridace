#!/usr/bin/python
import frida
import sys
import getopt



def printusage():
	print """
	Usage: 
	Trace class   : python app.py [option] -c -p [process] class1 class2 class3 ...
	Trace function: python app.py [option] -f -p [process] function1, function2, function3 ...\n

	Option:
	-n,    --no-backtrace      Set no backtrace
	"""
	sys.exit(2)


def jscode_traceclass(class_list,backtrace_flag):
	class_list_str = '"'+'","'.join([str(elem) for elem in class_list]) + '"'
	if backtrace_flag == 1:
		bt = "printBacktrace()"
	else:
		bt = ""
	return """
var Color = {
    RESET: "\\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
    Light: {
        Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
    }
};

/**
 *
 * @param input. 
 *      If an object is passed it will print as json 
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log', colorPrefix = '\\x1b[3', colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);

};

var printBacktrace = function () {
    Java.perform(function() {
        var android_util_Log = Java.use('android.util.Log'), java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function traceClass(targetClass) {
    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\\sTOKEN(.*)\\(/)[1];
         parsedMethods.push(methodReplace);
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod);
    });
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    LOG({ tracing: targetClassMethod, overloaded: overloadCount }, { c: Color.Blue });

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString(): 'null'});
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { val: retval, str: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            console.log("-------------------------------------------");
            """+bt+""";
            LOG(log, { c: Color.Green });

            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


var Main = function() {
    Java.perform(function () { // avoid java.lang.ClassNotFoundException
        [
            """+class_list_str+"""
        ].forEach(traceClass);
    });
};

Java.perform(Main);
"""

def jscode_tracefunction(function_list, backtrace_flag):
	hookoverload = ""
	count = len(function_list)
	for func in function_list:
		dot = func.rfind(".")
		class_name = func[:dot]
		function_name = func[dot+1:]
		hookoverload += "hookOverloads('"+class_name+"','"+function_name+"');\n";
	if backtrace_flag == 1:
		bt = 'Java.perform(function() {var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());console.log("Backtrace:" + bt);});'
	else:
		bt = ''
	return """function hookOverloads(className, func) {
  var clazz = Java.use(className);
  var overloads = clazz[func].overloads;
  for (var i in overloads) {
	  
    if (overloads[i].hasOwnProperty('argumentTypes')) {
      var parameters = [];

      var curArgumentTypes = overloads[i].argumentTypes, args = [], argLog = '[';

      for (var j in curArgumentTypes) {
        var cName = curArgumentTypes[j].className;
        parameters.push(cName);
        argLog += "'(" + cName + ") ' + v" + j + ",";
        args.push('v' + j);
      }
      argLog += ']';

      var script = "var ret = this." + func + '(' + args.join(',') + ") || '';\\n"
		+ "console.log('--------------------------------------------------------------------------------');"
        + "console.log(JSON.stringify(" + argLog + "));\\n"
        + '    """+bt+"""'
        + "return ret;"

      args.push(script);
      clazz[func].overload.apply(this, parameters).implementation = Function.apply(null, args);
    }
  }
}

Java.perform(function() {
    console.log("-----------------------------------------------");
  """+hookoverload+"""
})
"""

def on_message(message, data):
    print "============================================"
    if message["type"] == "send":
        data = message["payload"]
        print data

def main():
	process_name = ""
	class_list = []
	function_list = []
	jscode_perform = ""
	backtrace_flag = 1

	# option = 1 -> trace class
	# option = 2 -> trace funtion
	option = 0
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ncfp:",["class","function","process=","no-backtrace"])
	except getopt.GetoptError as err:
		printusage()

	# print opts
	# print args

	for o, a in opts:
		if o == "-c":
			option = 1
		if o == "-f":
			option = 2

		if o == "-p" or "--process":
			process_name = a
		if o == "-n" or "--no-backtrace":
			backtrace_flag = 0

	if option == 1 or option == 0 and args != []:
		class_list = args
		jscode_perform = jscode_traceclass(class_list, backtrace_flag)


	if option == 2 and args != []:
		function_list = args
		jscode_perform = jscode_tracefunction(function_list, backtrace_flag)

	if process_name == "" or jscode_perform == "":
		printusage()


	session = frida.get_usb_device().attach(process_name)

	script = session.create_script(jscode_perform)

	script.on("message",on_message)
	script.load()


	raw_input()

if __name__ == "__main__":
	main()
