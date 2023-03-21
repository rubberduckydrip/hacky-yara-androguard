console.log("Hello");
Java.perform(function() {
    var className = "com.example.app.MainActivity";
    var classMethods = Java.use(className);
    var methods = classMethods.class.getDeclaredMethods();
    for (var i in methods) {
        var methodName = methods[i].getName();
        classMethods[methodName].overload().implementation = function() {
            console.log(className + "." + methodName);
            return this[methodName].apply(this, arguments);
        };
    }
});
