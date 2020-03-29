Java.perform(function () {
    var classname = "com.scottyab.rootbeer.RootBeer";
    var classmethod = "checkForSuBinary";
    var hookclass = Java.use(classname);

    //public boolean checkForSuBinary()

    hookclass.checkForSuBinary.overload().implementation = function () {
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = false;

        var s="";
        s=s+("\nHOOK: " + classname + "." + classmethod + "()");
        s=s+"\nIN: "+"";
        s=s+"\nOUT: "+ret;
        send(s);
                
        return ret;
    };
});

Java.perform(function () {
    var classname = "com.scottyab.rootbeer.RootBeer";
    var classmethod = "propsReader";
    var hookclass = Java.use(classname);

    //private java.lang.String[] propsReader()

    hookclass.propsReader.overload().implementation = function () {
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = false;

        var s="";
        s=s+("\nHOOK: " + classname + "." + classmethod + "()");
        s=s+"\nIN: "+"";
        s=s+"\nOUT: "+ret;
        send(s);
                
        return ret;
    };
});