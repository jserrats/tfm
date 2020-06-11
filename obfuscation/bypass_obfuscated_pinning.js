Java.perform(function () {
    var classname = "d.g";
    var classmethod = "a";
    var hookclass = Java.use(classname);
    
    //public final void a(java.lang.String,java.util.List)

    hookclass.a.overload("java.lang.String","java.util.List").implementation = function (v0,v1) {
        send("CALLED: " + classname + "." + classmethod + "()\n");
        //var ret = this.a(v0,v1);

        var s="";
        s=s+"HOOK: " + classname + "." + classmethod + "()\n";
        s=s+"IN: "+eval(v0,v1)+"\n";
        s=s+"OUT: "+ret+"\n";
        //uncomment the line below to print StackTrace
        //s=s+"StackTrace: "+Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()) +"\n";
        send(s);
                
        return ret;
    };
});