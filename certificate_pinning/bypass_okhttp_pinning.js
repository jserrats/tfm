setTimeout(function () {
    Java.perform(function () {
        // OkHTTPv3 
        try {
            var okhttp3_Activity = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                console.log('[+] Bypassing OkHTTPv3 {1}: ' + str);
                return true;
            };

        } catch (err) {
            console.log('[-] OkHTTPv3 pinner not found');
            console.log(err);
        }

    });

}, 0);