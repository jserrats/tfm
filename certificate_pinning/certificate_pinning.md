# Certificate pinning

Pinning is the process of associating a host with their expected certificate or public key. In an Android app environment, this is achieved at HTTP level. Most HTTP libraries support pinning a certificate, which works by hardcoding the certificate or the key into the code. From now on, the application only accepts connections from servers that provide the inserted certificate. In the end what we are doing is breaking the chain of trust of certificates, by only trusting the final certificate and not any root certificate issued by any CA or other institution. By doing this the developer increases the difficulty of intercepting HTTPS requests, since the only allowed connections will be to the owner of the pinned certificate, and this certificate cannot be easily changed by adding certificates in the OS, for example.

## Man in the Middle attacks on Android apps

In Android there are 2 kinds of certificates, user and system. User certificates are used by the browsers to determine the security of websites visited. These user certificates can be created and modified with user permissions easily. When applications other than a browser check for the validity of a certificate in a connection,by default they only trust the system certificates. These come preinstalled in the device, and can only be modified in a rooted device. So the first step in intercepting requests from the application we are reversing is to insert our own certificate in the root certificate store.

## Test environment

To test the succesfull bypass I have developed a test application (https://github.com/jserrats/certpin) with very simple functionality. It consists of two buttons, both make a HTTPS request to a public API (`https://swapi.dev/api/people/3/`) and displays the returning JSON. One button makes a usual HTTPS request (control)in order to check if the connection is made successfully. This way we can see if  and to see if we are able to intercept and modify the request using Burp. The other one makes a pinned request, with the hash of the certificate of `swapi.dev`.

In the following snippets we can see the diference between a request made without and with pinning.respectively. The full code can be found on the github project.

`PlainRequestActivity.java`

```java
OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url(url)
                .build();
```

`PinedRequestActity.java`

```java
CertificatePinner certpin = new CertificatePinner.Builder()
                .add(hostname, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo=")
                .build();

        OkHttpClient client = new OkHttpClient.Builder().certificatePinner(certpin)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .build();
```

In the following figure we can see how the phone gets the Burp Proxy certificate, and why it is required that we insert its certificate in the System CA, before we can try evading the pinning.

![](certificate_pinning/res/2020-08-26-19-18-35.png)

This way we have four scenarios, with two tests to perform in each one:

| Scenario                                          | Plain      | Pinned     |
| ------------------------------------------------- | ---------- | ---------- |
| Normality                                         | Successful | Successful |
| Burp - No certificate installed                   | Failure    | Failure    |
| Burp - Certificate installed                      | Successful | Failure    |
| Burp - Certificate installed - Pin bypass enabled | Successful | Successful |

## Installing our root CA on the emulator

In the following steps i describe a way that I have particularly found to install a certificate on the system folder. Particularly we'll be installing the certificate from Burp Proxy

1. Obtain a writable `/system` partition
    1. Launch the emulator with the flag `-writable-system`
    2. Then obtain root on the system with `adb root`
    3. Then remount the `/system` partition as writeable with `adb remount`
    4. Test that the partition was mounted succesfully with `touch /system/test.txt`

2. Obtain the Root CA from burp
   1. Obtain the Burp Root certificate. Enter `http://burp` into a browser configured with burp and download the CA file.
   2. Move the file to the SD card on the device with `adb push cacert.der /mnt/sdcard/cacert.cer`. In this step we are also changing the file's extension

3. Install the Root CA
   1. On the android emulator go to `Security & location > Advanced > Encryption & credentials > Install from SD card`
   2. Select the `cacert.cer` file from the SD. Put any name and choose the `VPN and Apps` option

4. Set the certificate as System certificate
   1. Copy the certificate to the correct folder in the system partition with `cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts`. Now the device trusts the certificate and will be used in app connections

![](certificate_pinning/res/2020-05-16-18-42-54.png)

## Using Burp Proxy to perform "Man in the Middle" attack

With the certificate installed we can configure the emulator to use Burp as a proxy in order to intercept requests. We can see the request appear in burp and in the app without any problem

![](certificate_pinning/res/2020-06-25-19-02-08.png)

![](certificate_pinning/res/2020-05-23-12-35-11.png)

![](certificate_pinning/res/2020-05-23-12-35-35.png)

When performing a pinned request inside our app, the `Okhttp` library performs a check on the certificate provided. In this case, our installed certificate is not accepted by the app even if the system trusts it, as it does not pass the internal check

```java
CertificatePinner certpin = new CertificatePinner.Builder()
         .add(hostname, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo=")
         .build();
```

![](certificate_pinning/res/2020-05-23-12-45-01.png)

### Bypassing certificate pinning

There are numerous ways to bypass a pinning, depending on how it was implemented. In this case there are two easy ways:

* Decompile the APK file, find the string with the hash of the CA, change it for the hash of our own app and repackage and sign the application
* Use Frida to disable the check performed by the HTTP library used (in this case OkHttp)

In this case we'll use the second method, as it is easier and more clean. To effectively disable the pinning check, we have to overwrite the method `check` from the class `CertificatePinner.java` from the OkHttp library. This information can be obtained from the own OkHttp documentation (https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html). Keep in mind that when this method finds a non valid certificate throws and exception, so to successfully bypass it we need to overwrite the whole execution of the method, not just override its return value.

```js
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
```
