# Obfuscation

## R8

R8 is the new proguard.

## Build a release version

```bash
./gradlew assembleRelease
```

## Sign your app

Las aplicaciones Android deben ser firmadas antes de poder ser ejecutadas en el dispositivo.

A diferencia de Apple, las aplicaciones Android pueden ser autofirmadas.

```bash
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
```

```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
```

## Install

```bash
adb install build.apk
```

## Decompile the apk

From now on we'll only work with the compiled APK. In order to obtain the maximum ammount of information we'll obtain the dex classes and use a java decompiler.

```console
apktool d release/app-release-unsigned.apk -d releasedex
```

```console
jadx release/app-release-unsigned.apk
```

## Find new name for pinner class

The only class ames that are not ofuscated are the ones defined in the Android Manifest as activities. We can start there:

```dalvik
# virtual methods
.method public n()V
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2
    iget-object v1, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->s:Ljava/lang/String;

    const-string v2, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo="

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    if-eqz v1, :cond_5

    .line 3
    array-length v4, v2

    const/4 v5, 0x0

    move v6, v5

    :goto_0
    if-ge v6, v4, :cond_0

    aget-object v7, v2, v6

    sget-object v8, Ld/g;->b:Ld/g$b;

    invoke-virtual {v8, v1, v7}, Ld/g$b;->a(Ljava/lang/String;Ljava/lang/String;)Ld/g$c;

    move-result-object v7

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    //...
```

The first thing we see is the hash of the pinned certificate in a plain string. A quick solution would be to simply modify this string and replace it with the hash of our certificate, and then repack and resign the application. This approach would not work if the relase version was obfuscated with a professional grade tool, such as dexguard, since it does encrypt all plain strings found in code. Because of this, we'll try to find the new name of the class and bypass the pinning using Frida once again.

```dalvik
invoke-virtual {v8, v1, v7}, Ld/g$b;->a(Ljava/lang/String;Ljava/lang/String;)Ld/g$c;
```

In this line we can see that we are invoking the method `a` from the class `d.g`. This line is equivalent to this other one in the source code:

```java
        CertificatePinner certpin = new CertificatePinner.Builder()
                .add(hostname, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo=")
                .build();
```

This method is invoked passing the hash of the certificate, and has the same signature `"java.lang.String","java.lang.String"`, so we can deduce the class CertificatePinner no has the name `d,g`.

If we enumerate classes which package begin with `d.g` and then analyze their signatures to one that matches the method `check(String hostname, List<Certificate> peerCertificates)` we'll find the class we are looking for.

If we look for the implementation of this [CertificatePinner](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html#check-java.lang.String-java.util.List-)

>Confirms that at least one of the certificates pinned for hostname is in peerCertificates. Does nothing if there are no certificates pinned for hostname. OkHttp calls this after a successful TLS handshake, but before the connection is used.
>
>Throws:
`SSLPeerUnverifiedException` - if peerCertificates don't match the certificates pinned for hostname.

So in order to bypass this control, we simply have to not execute this function in order to avoid raising any exception.