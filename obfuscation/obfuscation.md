# Obfuscation

Obfuscation consists occurs during compilation, and consists on purposely complicating the code in a manner that the result functions exactly the same as the original, but is way harder to decompile and modify. This is achieved by complicating logic, encrypting resources, renaming methods and classes and adding superfluous code among others.

In an Android environment there are several tools that do obfuscation, but most of them (the supposedly better ones) require expensive licenses. Because of this in this project I'm using R8 which is free to use and has a high amount of documentation online.

## R8

R8 is the default compiler that converts your project’s Java bytecode into the DEX format that runs on the Android platform. This compiler is free and included by default in Android Studio.

While compiling, it can also be configured to do the following things:

- **Code shrinking (or tree-shaking):** detects and safely removes unused classes, fields, methods, and attributes from your app and its library dependencies.
- **Resource shrinking:** removes unused resources from your packaged app, including unused resources in your app's library dependencies.
- **Obfuscation:** shortens the name of classes and members, which results in reduced DEX file sizes.
- **Optimization:** inspects and rewrites your code to further reduce the size of your app's DEX files. For example, if R8 detects that the `else {}` branch for a given if/else statement is never taken, R8 removes the code for the `else {}` branch.

In this case, what will be affecting us is the obfuscation and optimization, which will remove the names of the functions and modify the flow of the code respectively.

## Test environment

In order to understand how R8 applies obfuscation and how to bypass it, we are going to obfuscate the application developed in the previous chapter, certpin. Then we are going to see what has changed, how much more difficult it is now to bypass the pinning and how to do it now.

## Build and install a release version

R8 functionalities are disabled in non release versions, because it can complicate debugging. In order to test the obfuscation we have to install a release version on the device. To do so, we simply have to set the option on `minifyEnabled` on the file `build.gradle`

```gradle
buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
```

and then choose a release build when launching gradle:  

```bash
./gradlew assembleRelease
```

This will generate an `.apk` in the path `app/build/outputs/apk/release/app-release-unsigned.apk`  file, but this cannot be installed directly on the device yet. Android requires `apk` files to be signed in order to install them. Luckily, any certificate is valid, so we can generate and autosign our own.

```console
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
```

```console
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore app.apk alias_name
```

After this two simple steps, we'll have an application ready to be installed. By far the easiest way to do so is to  use ADB.

```bash
adb install build.apk
```

After running this you should find the application installed in the android dashboard.

## Decompile the apk

From now on we'll only work with the compiled APK. In order to obtain the maximum amount of information we'll both obtain the dex classes and use a java decompiler.

Apktool will give us a decompressed APK file with all the dalvik code obfuscated.

```console
apktool d release/app-release-unsigned.apk -d releasedex
```

Jadx will try to decompile the dalvik code and give us an equivalent in to java. This is far from perfect, but it can be useful to understand some snippets of code.

```console
jadx release/app-release-unsigned.apk
```

Here we can see a comparison between the same class `PinnedRequest.java` in the source code and the decompiled version after going trough R8 obfuscation

```java
public class PinnedRequestActivity extends AppCompatActivity {

    TextView txtString;
    public String hostname = "swapi.dev";
    public String url = "https://swapi.dev/api/people/3/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_plain_request);
        txtString = (TextView) findViewById(R.id.txtString);

        try {
            run();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void run() throws IOException {

        //OkHttpClient client = new OkHttpClient();

        CertificatePinner certpin = new CertificatePinner.Builder()
                .add(hostname, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo=")
                .build();

        OkHttpClient client = new OkHttpClient.Builder().certificatePinner(certpin)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.d("DEBUG", "Request Failed");
                call.cancel();
                PinnedRequestActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        txtString.setText("Request failed :(");
                    }
                });
                Log.e("ERROR", e.toString());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {

                final String myResponse = response.body().string();
                Log.d("DEBUG", myResponse);
                PinnedRequestActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        txtString.setText(myResponse);
                    }
                });

            }
        });
    }
}
```

```java
public class PinnedRequestActivity extends j {
    public TextView r;
    public String s = "swapi.dev";
    public String t = "https://swapi.dev/api/people/3/";

    public void n() {
        Set set;
        int i;
        ArrayList arrayList = new ArrayList();
        String str = this.s;
        String[] strArr = {"sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo="};
        if (str != null) {
            for (String str2 : strArr) {
                arrayList.add(C0160g.f2573b.a(str, str2));
            }
            int size = arrayList.size();
            if (size == 0) {
                set = k.f2078a;
            } else if (size != 1) {
                int size2 = arrayList.size();
                if (size2 < 3) {
                    i = size2 + 1;
                } else {
                    i = size2 < 1073741824 ? size2 + (size2 / 3) : Integer.MAX_VALUE;
                }
                set = new LinkedHashSet(i);
                g.a(arrayList, set);
            } else {
                set = Collections.singleton(arrayList.get(0));
                e.a((Object) set, "java.util.Collections.singleton(element)");
            }
            C0160g gVar = new C0160g(set, null);
            z.a aVar = new z.a();
            aVar.u = gVar;
            z zVar = new z(aVar);
            C.a aVar2 = new C.a();
            aVar2.b(this.t);
            B.a(zVar, aVar2.a(), false).a(new c(this));
            return;
        }
        e.a("pattern");
        throw null;
    }

    @Override // a.h.a.f, a.a.c, a.b.a.j, a.k.a.ActivityC0086i
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_plain_request);
        this.r = (TextView) findViewById(R.id.txtString);
        try {
            n();
        } catch (IOException e2) {
            e2.printStackTrace();
        }
    }
}
```

It is quite clear now that this process has complicated enormously the task of understanding what this code is doing, as any names given are replaced by random characters, and the general flow is much more difficult. Notice that the strings are intact. Paid obfuscators like Dexguard do encrypt strings among other assets in order to make it even more difficult to understand what the code does. Since R8 main objective is not security, the obfuscation it does is clearly not enough, though it will be a challenge anyway.

## Find new name for pinner class

The only class names that are not obfuscated are the ones defined in the Android Manifest as activities. We can start there:

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