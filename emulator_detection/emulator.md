# Emulator detection

In the context of anti-reversing, the goal of emulator detection is to increase the difficulty of running the app on an emulated device, which causes problems to some tools and techniques reverse engineers like to use. This increased difficulty forces the reverse engineer to defeat the emulator checks or utilize the physical device, making the analysis harder.

To check this, I have developed a fork from the Open source emulator checking app called [Emulator Detector](https://github.com/mofneko/EmulatorDetector). The developed fork can be found [here](https://github.com/jserrats/EmulatorDetector). This application basically checks for several properties in the file `build.prop` that are common on an emulator. This properties indicate parameters such as the name of the model, the manufacturer, and other similar information.

The original Emulator Detector application only returned a boolean result for the application runs in an emulated environment or not. The developed fork also prints in the screen the results for each parameter. This way we can easily see the parameters we are checking and its values.

The following screenshot shows the results of the app installed on our emulator without any tampering. As we can see, it is really obvious that the device is emulated.

![](emulator_detection/res/2020-05-02-17-37-11.png)

Now we proceed to install it in a physical device (my own phone). The parameters we get are the real ones, and we'll take these for bypassing the check

![](emulator_detection/res/2020-05-02-18-32-20.png)

The following table is a summary of the parameters in both devices

| Parameter          | Emulator                                                                             | Real Phone                                                                 | `build.prop`            |
| ------------------ | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | ----------------------- |
| Build.PRODUCT      | sdk_gphone_x86_64                                                                    | OnePlus5T                                                                  | ro.product.name         |
| Build.MANUFACTURER | Google                                                                               | OnePlus                                                                    | ro.product.manufacturer |
| Build.BRAND        | google                                                                               | OnePlus                                                                    | ro.product.brand        |
| Build.DEVICE       | generic_x86_64                                                                       | OnePlus5T                                                                  | ro.product.device       |
| Build.MODEL        | Android SDK built for x86_64                                                         | ONEPLUS A5010                                                              | ro.product.model        |
| Build.HARDWARE     | ranchu                                                                               | qcom                                                                       | -                       |
| Build.FINGERPRINT  | google/sdk_gphone_x86_64/generic_x86_64:9/PSR1.180720.093/5456446:userdebug/dev-keys | OnePlus/OnePlus5T/OnePlus5T:9/PKQ1.180716.001/2002242012:user/release-keys | ro.build.fingerprint    |

Same as before, we are using Frida to manipulate the check results. In this case the evasion is even better, since we are overriding directly the Android class `Build`. In this class methods are the properties described on the file. So we are not modifying the file, but the attributes of the class that parsed it. Because of this, this Frida script should be universal for all checks that use `andoroid.os.Build`, and it does not depend on the implementation of the app.

```js

Java.perform(function () {
    var classname = "android.os.Build";
    var hookclass = Java.use(classname);

    hookclass.PRODUCT.value = "OnePlus5T";
    hookclass.PRODUCT.value = "OnePlus5T";
    hookclass.MANUFACTURER.value  = "OnePlus";
    hookclass.BRAND.value = "OnePlus";
    hookclass.DEVICE.value = "OnePlus5T";
    hookclass.MODEL.value = "ONEPLUS A5010";
    hookclass.HARDWARE.value = "qcom";
    hookclass.FINGERPRINT.value = "OnePlus/OnePlus5T/OnePlus5T:9/PKQ1.180716.001/2002242012:user/release-keys";

});

```

With this Frida script, we can see that the parameters read from the file are the fake ones, and that the check returns false.

![](emulator_detection/res/2020-05-04-20-12-23.png)