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

