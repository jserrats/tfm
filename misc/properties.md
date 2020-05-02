# RAW NOTES

>   Android system properties are being managed by special property_service. The `/system/build.prop` is just one out of 4-6 (depending on the version) read-only files containing the default values that property_service uses to populate its internal in-memory database with during start-up. So changes to the files during run time would not propagate until after reboot. The setprop and getprop commands are used to access the data in that database. Unless the property name starts with persist. - then the value gets stored in `/data/property` folder.

## getprop

```console
generic_x86_64:/data/property # getprop ro.build.user
android-build
```

## setprop

