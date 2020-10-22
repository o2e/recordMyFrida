# hook art

## copy so 文件到手机

```text
adb push lib/libext64.so /data/local/tmp/libext64.so
adb push lib/libext.so /data/local/tmp/libext.so
adb shell su -c "cp /data/local/tmp/libext64.so /data/app/libext64.so"
adb shell su -c "cp /data/local/tmp/libext.so /data/app/libext.so"
adb shell su -c "chown 1000.1000 /data/app/libext*.so"
adb shell su -c "chmod 777 /data/app/libext*.so"
adb shell su -c "ls -al /data/app/libext*"
```
