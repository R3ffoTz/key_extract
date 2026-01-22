
Prerequisites
1.	Rooted Android phone (Magisk recommended)
2.	ADB installed on your PC
3.	Python 3.x installed
4.	Frida tools installed
Installation Steps
1. Install Frida on PC (PowerShell)
powershell
pip install frida-tools
2. Download frida-server for Android
•	Check your phone's architecture:
powershell
adb shell getprop ro.product.cpu.abi
•	Download matching version from: https://github.com/frida/frida/releases
•	Look for frida-server-<version>-android-<arch>.xz
3. Push frida-server to phone
powershell
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
4. Start frida-server (in separate terminal)
powershell
adb shell "su -c /data/local/tmp/frida-server &"
Running Scripts

Basic command
powershell
frida -U -f com.zeekr.overseas -l script_name.js
