
Prerequisites
1.	Rooted Android phone (Magisk recommended)
2.	ADB installed on your PC
3.	Python 3.x installed
4.	Frida tools installed
5.	
Installation Steps
1. Install Frida on PC (PowerShell)
powershell
pip install frida-tools

3. Download frida-server for Android
•	Check your phone's architecture:
powershell
adb shell getprop ro.product.cpu.abi
•	Download matching version from: https://github.com/frida/frida/releases
•	Look for frida-server-<version>-android-<arch>.xz

5. Push frida-server to phone
powershell
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

7. Start frida-server (in separate terminal)
powershell
adb shell "su -c /data/local/tmp/frida-server &"


Running Scripts
powershell
frida -U -f com.zeekr.overseas -l script_name.js
