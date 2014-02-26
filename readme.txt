Dealing with certain invalid registry keys

Background:
Here's Mark Russinovich's explanation of the issue; 
In the Win32 API strings are interpreted as NULL-terminated ANSI (8-bit) or wide character (16-bit) strings. In the Native API names are counted Unicode (16-bit) strings. While this distinction is usually not important, it leaves open an interesting situation: there is a class of names that can be referenced using the Native API, but that cannot be described using the Win32 API. 

In short that means that native functions (for instance kernel mode) can deal with null terminated ansi strings, whereas win32 api can't. So by using native functions it is possible to create names (for instance a registry key) that become invalid when accessed in usermode (regedit). That text was taken from the description of RegDelNull which really sparked this off; http://technet.microsoft.com/en-us/sysinternals/bb897448 That tool is definetely broken, and I am certain RegKeyFixer performs much better at dealing with these invalid key names.


Proof of Concept:
Inspired by good old RegHide; http://technet.microsoft.com/en-us/sysinternals/dd581628.aspx I wrote my own (CreateInvalidKey.exe) which is included in the download. Run the PoC and verify with regedit that you have an invalid registry key. Then run RegKeyFixer and specify the correct path, and remember to specify -r as switch (rename), to convert the key into a valid one. RegDelNull seems completely broken on x64, and halfbroken on x86 (could identify and delete the key, but not rename it). To fix the invalid key run this from the commandline;

RegKeyFixer64.exe \Registry\Machine\software\joakim -r -n


Details:
The included tools utilizes some powerfull native functions in ntdll.dll. Theses functions are what lets you deal with invalid key names, because we can interact with the OBJECT_ATTRIBUTES structure; http://msdn.microsoft.com/en-us/library/windows/hardware/ff557749(v=vs.85).aspx .

Since it uses native NT functions, it does not work with user friendly registry names like HKEY_LOCAL_MACHINE, HKCU etc. It will only take the Windows internal registry names, those starting with \Registry\... Below is a listing of the most important translations:

HKEY_LOCAL_MACHINE             \registry\machine
HKEY_USERS                     \registry\user
HKEY_CURRENT_USER              \registry\user\user_sid
HKEY_CLASSES_ROOT              \registry\machine\software\classes
HKEY_CURRENT_CONFIG            \Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current


The user sid is the one similar to this: S-1-5-21-2895024241-3518395705-1366494917-288


The syntax is RegKeyFixer.exe path -switch1 -switch2

Path can be in the format specified above

Switch1:
-r switch is for renaming invalid key names
-d switch is for deleting invalid key names
-f switch is for just finding the invalid key names (just search, no repair)

Switch2
-s switch is for recursive mode
-n switch is for regular enumeration of subkeys


Some examples:

Recursively find and rename invalid keys found at HKLM\SOFTWARE and all its subkeys
RegKeyFixer.exe \Registry\Machine\SOFTWARE -r -s

Just find invalid key names at HKLM\SYSTEM\ControlSet001\services  (no recursion, just enumerate 1 level down)
RegKeyFixer.exe \Registry\Machine\SYSTEM\ControlSet001\services -f -n

The tools have been tested on Windows 7 SP1 x64 and XP SP3 x86.

Extra:
There is a second PoC included that generate keys that are more or less impossible to fix on a live system. I suspect the only way to fix such keys, are to do it in offline mode. That means my program is not able to fix those keys. If you know about a program than can fix those keys, then let me know.



