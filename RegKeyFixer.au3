#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Searches registry for invalid key names
#AutoIt3Wrapper_Res_Description=Searches registry for invalid key names
#AutoIt3Wrapper_Res_Fileversion=1.0.0.2
#AutoIt3Wrapper_Res_LegalCopyright=Joakim Schicht
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include <String.au3>
Global Const $__WINAPICONSTANT_FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
Global Const $__WINAPICONSTANT_FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
Global Const $tagIOSTATUSBLOCK = "dword Status;ptr Information"
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $KEY_READ = 0x20019
Global Const $KEY_WRITE = 0x20006
Global Const $KEY_CREATE_LINK = 0x0020
Global Const $KEY_ALL_ACCESS = 0xF003F
Global Const $KEY_CREATE_SUB_KEY = 0x4
Global Const $KEY_ENUMERATE_SUB_KEYS = 0x8
Global Const $KEY_NOTIFY = 0x10
Global Const $KEY_QUERY_VALUE = 0x1
Global Const $REG_OPTION_NON_VOLATILE = 0x00000000
Global Const $tagKEYNODEINFORMATION = "int64 LastWriteTime;ulong TitleIndex;ulong ClassOffset;ulong ClassLength;ulong NameLength;byte Name[2048]"
Global Const $KeyNodeInformation = 1
Global $hNTDLL = DllOpen("ntdll.dll")
;$hFile = FileOpen(@ScriptDir&"\keys.txt", 2)
Global $Timerstart = TimerInit()
If $cmdline[0] <> 3 Then
	ConsoleWrite("Error: wrong input " & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Try:" & @CRLF)
	ConsoleWrite("RegKeyFixer.exe path -switch1[-r | -d | -f] -switch2[-s | -n]" &  @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("path:" & @CRLF)
	ConsoleWrite("Can be something like \Registry\Machine\SOFTWARE" & @CRLF)
	ConsoleWrite("switch1:" & @CRLF)
	ConsoleWrite("-r switch is for renaming invalid key names" & @CRLF)
	ConsoleWrite("-d switch is for deleting invalid key names" & @CRLF)
	ConsoleWrite("-f switch is for just finding the invalid key names (just search, no repair)" & @CRLF)
	ConsoleWrite("switch2:" & @CRLF)
	ConsoleWrite("-s switch is for recursive mode" & @CRLF)
	ConsoleWrite("-n switch is for regular enumeration of subkeys" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Examples:" & @CRLF)
	ConsoleWrite("Recursively find and rename invalid keys found at HKLM\SOFTWARE and all its subkeys" & @CRLF)
	ConsoleWrite("RegKeyFixer.exe \Registry\Machine\SOFTWARE -r -s" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Just find invalid key names at HKLM\SYSTEM\ControlSet001\services  (no recursion, just enumerate 1 level down)" & @CRLF)
	ConsoleWrite("RegKeyFixer.exe \Registry\Machine\SYSTEM\ControlSet001\services -f -n" & @CRLF)
	Exit
EndIf
If StringRight($cmdline[1],1) = "\" Then
	$RootDir = StringTrimRight($cmdline[1],1)
Else
	$RootDir = $cmdline[1]
EndIf
$ObjectNames = StringSplit($RootDir,"\")
Local $tmp
For $i = 1 To Ubound($ObjectNames)-2
	$tmp &= $ObjectNames[$i]&"\"
Next
$RootDir = StringTrimRight($tmp,1)
If $ObjectNames[0] < 2 Then
	$ObjName = ""
Else
	$ObjName = $ObjectNames[Ubound($ObjectNames)-1]
EndIf
$RootDir = _StrToUnicode($RootDir)
$ObjName = _StrToUnicode($ObjName)
$CreateKey = _CheckSubKeys($RootDir, $ObjName)
If @error Then Exit
DllClose($hNTDLL)
_End($Timerstart)
;FileClose($hFile)
Exit

Func _CheckSubKeys($startkey, $subkey)
;	ConsoleWrite("Startkey: " &  _HexToString(_RemoveUnicode($startkey))&"\"&_HexToString(_RemoveUnicode($subkey)) & @CRLF)
;	FileWrite($hFile,_HexToString(_RemoveUnicode($startkey))&"\"&_HexToString(_RemoveUnicode($subkey)) & @CRLF)
    Local $key, $found = ""
	Local $Disposition, $ret, $KeyHandle, $NameLengthDiff, $ResultLength, $Index, $handle, $handle2, $aCounter = 1, $aTmp, $nLength
	Local $szName = DllStructCreate("byte[520]")
	Local $sUS = DllStructCreate("ushort Length;ushort MaximumLength;ptr Buffer")
	Local $sOA = DllStructCreate($tagOBJECTATTRIBUTES)
	DllStructSetData($szName, 1, "0x"&$startkey)
	$nLength = StringLen($startkey)/2
	DllStructSetData($sUS,"Length",$nLength)
	DllStructSetData($sUS,"MaximumLength",$nLength+2)
	DllStructSetData($sUS,"Buffer",DllStructGetPtr($szName))
	DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", 0)
    DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
	$ret = DllCall($hNTDLL, "int", "NtOpenKey", "hwnd*", "", "dword", $KEY_READ, "ptr", DllStructGetPtr($sOA))
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Location: " &  _HexToString(_RemoveUnicode($startkey)) & @CRLF)
		ConsoleWrite("Error in NtOpenKey 1 : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,0)
	EndIf
	$handle = $ret[1]
	Local $szName = DllStructCreate("byte[520]")
	Local $sUS = DllStructCreate("ushort Length;ushort MaximumLength;ptr Buffer")
	DllStructSetData($szName, 1, "0x"&$subkey)
	$nLength = StringLen($subkey)/2
	DllStructSetData($sUS,"Length",$nLength)
	DllStructSetData($sUS,"MaximumLength",$nLength+2)
	DllStructSetData($sUS,"Buffer",DllStructGetPtr($szName))
    DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", $handle)
    DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
	$ret = DllCall($hNTDLL, "int", "NtOpenKey", "hwnd*", "", "dword", $KEY_READ, "ptr", DllStructGetPtr($sOA))
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Location: " &  _HexToString(_RemoveUnicode($startkey)) & "\" & _HexToString(_RemoveUnicode($subkey)) & @CRLF)
		ConsoleWrite("Error in NtOpenKey 2 : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,0)
	EndIf
	$handle = $ret[1]
    $Index = 0
    While 1
		$sKI = DllStructCreate($tagKEYNODEINFORMATION)
		Local $ResultLength
		Local $ret = DllCall($hNTDLL, "int", "NtEnumerateKey", "hwnd", $handle, "dword", $Index, "dword", $KeyNodeInformation, "ptr", DllStructGetPtr($sKI), "dword", DllStructGetSize($sKI), "ulong*", $ResultLength)
		If Not NT_SUCCESS($ret[0]) And $ret[0] <> -2147483622 Then
			ConsoleWrite("Location: " &  _HexToString(_RemoveUnicode($startkey)) & "\" & _HexToString(_RemoveUnicode($subkey)) & " //$Index=" & $Index & @CRLF)
			ConsoleWrite("Error in NtEnumerateKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
			If Hex($ret[0],8) = "C0000008" Then ExitLoop; STATUS_INVALID_HANDLE
			$Index += 1
			ContinueLoop
		EndIf
		$NtStatus = "0x"&Hex($ret[0],8)
		If $NtStatus = "0x8000001A" Then ExitLoop ; STATUS_NO_MORE_ENTRIES
		$NameLength = DllStructGetData($sKI,"NameLength")
		$Name = DllStructGetData($sKI,"Name")
		$Name = StringMid($Name,3,$NameLength*2)
		$TestChars = _FixUnicodeString($Name)
		$InvalidChars = $TestChars[0]
		$FixedChars = $TestChars[1]
		If $InvalidChars > 0 Then
			ConsoleWrite("Startkey: " &  _HexToString(_RemoveUnicode($startkey)) & "\" & _HexToString(_RemoveUnicode($subkey)) & @CRLF)
			ConsoleWrite("Invalid keyname in hex: " &  $Name & @CRLF)
			ConsoleWrite("Number of invalid charaters in keyname: " &  $InvalidChars & @CRLF)
			Local $szName = DllStructCreate("byte[520]")
			Local $sUS = DllStructCreate("ushort Length;ushort MaximumLength;ptr Buffer")
			DllStructSetData($szName, 1, "0x"&$Name)
			$nLength = StringLen($Name)/2
			DllStructSetData($sUS,"Length",$nLength)
			DllStructSetData($sUS,"MaximumLength",$nLength+2)
			DllStructSetData($sUS,"Buffer",DllStructGetPtr($szName))
			DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
			DllStructSetData($sOA, "RootDirectory", $handle)
			DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
			DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
			DllStructSetData($sOA, "SecurityDescriptor", 0)
			DllStructSetData($sOA, "SecurityQualityOfService", 0)
			$ret = DllCall($hNTDLL, "int", "NtOpenKey", "hwnd*", "", "dword", $KEY_ALL_ACCESS, "ptr", DllStructGetPtr($sOA))
			If Not NT_SUCCESS($ret[0]) Then
				ConsoleWrite("Location: " &  _HexToString(_RemoveUnicode($startkey)) & "\" & _HexToString(_RemoveUnicode($subkey)) & "\" & _HexToString($FixedChars) & @CRLF)
				ConsoleWrite("Error in NtOpenKey 3 : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
				Return SetError(1,0,$ret[0])
			EndIf
			$handle2 = $ret[1]
			If $cmdline[2] = "-r" Then
				$RenameKey = _NtRenameKey2($handle2,_HexToUnicode($FixedChars))
				If @error Then
#cs
;------------------------------- To prevent "Access denied" when key already exist ---------------------------------
					Do
						$aTmp = _StrToUnicode("_"&$aCounter)
						$RenameKey = _NtRenameKey2($handle2,_HexToUnicode($FixedChars)&$aTmp)
						$aCounter += 1
						If $RenameKey = 0 Then
							ConsoleWrite("The key was renamed to: " & _HexToString($FixedChars&_RemoveUnicode($aTmp)) & @CRLF)
							ExitLoop
						EndIf
						If $aCounter > 5 Then ExitLoop ; Prevent infinit loop ??
					Until Hex($RenameKey,8) <> "C0000121" ; Access denied usually due to key name already existing
					$Name = $FixedChars&_RemoveUnicode($aTmp)
;----------------------------------
#ce
				Else
					ConsoleWrite("The key was renamed to: " & _HexToString($FixedChars) & @CRLF)
					$Name = _HexToUnicode($FixedChars)
					_NtFlushKey($handle2)
				EndIf
			EndIf
			If $cmdline[2] = "-d" Then
				_NtDeleteKey($handle2)
				If not @error Then
					ConsoleWrite("Deleted the invalid key: " & $Name & " (" & _HexToString($FixedChars) & ")" & @CRLF)
					_NtFlushKey($handle2)
				EndIf
			EndIf
		EndIf
		If $cmdline[3] = "-s" Then _CheckSubKeys($startkey&"5C00"&$subkey,$Name)
		$Index += 1
    WEnd
	DllCall($hNTDLL, "int", "NtClose", "hwnd", $handle)
EndFunc

Func _NtRenameKey2($KeyHandle,$NewName)
	Local $szName = DllStructCreate("byte[260]")
	Local $sUS = DllStructCreate("ushort Length;ushort MaximumLength;ptr Buffer")
	DllStructSetData($szName, 1, "0x"&$NewName)
	DllStructSetData($sUS,"Length",StringLen($NewName)/2)
	DllStructSetData($sUS,"MaximumLength",(StringLen($NewName)/2)+2)
	DllStructSetData($sUS,"Buffer",DllStructGetPtr($szName))
	Local $ret = DllCall($hNTDLL, "int", "NtRenameKey", "hwnd", $KeyHandle, "ptr", DllStructGetPtr($sUS))
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtRenameKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,$ret[0])
	Else
		Return $ret[0]
	EndIf
EndFunc

Func _NtFlushKey($KeyHandle)
	Local $ret = DllCall($hNTDLL, "int", "NtFlushKey", "hwnd", $KeyHandle)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtFlushKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,$ret[0])
	EndIf
EndFunc

Func _NtDeleteKey($KeyHandle)
	Local $ret = DllCall($hNTDLL, "int", "NtDeleteKey", "hwnd", $KeyHandle)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtDeleteKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,$ret[0])
	EndIf
EndFunc

Func NT_SUCCESS($status)
    If 0 <= $status And $status <= 0x7FFFFFFF Then
        Return True
    Else
        Return False
    EndIf
EndFunc

Func _FixUnicodeString($Inp)
	Local $InpLen, $Tmp, $Appended, $Counter=0, $Info[2]
	If StringLeft($Inp,2) = "0x" Then $Inp = StringMid($Inp,3)
	$InpLen = StringLen($Inp)
	For $i = 1 To $InpLen Step 4
		$Tmp = StringMid($Inp,$i,2)
;		If Dec($Tmp) = 0 Then
		If Dec($Tmp) < 32 Then; Replace all control characters too
			$Tmp = "2A"
			$Counter+=1
		EndIf
		$Appended &= $Tmp
	Next
	$Info[0] = $Counter
	$Info[1] = $Appended
	Return $Info
EndFunc

Func _RtlNtStatusToDosError($Status)
    Local $aCall = DllCall("ntdll.dll", "ulong", "RtlNtStatusToDosError", "dword", $Status)
    If Not NT_SUCCESS($aCall[0]) Then
        ConsoleWrite("Error in RtlNtStatusToDosError: " & Hex($aCall[0], 8) & @CRLF)
        Return SetError(1, 0, $aCall[0])
    Else
        Return $aCall[0]
    EndIf
EndFunc

Func _TranslateErrorCode($ErrCode)
	Local $tBufferPtr = DllStructCreate("ptr")

	Local $nCount = _FormatMessage(BitOR($__WINAPICONSTANT_FORMAT_MESSAGE_ALLOCATE_BUFFER, $__WINAPICONSTANT_FORMAT_MESSAGE_FROM_SYSTEM), _
			0, $ErrCode, 0, $tBufferPtr, 0, 0)
	If @error Then Return SetError(@error, 0, "")

	Local $sText = ""
	Local $pBuffer = DllStructGetData($tBufferPtr, 1)
	If $pBuffer Then
		If $nCount > 0 Then
			Local $tBuffer = DllStructCreate("wchar[" & ($nCount + 1) & "]", $pBuffer)
			$sText = DllStructGetData($tBuffer, 1)
		EndIf
		_LocalFree($pBuffer)
	EndIf

	Return $sText
EndFunc

Func _FormatMessage($iFlags, $pSource, $iMessageID, $iLanguageID, ByRef $pBuffer, $iSize, $vArguments)
	Local $sBufferType = "struct*"
	If IsString($pBuffer) Then $sBufferType = "wstr"
	Local $aResult = DllCall("Kernel32.dll", "dword", "FormatMessageW", "dword", $iFlags, "ptr", $pSource, "dword", $iMessageID, "dword", $iLanguageID, _
			$sBufferType, $pBuffer, "dword", $iSize, "ptr", $vArguments)
	If @error Then Return SetError(@error, @extended, 0)
	If $sBufferType = "wstr" Then $pBuffer = $aResult[5]
	Return $aResult[0]
EndFunc

Func _LocalFree($hMem)
	Local $aResult = DllCall("kernel32.dll", "handle", "LocalFree", "handle", $hMem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc

Func _StrToUnicode($Inp)
	Local $InpLen, $Tmp, $Appended
	$InpLen = StringLen($Inp)
	For $i = 1 To $InpLen
		$Tmp = _StringToHex(StringMid($Inp,$i,1))
		$Appended &= $Tmp&"00"
	Next
	Return $Appended
EndFunc

Func _HexToUnicode($Inp)
	Local $InpLen, $Tmp, $Appended
	$InpLen = StringLen($Inp)
	For $i = 1 To $InpLen Step 2
		$Tmp = StringMid($Inp,$i,2)
		$Appended &= $Tmp&"00"
	Next
	Return $Appended
EndFunc

Func _RemoveUnicode($Inp)
	Local $InpLen, $Tmp, $Appended
	If StringLeft($Inp,2) = "0x" Then $Inp = StringMid($Inp,3)
	$InpLen = StringLen($Inp)
	For $i = 1 To $InpLen Step 4
		$Tmp = StringMid($Inp,$i,2)
		$Appended &= $Tmp
	Next
	Return $Appended
EndFunc

Func _End($begin)
	Local $timerdiff = TimerDiff($begin)
	$timerdiff = Round(($timerdiff / 1000), 2)
	ConsoleWrite("Job took " & $timerdiff & " seconds" & @CRLF)
;	Exit
EndFunc

Func _HighPrecisionSleep($iMicroSeconds,$hDll=False)
    Local $hStruct, $bLoaded
    If Not $hDll Then
        $hDll=DllOpen("ntdll.dll")
        $bLoaded=True
    EndIf
    $hStruct=DllStructCreate("int64 time;")
    DllStructSetData($hStruct,"time",-1*($iMicroSeconds*1))
    DllCall($hDll,"dword","NtDelayExecution","int",0,"ptr",DllStructGetPtr($hStruct))
    If $bLoaded Then DllClose($hDll)
EndFunc

Func _HighPrecisionSleepUnsafe($iMicroSeconds,$hDll)
    _HighPrecisionSleepRawUnsafe( -1*($iMicroSeconds*10), $hDll )
EndFunc

Func _HighPrecisionSleepRawUnsafe($iMicroSecondsRaw, $hDll)
    $hStruct=DllStructCreate("int64 time;")
    DllStructSetData($hStruct,"time",$iMicroSecondsRaw)
    DllCall($hDll,"dword","ZwDelayExecution","int",0,"ptr",DllStructGetPtr($hStruct))
EndFunc