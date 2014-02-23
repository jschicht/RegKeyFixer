#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Res_Comment=PoC to creating very tricky and invalid registry keys
#AutoIt3Wrapper_Res_Description=PoC to creating very tricky and invalid registry keys
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
; Sample by Joakim Schicht
Global Const $__WINAPICONSTANT_FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
Global Const $__WINAPICONSTANT_FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
Global Const $tagIOSTATUSBLOCK = "dword Status;ptr Information"
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $KEY_ALL_ACCESS = 0xF003F
Global Const $REG_SZ = 1
Global Const $REG_OPTION_NON_VOLATILE = 0x00000000
Global $hNTDLL = DllOpen("ntdll.dll")
$SubKey = ""
$RootKey = "\Registry\Machine\SOFTWARE\YouBastard!"  ;37
$Tmp = "HiHiHoHoHaHa"

For $i = 1 To 21 ;21 x 12 = 252
	$SubKey &= $Tmp
Next
$SpecialValueName = "Secret Value"

For $i = 0 To 8 Step 2
	$SpecialValueData = "Hidden message " & $i
	$CreateKey = _NtCreateKey($RootKey, $SubKey, $i, $SpecialValueName, $SpecialValueData)
	If @error Then Exit
	_NtFlushKey($CreateKey)
Next

DllCall($hNTDLL, "int", "NtClose", "hwnd", $CreateKey)
DllClose($hNTDLL)
MsgBox(0,"Done","Windows will now have a hard time deleting this key: " & $RootKey)
Exit

Func _NtCreateKey($RootDirectory, $ObjectName, $NullChars, $vName , $vData)
	Local $Disposition, $ret, $KeyHandle
    Local $szName = DllStructCreate("wchar[260]")
	Local $sUS = DllStructCreate($tagUNICODESTRING)
    Local $sOA = DllStructCreate($tagOBJECTATTRIBUTES)
    Local $sISB = DllStructCreate($tagIOSTATUSBLOCK)
    DllStructSetData($szName, 1, $RootDirectory)
    $ret = DllCall($hNTDLL, "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
	DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", 0)
    DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
	$ret = DllCall($hNTDLL, "int", "NtCreateKey", "hwnd*", "", "dword", $KEY_ALL_ACCESS, "ptr", DllStructGetPtr($sOA), "ulong", 0, "ulong", 0, "ulong", $REG_OPTION_NON_VOLATILE, "ulong*", $Disposition)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtCreateKey 1 : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,$ret[0])
	EndIf
;	ConsoleWrite("Disposition: " &  $ret[7] & @CRLF)
	$handle = $ret[1]
	Local $szName = DllStructCreate("wchar[260]")
	Local $sUS = DllStructCreate($tagUNICODESTRING)
    DllStructSetData($szName, 1, $ObjectName)
    $ret = DllCall($hNTDLL, "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
	DllStructSetData($sUS,"Length",DllStructGetData($sUS,"Length")+$NullChars)
	DllStructSetData($sUS,"MaximumLength",DllStructGetData($sUS,"MaximumLength")+$NullChars)
    DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", $handle)
    DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
	$ret = DllCall($hNTDLL, "int", "NtCreateKey", "hwnd*", "", "dword", $KEY_ALL_ACCESS, "ptr", DllStructGetPtr($sOA), "ulong", 0, "ulong", 0, "ulong", $REG_OPTION_NON_VOLATILE, "ulong*", $Disposition)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtCreateKey 2 : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return SetError(1,0,$ret[0])
	EndIf
;	ConsoleWrite("Disposition: " &  $ret[7] & @CRLF)
	If $ret[7] = 1 Then ConsoleWrite("Success creating new key" & @CRLF)
	If $ret[7] = 2 Then ConsoleWrite("Key already exist" & @CRLF)
	$handle = $ret[1]
	If $vName <> "" Then
		DllStructSetData($szName, 1, $vName)
		$ret = DllCall($hNTDLL, "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
		$ValueData = DllStructCreate("wchar["&StringLen($vData)&"]")
		DllStructSetData($ValueData,1,$vData)
		Local $ret = DllCall($hNTDLL, "int", "NtSetValueKey", "hwnd", $handle, "ptr", DllStructGetPtr($sUS), "ulong", 0, "ulong", $REG_SZ, "ptr", DllStructGetPtr($ValueData), "ulong", DllStructGetSize($ValueData))
		If Not NT_SUCCESS($ret[0]) Then
			ConsoleWrite("Error in NtSetValueKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
			Return SetError(1,0,$ret[0])
		EndIf
	EndIf
	Return $handle
EndFunc

Func _NtFlushKey($KeyHandle)
	Local $ret = DllCall($hNTDLL, "int", "NtFlushKey", "hwnd", $KeyHandle)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("Error in NtFlushKey : 0x"&Hex($ret[0],8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
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

