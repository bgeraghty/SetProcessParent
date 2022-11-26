Import"Kernel32.lib":InitializeProcThreadAttributeList(*AttributeList,dwAttributeCount.l,dwFlags.l,*lpSize):EndImport
Import"Kernel32.lib":UpdateProcThreadAttribute(*lpAttributeList,dwFlags.l,*Attribute,*lpValue,cbSize.l,*lpPreviousValue,*lpReturnSize):EndImport

#EXTENDED_STARTUPINFO_PRESENT         = $80000
#PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = $20000

Structure STARTUPINFOEX
  StartupInfo.STARTUPINFO
  *lpAttributeList
EndStructure

Procedure.s FormatError(N=0)
  If N=0:N=GetLastError_():EndIf 
  Protected E.s="Code "+Str(N)+" [0x"+RSet(Hex(N),5,"0")+"] ",
            *B,L=FormatMessage_(#FORMAT_MESSAGE_ALLOCATE_BUFFER|
                                #FORMAT_MESSAGE_FROM_SYSTEM,
                                0,N,0,@*B,0,0)
  If L:E+PeekS(*B,L-2):LocalFree_(*B):EndIf
  ProcedureReturn(E)
EndProcedure

Procedure.b EnableProcPrivilege(PrivilegeName$,hProcess=#Null)
  If hProcess=#Null : hProcess = GetCurrentProcess_() : EndIf 
  Protected TP.TOKEN_PRIVILEGES,TPOut.TOKEN_PRIVILEGES,hToken,lpLUID.LUID,ReturnLength,Result=#False
  If OpenProcessToken_(hProcess,#TOKEN_ALL_ACCESS,@hToken)
    If LookupPrivilegeValue_(#Null,PrivilegeName$,@lpLUID):TP\PrivilegeCount=1 
      TP\Privileges[0]\Luid\LowPart=lpLUID\LowPart
      TP\PRivileges[0]\Luid\HighPart=lpLUID\HighPart
      TP\Privileges[0]\Attributes=#SE_PRIVILEGE_ENABLED
      Result=AdjustTokenPrivileges_(hToken,#False,@TP,SizeOf(TOKEN_PRIVILEGES),@TPOut,@ReturnLength)
    EndIf:CloseHandle_(hToken)
  EndIf:CloseHandle_(hProcess)
  ProcedureReturn Bool(Result=#ERROR_SUCCESS)
EndProcedure

Procedure.b CreateProcessWithParent(ParentPId,lpCommandLine$)
  Protected SIE.STARTUPINFOEX,PINFO.PROCESS_INFORMATION,T=0,R,hProcess,bSize
  CompilerIf #PB_Compiler_32Bit:#USIZE=4:CompilerElse:#USIZE=8:CompilerEndIf
  SIE\StartupInfo\cb=SizeOf(STARTUPINFOEX)
  hProcess=OpenProcess_(#PROCESS_CREATE_PROCESS,#False,ParentPId)
  If hProcess : R=InitializeProcThreadAttributeList(#Null,1,0,@bSize)
    If bSize And Not R:SIE\lpAttributeList = AllocateMemory(bSize)
      R=InitializeProcThreadAttributeList(SIE\lpAttributeList,1,0,@bSize)
      If R:R=UpdateProcThreadAttribute(SIE\lpAttributeList,0,#PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,@hProcess,#USIZE,0,0)
        If R:R=CreateProcess_(#Null,@lpCommandLine$,#Null,#Null,#False,#EXTENDED_STARTUPINFO_PRESENT,#Null,#Null,@SIE,@PINFO):EndIf
      EndIf
    Else : ProcedureReturn 0 : EndIf : CloseHandle_(hProcess)
  Else : ProcedureReturn 0 : EndIf : ProcedureReturn Bool(R<>0)
EndProcedure

;Debug EnableProcPrivilege("SeDebugName")
Debug CreateProcessWithParent(14552,"notepad.exe"); In this example, PID 14552 is Purebasic.exe.  There are a number of ways
                                                  ; to find the PID of a process, I'll leave that up to you.
