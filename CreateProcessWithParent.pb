Import"Kernel32.lib":InitializeProcThreadAttributeList(*AttributeList,dwAttributeCount.l,dwFlags.l,*lpSize):EndImport
Import"Kernel32.lib":UpdateProcThreadAttribute(*lpAttributeList,dwFlags.l,*Attribute,*lpValue,cbSize.l,*lpPreviousValue,*lpReturnSize):EndImport

Procedure.b CreateProcessWithParent(ParentPId,lpCommandLine$)
  Structure STARTUPINFOEX : StartupInfo.STARTUPINFO : *lpAttributeList : EndStructure
  #EXTENDED_STARTUPINFO_PRESENT=$80000:#PROC_THREAD_ATTRIBUTE_PARENT_PROCESS=$20000
  Protected SIE.STARTUPINFOEX,PINFO.PROCESS_INFORMATION,LastR,hProcess,bSize
  CompilerIf #PB_Compiler_32Bit:#USIZE=4:CompilerElse:#USIZE=8:CompilerEndIf
  SIE\StartupInfo\cb=SizeOf(STARTUPINFOEX)
  hProcess=OpenProcess_(#PROCESS_CREATE_PROCESS,#False,ParentPId)
  If hProcess : LastR=InitializeProcThreadAttributeList(#Null,1,0,@bSize)
    If bSize And Not LastR:SIE\lpAttributeList = AllocateMemory(bSize)
      LastR=InitializeProcThreadAttributeList(SIE\lpAttributeList,1,0,@bSize)
      If LastR:LastR=UpdateProcThreadAttribute(SIE\lpAttributeList,0,#PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,@hProcess,#USIZE,0,0)
        If LastR:LastR=CreateProcess_(#Null,@lpCommandLine$,#Null,#Null,#False,#EXTENDED_STARTUPINFO_PRESENT,#Null,#Null,@SIE,@PINFO):EndIf
      EndIf
    Else : ProcedureReturn 0 : EndIf : CloseHandle_(hProcess)
  Else : ProcedureReturn 0 : EndIf : ProcedureReturn Bool(LastR<>0)
EndProcedure

;Debug EnableProcPrivilege("SeDebugName")
Debug CreateProcessWithParent(14552,"notepad.exe"); In this example, PID 14552 is Purebasic.exe.  There are a number of ways
                                                  ; to find the PID of a process, I'll leave that up to you.
