library Hook;

uses
  SysUtils,
  Windows,
  Winsock,
  Classes;

{$R *.res}

var o_connect: function(s: Integer; const name: sockaddr_in; namelen: Integer):Integer;stdcall;
var dwThreadID: Cardinal = 0;

function RunningApp:String;
var
  mb: array[0..250-1] of Char;
begin
  GetModuleFileName(0, mb, sizeof(mb));
  result := mb;
end;

function GetMySelf:String;
var
  mb: array[0..250-1] of Char;
begin
  GetModuleFileName(0, mb, sizeof(mb));
  result := ExtractFilePath(mb);
end;

function DetourHook(pTargetAddr: Pointer; pNewAddr: Pointer; dwLength: Cardinal; var pCallOrigAddress: Pointer):LongBool;
type
  TJumP = packed record
    bJmp: Byte;
    dwAddress: DWord;
end;
function WriteNops(lpFunctionAddress: Pointer; lpLength:Cardinal):LongBool;
const
  lpNop: Byte = $90;
var
  dwProtect: DWord;
  g: Byte;
  dwBytesWritten: DWord;
begin
  result := false;
  if VirtualProtectEx(GetCurrentProcess, lpFunctionAddress, lpLength, PAGE_READWRITE, dwProtect) then
  begin
    for g := 0 to lpLength do
      result := WriteProcessMemory(GetCurrentProcess, Pointer(DWord(lpFunctionAddress) + g), @lpNop, 1, dwBytesWritten);
    VirtualProtectEx(GetCurrentProcess, lpFunctionAddress, lpLength, dwProtect, dwProtect);
  end;
end;
var
  gOrigJump: TJump;
  gJump: TJump;
  dwProtect: DWord;
begin
  result := false;
  
  pCallOrigAddress := VirtualAlloc(nil, dwLength + 5, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if pCallOrigAddress <> nil then
  begin
    CopyMemory(pCallOrigAddress, pTargetAddr, dwLength);

    gOrigJump.bJmp := $E9;
    gOrigJump.dwAddress := (DWord(pTargetAddr) + dwLength) - DWord(pCallOrigAddress) - (dwLength + 5);
    CopyMemory(Pointer(DWord(pCallOrigAddress) + dwLength), @gOrigJump, dwLength+5);

    if (WriteNops(pTargetAddr, dwLength-1) = true) and (VirtualProtect(pTargetAddr, dwLength, PAGE_EXECUTE_READWRITE, dwProtect) = true) then
	  begin
	    gJump.bJmp := $E9;
	    gJump.dwAddress := DWord(pNewAddr) - DWord(pTargetAddr) - 5;

	    CopyMemory(pTargetAddr, @gJump, sizeof(TJump));

	    result := true;
	  end;
  end;
end;

function n_connect(s: Integer; const name: sockaddr_in; namelen: Integer):Integer;stdcall;
var
  imsg: Cardinal;
begin
  result := 0;
  imsg := MessageBox(0, PChar(Format('Application %s wants to connect to a host, allow it?', [RunningApp()])), 'conhk', MB_ICONINFORMATION or MB_YESNO);
  if imsg = ID_NO then
    result := SOCKET_ERROR
  else if imsg = ID_YES then
    result := o_connect(s, name, namelen);
end;

procedure HookThread;
begin
  while GetModuleHandle('ws2_32.dll') = 0 do
    Sleep(50);

  if DetourHook(GetProcAddress(GetModuleHandle('ws2_32.dll'), 'connect'), @n_connect, 5, @o_connect) = false then
    ExitProcess(0);
end;


procedure DllMain(fdwReason: Cardinal);
begin
  case fdwReason of
    DLL_PROCESS_ATTACH:
    begin
      CreateThread(nil, 0, @HookThread, nil, 0, dwThreadID);
    end;
    DLL_PROCESS_DETACH:
    begin
      TerminateThread(dwThreadID, 0);
    end;
  end;
end;

begin
  DllProc := @DllMain;
  DllMain(DLL_PROCESS_ATTACH);
end.
