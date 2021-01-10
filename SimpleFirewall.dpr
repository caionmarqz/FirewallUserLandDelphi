program SimpleFirewall;

uses
  SysUtils,
  Windows,
  TlHelp32;

const MODULE = 'Hook.dll';

function GetCurPath:String;
var
  mb: array[0..250-1] of Char;
begin
  GetModuleFileName(0, mb, sizeof(mb));
  result := ExtractFilePath(mb);
end;

function GetProcessId(const szProcName: PChar):Cardinal;
var
  hSnapShot: THandle;
  PeFormat32: TProcessEntry32;
begin
  result := 0;

  PeFormat32.dwSize := sizeof(ProcessEntry32);

  hSnapShot := CreateToolHelp32SnapShot(TH32CS_SNAPPROCESS, 0);
  if hSnapShot <> 0 then
  begin
    if Process32First(hSnapShot, PeFormat32) <> false then
    begin
      while Process32Next(hSnapShot, PeFormat32) <> false do
      begin
        if lstrcmpi(PeFormat32.szExeFile, szProcName) = 0 then
        begin
          result := PeFormat32.th32ProcessID;
          break;
        end;
      end;
    end;
    CloseHandle(hSnapShot);
  end;
end;

function IsDllInProcLoaded(const hProc: Cardinal; szMod: PChar):Boolean;
var
  hSnap: Cardinal;
  te: TModuleEntry32;
begin
  result := false;

  te.dwSize := sizeof(TModuleEntry32);

  hSnap := CreateToolHelp32SnapShot(TH32CS_SNAPMODULE, hProc);
  if hSnap <> 0 then
  begin
    if Module32First(hSnap, te) = true then
    begin
      while Module32Next(hSnap, te) = true do
      begin
        if lstrcmpi(szMod, te.szModule) = 0 then
        begin
          result := true;
          break;
        end;
      end;
    end;
    CloseHandle(hSnap);
  end;
end;

function InjectLibrary(lpProcessID: Cardinal; lpDllname: String):LongBool;
var
  hProc: Cardinal;
  oAlloc: Pointer;
  cWPM: Cardinal;
  hRemThread: Cardinal;
begin
  result := false;
  SetLastError(ERROR_SUCCESS);
  hProc := OpenProcess(PROCESS_ALL_ACCESS, false, lpProcessID);
  if hProc <> 0 then
  begin
    oAlloc := VirtualAllocEx(hProc, nil, length(lpDllname), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if oAlloc <> nil then
    begin
      if WriteProcessMemory(hProc, oAlloc, PChar(lpDllName), length(lpDllName), cWPM) = true then
      begin
        CreateRemoteThread(hProc, nil, 0, GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'), oAlloc, 0, hRemThread);
        if GetLastError = ERROR_SUCCESS then
        begin
          result := true;
        end;
      end;
    end;
  end;
  CloseHandle(hProc);
end;

var
  Snap: Cardinal;
  tp: TProcessEntry32;
  s: String;
begin

  MessageBoxA(0, 'começando os trabalhos!', 'firewall', 0);

  while true do
  begin
    Snap := CreateToolHelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if Snap <> 0 then
    begin
      tp.dwSize := Sizeof(TProcessEntry32);
      if Process32First(Snap, tp) = true then
      begin
        while Process32Next(Snap, tp) = true do
        begin
          s := tp.szExeFile;
          if Copy(s, length(s)-3, 4) <> '.exe' then continue;
          if IsDllInProcLoaded(tp.th32ProcessID, MODULE) = false then
          begin
            InjectLibrary(tp.th32ProcessID, Format('%s\%s', [GetCurPath(), MODULE]));
          end;
        end;
      end;
      CloseHandle(Snap);
    end;

    Sleep(1000);
  end;
end.
