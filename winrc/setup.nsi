# The NSIS (http://nsis.sourceforge.net) install script.
# This script is BSD licensed.
SetCompressor /solid /final lzma

!include LogicLib.nsh
!include MUI2.nsh
!include WinMessages.nsh

!define VERSION "0.0.0"
!define QUADVERSION "0.0.0.0"

outFile "dnssec_trigger_setup_${VERSION}.exe"
Name "DnssecTrigger"

# default install directory
installDir "$PROGRAMFILES\DnssecTrigger"
installDirRegKey HKLM "Software\DnssecTrigger" "InstallLocation"
RequestExecutionLevel admin
#give credits to Nullsoft: BrandingText ""
VIAddVersionKey "ProductName" "Dnssec Trigger"
VIAddVersionKey "CompanyName" "NLnet Labs"
VIAddVersionKey "FileDescription" "(un)install dnssec-trigger"
VIAddVersionKey "LegalCopyright" "Copyright 2011, NLnet Labs"
VIAddVersionKey "FileVersion" "${QUADVERSION}"
VIAddVersionKey "ProductVersion" "${QUADVERSION}"
VIProductVersion "${QUADVERSION}"

; typedef struct _RECT {
;   LONG left;
;   LONG top;
;   LONG right;
;   LONG bottom;
; } RECT, *PRECT;
!define stRECT "(i, i, i, i) i"

# http://nsis.sourceforge.net/Refresh_SysTray
Function un.RefreshSysTray
	; $0: SysTray Window Handle
	FindWindow $0 "Shell_TrayWnd" ""
	FindWindow $0 "TrayNotifyWnd" "" $0
	FindWindow $0 "SysPager" "" $0
	FindWindow $0 "ToolbarWindow32" "" $0
 
	; Create RECT struct
	System::Call "*${stRECT} .r1"
	; Get windows information
	System::Call "User32::GetWindowRect(i, i) i (i r0, r1) .r2"
	; Get left/top/right/bottom coords
	; $2: Left, $3: Top, $4: Right, $5: Bottom
	System::Call "*$1${stRECT} (.r2, .r3, .r4, .r5)"
	System::Free $1
 
	; $2: Width
	IntOp $2 $4 - $2
	; $3: Height
	IntOp $3 $5 - $3
 
	; $4: Small Icon Width
	System::Call 'User32::GetSystemMetrics(i 49) i .r4'
	; $5: Small Icon Height
	System::Call 'User32::GetSystemMetrics(i 50) i .r5'
 
	; $7: y - Start at the bottom
	IntOp $7 $4 / 2
	IntOp $7 $3 - $7
	LoopY:
		; $6: X - Start at the right
		IntOp $6 $5 / 2
		IntOp $6 $2 - $6
		LoopX:
			SendMessage $0 ${WM_MOUSEMOVE} 0 "$6 | $7"
			IntOp $6 $6 - $4
			IntCmp $6 0 EndLoopX EndLoopX LoopX
		EndLoopX:
		IntOp $7 $7 - $5
		IntCmp $7 0 EndLoopY EndLoopY LoopY
	EndLoopY:
FunctionEnd

# Find and kill a process
Function FindAndStopPanel
    System::Alloc 1024
    Pop $R9
    System::Call "Psapi::EnumProcesses(i R9, i 1024, *i .R1)i .R8"
    StrCmp $R8 0 HandleError
 
    IntOp $R2 $R1 / 4 ; Divide by sizeof(DWORD) to get number of processes
 
    StrCpy $R4 0 ; R4 is our counter variable
iterate:
    System::Call "*$R9(i .R5)" ; Get next PID
    IntCmp $R5 0 next_iteration iterate_end 0 ; break if PID < 0, continue if PID = 0
 
    System::Call "Kernel32::OpenProcess(i 1040, i 0, i R5)i .R8"
    StrCmp $R8 0 next_iteration
    System::Alloc 1024
    Pop $R6
    System::Call "Psapi::EnumProcessModules(i R8, i R6, i 1024, *i .R1)i .R7"
    StrCmp $R7 0 0 no_enumproc_error
    System::Free $R6
    GoTo next_iteration
no_enumproc_error:
    System::Alloc 256
    Pop $R7
    System::Call "*$R6(i .r6)" ; Get next module
    System::Free $R6
    System::Call "Psapi::GetModuleBaseName(i R8, i r6, t .R7, i 256)i .r6"
    StrCmp $6 0 0 no_getmod_error
    System::Free $R7
    GoTo HandleError
no_getmod_error:
    MessageBox MB_OK "Found process called $R7 with length $6!"
    System::Free $R7
 
next_iteration:
    IntOp $R4 $R4 + 1 ; Add 1 to our counter
    IntOp $R9 $R9 + 4 ; Add sizeof(int) to our buffer address
 
    IntCmp $R4 $R2 iterate_end iterate iterate_end
iterate_end:
    MessageBox MB_OK "Success!"
    System::Free $R9
    Return
HandleError:
    MessageBox MB_OK "Something went wrong here."
    Return
FunctionEnd
 
# Global Variables
Var StartMenuFolder

# use ReserveFile for files required before actual installation
# makes the installer start faster
#ReserveFile "System.dll"
#ReserveFile "NsExec.dll"

!define MUI_ICON "install.ico"
!define MUI_UNICON "uninstall.ico"

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "setup_top.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "setup_left.bmp"
!define MUI_ABORTWARNING
#!define MUI_FINISHPAGE_NOAUTOCLOSE  # so we can inspect install log.

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY

!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\DnssecTrigger"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "DnssecTrigger"
!insertmacro MUI_PAGE_STARTMENU DnssecTriggerStartMenu $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the uninstallation of Dnssec Trigger.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English" 

# default section, one per component, we have one component.
section "DnssecTrigger" SectionDnssecTrigger
	SectionIn RO  # cannot unselect this one
	# real work in postinstall
sectionEnd

section "-hidden.postinstall"
	# copy files
	setOutPath $INSTDIR
	Call FindAndStopPanel
	File "..\LICENSE"
	File "..\README"
	File "..\dnssec-triggerd.exe"
	File "..\dnssec-trigger-panel.exe"
	File "..\dnssec-trigger-control.exe"
	File "..\dnssec-trigger-keygen.exe"
	File "/oname=dnssec-trigger.conf" "..\example.conf"
	File "..\panel\pui.xml"
	File "..\panel\status-icon.png"
	File "..\panel\status-icon-alert.png"
	File "..\winrc\gtkrc"
	File "..\tmp.collect\*.dll"

	# store installation folder
	WriteRegStr HKLM "Software\DnssecTrigger" "InstallLocation" "$INSTDIR"
	WriteRegStr HKLM "Software\DnssecTrigger" "ConfigFile" "$INSTDIR\dnssec-trigger.conf"
	WriteRegStr HKLM "Software\DnssecTrigger" "Gtkrc" "$INSTDIR\gtkrc"
	# no cron action at this time.
	WriteRegStr HKLM "Software\DnssecTrigger" "CronAction" ""
	WriteRegDWORD HKLM "Software\DnssecTrigger" "CronTime" 86400

	# uninstaller
	WriteUninstaller "uninst.exe"

	# register uninstaller
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "DisplayName" "DnssecTrigger"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "UninstallString" "$\"$INSTDIR\uninst.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "QuietUninstallString" "$\"$INSTDIR\uninst.exe$\" /S"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "NoRepair" "1"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "URLInfoAbout" "http://unbound.net"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "Publisher" "NLnet Labs"

	# write key locations to file
	ClearErrors
	FileOpen $R1 "$INSTDIR\dnssec-trigger.conf" a
	IfErrors done_keys
	FileSeek $R1 0 END
	FileWrite $R1 "$\n"
	FileWrite $R1 "server-key-file: $\"$INSTDIR\dnssec_trigger_server.key$\"$\n"
	FileWrite $R1 "server-cert-file: $\"$INSTDIR\dnssec_trigger_server.pem$\"$\n"
	FileWrite $R1 "control-key-file: $\"$INSTDIR\dnssec_trigger_control.key$\"$\n"
	FileWrite $R1 "control-cert-file: $\"$INSTDIR\dnssec_trigger_control.pem$\"$\n"
	FileWrite $R1 "$\n"
	FileClose $R1
done_keys:
	
	# generate keys
	nsExec::ExecToLog '"$INSTDIR\dnssec-trigger-keygen.exe" -d "$INSTDIR"'

	# start menu items
	!insertmacro MUI_STARTMENU_WRITE_BEGIN DnssecTriggerStartMenu
	CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" "" "" "" "Uninstall dnssec trigger"
	!insertmacro MUI_STARTMENU_WRITE_END

	# install service entry
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w install'
	# start service
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w start'

	# register tray icon 
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "DnssecTrigger" "$INSTDIR\dnssec-trigger-panel.exe"
	# start tray icon

sectionEnd

# set section descriptions
LangString DESC_dnssectrigger ${LANG_ENGLISH} "The dnssec trigger package. $\r$\n$\r$\nStarts a service and a tray icon, logs to the Application Log, and the config file is its Program Files folder."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SectionDnssecTrigger} $(DESC_dnssectrigger)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

# setup macros for uninstall functions.
!ifdef UN
!undef UN
!endif
!define UN "un."

# uninstaller section
section "un.DnssecTrigger"
	# stop tray icon 
	# remove tray icon
	DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "DnssecTrigger"
	# stop service
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w stop'
	# uninstall service entry
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w remove'

	# remove tray icon if panel killed too fast to remove it itself.
	Call un.RefreshSysTray

	# deregister uninstall
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger"
	Delete "$INSTDIR\uninst.exe"   # delete self
	Delete "$INSTDIR\LICENSE"
	Delete "$INSTDIR\README"
	Delete "$INSTDIR\dnssec-triggerd.exe"
	Delete "$INSTDIR\dnssec-trigger-panel.exe"
	Delete "$INSTDIR\dnssec-trigger-control.exe"
	Delete "$INSTDIR\dnssec-trigger-keygen.exe"
	Delete "$INSTDIR\dnssec-trigger.conf"
	Delete "$INSTDIR\pui.xml"
	Delete "$INSTDIR\status-icon.png"
	Delete "$INSTDIR\status-icon-alert.png"
	Delete "$INSTDIR\gtkrc"
	Delete "$INSTDIR\*.dll"
	RMDir "$INSTDIR"

	# start menu items
	!insertmacro MUI_STARTMENU_GETFOLDER DnssecTriggerStartMenu $StartMenuFolder
	Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
	RMDir "$SMPROGRAMS\$StartMenuFolder"

	DeleteRegKey HKLM "Software\DnssecTrigger"
sectionEnd
