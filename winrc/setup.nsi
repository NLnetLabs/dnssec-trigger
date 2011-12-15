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
!macro RefreshSysTray
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
!macroend

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
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "setup_left_un.bmp"
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
	# check if unbound installed (but not via dnssec-trigger)
	ReadRegStr $R1 HKLM "Software\Unbound" "InstallLocation"
	StrCmp $R1 "" doinstall 0
	ReadRegStr $R1 HKLM "Software\Unbound" "DnssecTrigger"
	StrCmp $R1 "yes" doinstall 0
	# unbound installed but not ours, fail
	Abort "Unbound is already installed, please uninstall it"
	doinstall:

	# must stop dnssec-triggerd, panel and unbound to update their exe
	# (if installed).
	ReadRegStr $R1 HKLM "Software\Unbound" "InstallLocation"
	StrCmp $R1 "" donestop 0
	DetailPrint "Stop tray icons"
	nsExec::ExecToLog '"$R1\dnssec-trigger-control.exe" stoppanels'
	DetailPrint "Stop dnssec-trigger daemon"
	nsExec::ExecToLog '"$R1\dnssec-triggerd.exe" -w stop'
	DetailPrint "Stop unbound daemon"
	nsExec::ExecToLog '"$R1\unbound.exe" -w stop'
	Sleep 2000
	!insertmacro RefreshSysTray
	donestop:

	# copy files
	setOutPath $INSTDIR
	File "..\LICENSE"
	File "..\tmp.collect\README.txt"
	File "..\dnssec-triggerd.exe"
	File "..\dnssec-trigger-panel.exe"
	File "..\dnssec-trigger-control.exe"
	File "..\dnssec-trigger-keygen.exe"
	File "..\tmp.collect\unbound.exe"
	File "..\tmp.collect\unbound-control.exe"
	File "..\tmp.collect\unbound-anchor.exe"
	File "..\tmp.collect\unbound-host.exe"
	File "..\tmp.collect\unbound-checkconf.exe"
	File "..\tmp.collect\unbound.conf"
	File "..\winrc\alert.ico"
	File "..\winrc\status.ico"
	File "..\tmp.collect\*.dll"
	File "/oname=dnssec-trigger.conf" "..\example.conf"

	# store installation folder
	WriteRegStr HKLM "Software\DnssecTrigger" "InstallLocation" "$INSTDIR"
	WriteRegStr HKLM "Software\DnssecTrigger" "ConfigFile" "$INSTDIR\dnssec-trigger.conf"
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
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "URLInfoAbout" "http://nlnetlabs.nl"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger" "Publisher" "NLnet Labs"

	DetailPrint "Setup config files"
	# setup unbound registry entries
	WriteRegStr HKLM "Software\Unbound" "InstallLocation" "$INSTDIR"
	WriteRegStr HKLM "Software\Unbound" "ConfigFile" "$INSTDIR\unbound.conf"
	WriteRegStr HKLM "Software\Unbound" "CronAction" ""
	# setup that unbound is 'ours'
	WriteRegStr HKLM "Software\Unbound" "DnssecTrigger" "yes"
	WriteRegDWORD HKLM "Software\Unbound" "CronTime" 86400
	# setup unbound.conf 
	ClearErrors
	FileOpen $R1 "$INSTDIR\unbound.conf" a
	IfErrors done_rk
	FileSeek $R1 0 END
	FileWrite $R1 "$\n$\nserver: auto-trust-anchor-file: $\"$INSTDIR\root.key$\"$\n"
	FileWrite $R1 "remote-control: control-enable: yes$\n"
	FileWrite $R1 "  server-key-file: $\"$INSTDIR\unbound_server.key$\"$\n"
	FileWrite $R1 "  server-cert-file: $\"$INSTDIR\unbound_server.pem$\"$\n"
	FileWrite $R1 "  control-key-file: $\"$INSTDIR\unbound_control.key$\"$\n"
	FileWrite $R1 "  control-cert-file: $\"$INSTDIR\unbound_control.pem$\"$\n"
	FileWrite $R1 "$\n"
	FileClose $R1
	done_rk:
	WriteRegStr HKLM "Software\Unbound" "RootAnchor" "$\"$INSTDIR\unbound-anchor.exe$\" -a $\"$INSTDIR\root.key$\" -c $\"$INSTDIR\icannbundle.pem$\""

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

	DetailPrint "Setup keys"
	# generate keys
	nsExec::ExecToLog '"$INSTDIR\dnssec-trigger-keygen.exe" -d "$INSTDIR"'
	# generate unbound keys
	nsExec::ExecToLog '"$INSTDIR\dnssec-trigger-keygen.exe" -u -d "$INSTDIR"'

	# start menu items
	!insertmacro MUI_STARTMENU_WRITE_BEGIN DnssecTriggerStartMenu
	CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" "" "" "" "Uninstall dnssec trigger"
	!insertmacro MUI_STARTMENU_WRITE_END

	# install unbound service entry
	DetailPrint "Start unbound daemon"
	nsExec::ExecToLog '"$INSTDIR\unbound.exe" -w install'
	nsExec::ExecToLog '"$INSTDIR\unbound.exe" -w start'

	# install service entry
	DetailPrint "Start dnssec-trigger daemon"
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w install'
	# start service
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w start'

	# register tray icon 
	DetailPrint "Start tray icon"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "DnssecTrigger" '"$INSTDIR\dnssec-trigger-panel.exe"'
	# start tray icon
	Exec '"$INSTDIR\dnssec-trigger-panel.exe"'
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
	# remove tray icon from startup list
	DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "DnssecTrigger"
	# stop tray icon
	DetailPrint "Remove tray icons"
	nsExec::ExecToLog '"$INSTDIR\dnssec-trigger-control.exe" stoppanels'
	# stop service
	DetailPrint "Remove dnssec-trigger daemon"
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w stop'
	# uninstall service entry
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -w remove'

	# stop unbound service
	DetailPrint "Remove unbound daemon"
	nsExec::ExecToLog '"$INSTDIR\unbound.exe" -w stop'
	nsExec::ExecToLog '"$INSTDIR\unbound.exe" -w remove'

	# remove DNS override entries from registry
	nsExec::ExecToLog '"$INSTDIR\dnssec-triggerd.exe" -u'

	# give the panel time to process the messages.
	Sleep 2000

	# remove tray icon if panel killed too fast to remove it itself.
	!insertmacro RefreshSysTray

	# give the panel time to process the messages.
	Sleep 1000

	# deregister uninstall
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DnssecTrigger"
	Delete "$INSTDIR\uninst.exe"   # delete self
	Delete "$INSTDIR\LICENSE"
	Delete "$INSTDIR\README.txt"
	Delete "$INSTDIR\dnssec-triggerd.exe"
	Delete "$INSTDIR\dnssec-trigger-panel.exe"
	Delete "$INSTDIR\dnssec-trigger-control.exe"
	Delete "$INSTDIR\dnssec-trigger-keygen.exe"
	Delete "$INSTDIR\unbound.exe"
	Delete "$INSTDIR\unbound-control.exe"
	Delete "$INSTDIR\unbound-anchor.exe"
	Delete "$INSTDIR\unbound-host.exe"
	Delete "$INSTDIR\unbound-checkconf.exe"
	Delete "$INSTDIR\unbound.conf"
	Delete "$INSTDIR\alert.ico"
	Delete "$INSTDIR\status.ico"
	Delete "$INSTDIR\*.dll"
	Delete "$INSTDIR\dnssec-trigger.conf"
	RMDir "$INSTDIR"

	# start menu items
	!insertmacro MUI_STARTMENU_GETFOLDER DnssecTriggerStartMenu $StartMenuFolder
	Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
	RMDir "$SMPROGRAMS\$StartMenuFolder"

	DeleteRegKey HKLM "Software\Unbound"
	DeleteRegKey HKLM "Software\DnssecTrigger"
sectionEnd
