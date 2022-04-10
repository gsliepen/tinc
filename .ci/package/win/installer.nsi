!include "MUI.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\COPYING"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Name "tinc"
OutFile "tinc-x64.exe"
InstallDir "$PROGRAMFILES64\tinc"
ShowInstDetails show
RequestExecutionLevel admin

Section "Tinc"
  SetOutPath $INSTDIR

  File ..\..\..\default\src\tinc.exe
  File ..\..\..\default\src\tincd.exe
  File ..\..\..\wintap.exe

  CreateDirectory "$SMPROGRAMS\Tinc"
  CreateShortCut "$SMPROGRAMS\Tinc.lnk" "$INSTDIR\tinc.exe"

  ExecWait "wintap.exe"

  CreateDirectory "$SMPROGRAMS\tinc"
SectionEnd
