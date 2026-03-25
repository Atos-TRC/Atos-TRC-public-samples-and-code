@echo off
setlocal

REM --- Adjust VS_PATH to your Visual Studio / Build Tools installation ---
set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community
if not defined VSINSTALLDIR (
    echo [*] Initializing VS build environment...
    call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
    if errorlevel 1 (
        echo [-] Failed to init VS environment. Check VS_PATH.
        exit /b 1
    )
)

set WDK=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.26100.0
set WDK_INC=%WDK%\Include\%WDK_VER%
set WDK_LIB=%WDK%\Lib\%WDK_VER%

set CFLAGS=/nologo /W4 /WX /Zi /Od /D _AMD64_ /D AMD64 /D _WIN64 /kernel /GS- ^
    /I"%WDK_INC%\km" /I"%WDK_INC%\shared" /I"%WDK_INC%\km\crt"

set LFLAGS=/nologo /subsystem:native /driver /entry:DriverEntry ^
    /DEBUG /OUT:nulldev.sys ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    ntoskrnl.lib hal.lib

echo [*] Compiling...
cl.exe %CFLAGS% /c nulldev.c
if errorlevel 1 goto :fail

echo [*] Linking...
link.exe %LFLAGS% nulldev.obj
if errorlevel 1 goto :fail

echo [+] Built nulldev.sys successfully.
goto :done

:fail
echo [-] Build failed.
exit /b 1

:done
endlocal
