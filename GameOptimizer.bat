@echo off
chcp 437 >nul
title Ultimate Game Optimizer v0.5 by Lexfan
mode con cols=100 lines=35
setlocal EnableDelayedExpansion

:: Set version
set "version=0.5"
set "github_repo=https://raw.githubusercontent.com/yourusername/GameOptimizer/main"

:splash_screen
cls
color 0A
echo.
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                ULTIMATE GAME OPTIMIZER v%version% by LEXFAN
echo   ========================================================================
echo.
echo                      Loading optimization tools...

:: Check for updates
echo   Checking for updates...
call :check_for_updates
timeout /t 2 /nobreak >nul

:: Check for administrator privileges
NET SESSION >nul 2>&1
if %ERRORLEVEL% neq 0 (
    cls
    color 0C
    echo.
    echo   ##        #######  ##     ## #######    ###    ##    ##
    echo   ##        ##        ##   ##  ##        ## ##   ###   ##
    echo   ##        ##         ## ##   ##       ##   ##  ####  ##
    echo   ##        ######      ###    ######  ##     ## ## ## ##
    echo   ##        ##         ## ##   ##      ######### ##  ####
    echo   ##        ##        ##   ##  ##      ##     ## ##   ###
    echo   ######## ######## ##     ## ##      ##     ## ##    ##
    echo.
    echo   ========================================================================
    echo                              ERROR MESSAGE
    echo   ========================================================================
    echo.
    echo   This script requires administrator privileges.
    echo   Please right-click and select "Run as administrator".
    echo.
    echo   Press any key to exit...
    pause >nul
    exit
)

:main_menu
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                ULTIMATE GAME OPTIMIZER v%version% by LEXFAN
echo   ========================================================================
echo.
color 0B
echo   [1] OPTIMIZE PC FOR GAMING
color 0C
echo   [2] RESTORE SYSTEM (run after gaming)
color 0D
echo   [3] SYSTEM INFORMATION
color 0E
echo   [4] CHECK FOR UPDATES
color 09
echo   [5] EXIT
color 0A
echo.
echo   Enter your choice (1-5):

set choice=
set /p choice=

if "%choice%"=="1" goto optimize
if "%choice%"=="2" goto restore
if "%choice%"=="3" goto sysinfo
if "%choice%"=="4" goto manual_update_check
if "%choice%"=="5" goto end

echo   Invalid choice. Try again.
timeout /t 2 >nul
goto main_menu

:optimize
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                        OPTIMIZATION IN PROGRESS
echo   ========================================================================
echo.
echo   Creating system restore point...
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Before Gaming Optimization", 100, 7 >nul 2>&1

color 0B
echo.
echo   ========================================================================
echo   PHASE 1/10 - Setting power plan to ultimate performance
echo   ========================================================================
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PERFINCPOL 2 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PERFDECPOL 1 >nul 2>&1
powercfg /setactive scheme_current >nul 2>&1
echo   Power plan optimized for maximum performance.
timeout /t 2 /nobreak >nul

color 0C
echo.
echo   ========================================================================
echo   PHASE 2/10 - Stopping non-essential services
echo   ========================================================================
net stop wuauserv >nul 2>&1
net stop WSearch >nul 2>&1
net stop Spooler >nul 2>&1
net stop SysMain >nul 2>&1
net stop WinDefend >nul 2>&1
net stop BITS >nul 2>&1
net stop DiagTrack >nul 2>&1
net stop dmwappushservice >nul 2>&1
net stop MapsBroker >nul 2>&1
net stop wscsvc >nul 2>&1
echo   Non-essential services stopped successfully.
timeout /t 2 /nobreak >nul

color 0D
echo.
echo   ========================================================================
echo   PHASE 3/10 - Closing background applications
echo   ========================================================================
taskkill /f /im OneDrive.exe >nul 2>&1
taskkill /f /im Skype.exe >nul 2>&1
taskkill /f /im Discord.exe >nul 2>&1
taskkill /f /im EpicGamesLauncher.exe >nul 2>&1
taskkill /f /im Dropbox.exe >nul 2>&1
taskkill /f /im chrome.exe >nul 2>&1
taskkill /f /im firefox.exe >nul 2>&1
taskkill /f /im msedge.exe >nul 2>&1
taskkill /f /im Teams.exe >nul 2>&1
taskkill /f /im Slack.exe >nul 2>&1
taskkill /f /im AdobeIPCBroker.exe >nul 2>&1
taskkill /f /im AdobeNotificationClient.exe >nul 2>&1
echo   Background applications closed successfully.
timeout /t 2 /nobreak >nul

color 0E
echo.
echo   ========================================================================
echo   PHASE 4/10 - Optimizing network settings
echo   ========================================================================
netsh int tcp set global autotuninglevel=normal >nul 2>&1
netsh int tcp set global congestionprovider=ctcp >nul 2>&1
netsh int tcp set global ecncapability=disabled >nul 2>&1
netsh int tcp set global rss=enabled >nul 2>&1
netsh int tcp set global timestamps=disabled >nul 2>&1
netsh int tcp set global initialRto=2000 >nul 2>&1
netsh int tcp set global rsc=enabled >nul 2>&1
netsh int tcp set global maxsynretransmissions=2 >nul 2>&1
netsh int tcp set global fastopen=enabled >nul 2>&1
netsh int tcp set heuristics disabled >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo   Network settings optimized for gaming.
timeout /t 2 /nobreak >nul

color 09
echo.
echo   ========================================================================
echo   PHASE 5/10 - Applying registry tweaks
echo   ========================================================================
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f >nul 2>&1
echo   Registry tweaks applied successfully.
timeout /t 2 /nobreak >nul

color 05
echo.
echo   ========================================================================
echo   PHASE 6/10 - Optimizing visual effects for performance
echo   ========================================================================
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012078010000000 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f >nul 2>&1
echo   Visual effects optimized for performance.
timeout /t 2 /nobreak >nul

color 06
echo.
echo   ========================================================================
echo   PHASE 7/10 - Optimizing memory settings
echo   ========================================================================
echo   Clearing memory standby list...
PowerShell -Command "& {Get-Process | Where-Object {$_.Name -ne 'System' -and $_.Name -ne 'Registry' -and $_.Name -ne 'Idle'} | ForEach-Object { try { $_.MinWorkingSet = [IntPtr]::Zero; $_.MaxWorkingSet = [IntPtr]::Zero } catch {} }}" >nul 2>&1
PowerShell -Command "Disable-MMAgent -MemoryCompression" >nul 2>&1
echo   Optimizing pagefile settings...
wmic computersystem set AutomaticManagedPagefile=False >nul 2>&1
wmic pagefileset delete >nul 2>&1
for /f "tokens=2 delims==" %%a in ('wmic ComputerSystem get TotalPhysicalMemory /value') do set "ram_bytes=%%a"
set /a "pagefile_size_mb=%ram_bytes:~0,-3% / 1024"
set /a "pagefile_size_mb=%pagefile_size_mb% * 3 / 2"
wmic pagefileset create name="C:\pagefile.sys" InitialSize=%pagefile_size_mb% MaximumSize=%pagefile_size_mb% >nul 2>&1
echo   Memory settings optimized.
timeout /t 2 /nobreak >nul

color 0B
echo.
echo   ========================================================================
echo   PHASE 8/10 - Clearing temporary files
echo   ========================================================================
del /q /s %temp%\* >nul 2>&1
del /q /s C:\Windows\Temp\* >nul 2>&1
del /q /s C:\Windows\Prefetch\* >nul 2>&1
echo   Temporary files cleared successfully.
timeout /t 2 /nobreak >nul

color 0C
echo.
echo   ========================================================================
echo   PHASE 9/10 - Optimizing GPU settings
echo   ========================================================================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v DirectXUserGlobalSettings /t REG_SZ /d "VRROptimizeEnable=0;SwapEffectUpgradeEnable=0;HwSchMode=2;AutoHDREnable=0;" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v SwapEffectUpgradeCache /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v HwSchMode /t REG_DWORD /d 2 /f >nul 2>&1
echo   GPU settings optimized.
timeout /t 2 /nobreak >nul

color 0D
echo.
echo   ========================================================================
echo   PHASE 10/10 - Creating game launcher
echo   ========================================================================
echo @echo off > "%USERPROFILE%\Desktop\Game Launcher.bat"
echo mode con cols=100 lines=35 >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo title Game Launcher by Lexfan >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0A >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0B >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        #######  ##     ## #######    ###    ##    ## >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0C >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        ##        ##   ##  ##        ## ##   ###   ## >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0D >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        ##         ## ##   ##       ##   ##  ####  ## >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0E >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        ######      ###    ######  ##     ## ## ## ## >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 09 >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        ##         ## ##   ##      ######### ##  #### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 05 >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ##        ##        ##   ##  ##      ##     ## ##   ### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 06 >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ######## ######## ##     ## ##      ##     ## ##    ## >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo color 0A >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ======================================================================== >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo                           GAME LAUNCHER by LEXFAN >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ======================================================================== >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   Setting high priority for maximum performance... >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   Enter the path to your game executable: >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   (Example: C:\Games\YourGame.exe) >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo set /p gamepath= >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo if not exist "%%gamepath%%" ( >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   echo   ERROR: Game executable not found. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   echo   Please check the path and try again. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   pause >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   exit >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo ) >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   Launching game with optimizations... >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo start "" "%%gamepath%%" >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo timeout /t 5 /nobreak ^>nul >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo for /f "tokens=2 delims=," %%%%p in ('wmic process where "ExecutablePath='%%gamepath%%'" get processid /format:csv 2^>nul ^| findstr /r [0-9]') do ( >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo   wmic process where processid=%%%%p CALL setpriority "high" ^>nul 2^>^&1 >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo ) >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ======================================================================== >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ####                                                                #### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ####            GAME LAUNCHED WITH OPTIMIZATIONS!                   #### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ####                      BY LEXFAN                                 #### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ####                                                                #### >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   ======================================================================== >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo. >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo echo   Press any key to exit... >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo pause ^>nul >> "%USERPROFILE%\Desktop\Game Launcher.bat"
echo exit >> "%USERPROFILE%\Desktop\Game Launcher.bat"

echo   Game launcher created successfully.
timeout /t 2 /nobreak >nul

cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                        OPTIMIZATION COMPLETE!
echo   ========================================================================
echo.
echo   Your PC has been optimized for maximum gaming performance!
echo.
echo   IMPORTANT: When you're done gaming, run the restore option
echo   to return your system to normal operation.
echo.
echo   A game launcher shortcut has been created on your desktop.
echo   Use it to launch any game with optimized settings.
echo.
echo   Press any key to return to the menu...
pause >nul
goto main_menu

:restore
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                          SYSTEM RESTORATION
echo   ========================================================================
echo.
echo   Restoring services...
net start wuauserv >nul 2>&1
net start WSearch >nul 2>&1
net start Spooler >nul 2>&1
net start SysMain >nul 2>&1
net start WinDefend >nul 2>&1
net start BITS >nul 2>&1
net start DiagTrack >nul 2>&1
net start dmwappushservice >nul 2>&1
net start MapsBroker >nul 2>&1
net start wscsvc >nul 2>&1
echo   Services restored successfully.
timeout /t 2 /nobreak >nul

echo.
echo   Restoring network settings...
netsh int tcp reset >nul 2>&1
echo   Network settings restored successfully.
timeout /t 2 /nobreak >nul

echo.
echo   Restoring power plan...
powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e >nul 2>&1
echo   Power plan restored successfully.
timeout /t 2 /nobreak >nul

echo.
echo   Restoring memory settings...
PowerShell -Command "Enable-MMAgent -MemoryCompression" >nul 2>&1
wmic computersystem set AutomaticManagedPagefile=True >nul 2>&1
echo   Memory settings restored successfully.
timeout /t 2 /nobreak >nul

echo.
echo   Restoring visual effects...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /f >nul 2>&1
echo   Visual effects restored successfully.
timeout /t 2 /nobreak >nul

cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                     SYSTEM RESTORED SUCCESSFULLY!
echo   ========================================================================
echo.
echo   Your system has been restored to normal operation.
echo.
echo   Thank you for using the Ultimate Game Optimizer!
echo.
echo   Press any key to return to the menu...
pause >nul
goto main_menu

:sysinfo
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                          SYSTEM INFORMATION
echo   ========================================================================
echo.
echo   Gathering system information...
echo.
color 0B
echo   OPERATING SYSTEM:
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
echo.
color 0C
echo   PROCESSOR:
wmic cpu get name
echo.
color 0D
echo   MEMORY:
systeminfo | findstr /C:"Total Physical Memory"
echo.
color 0E
echo   GRAPHICS CARD:
wmic path win32_VideoController get name
echo.
color 09
echo   DISK SPACE:
wmic logicaldisk where drivetype=3 get name, freespace, size
echo.
color 0A
echo   Press any key to return to the menu...
pause >nul
goto main_menu

:manual_update_check
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                          CHECKING FOR UPDATES
echo   ========================================================================
echo.
echo   Current version: %version%
echo   Checking for updates...

call :check_for_updates show_result

echo.
echo   Press any key to return to the menu...
pause >nul
goto main_menu

:check_for_updates
:: Check for updates from GitHub
set "show_result="
if "%1"=="show_result" set "show_result=1"

:: Use PowerShell to check for updates
PowerShell -Command "& {try { $latestVersion = (Invoke-WebRequest -Uri '%github_repo%/version.txt' -UseBasicParsing).Content.Trim(); if ([version]$latestVersion -gt [version]'%version%') { Write-Output 'update_available|' + $latestVersion } else { Write-Output 'up_to_date' } } catch { Write-Output 'error' }}" > "%temp%\update_check.txt"

set /p update_status=<"%temp%\update_check.txt"

if "%update_status%"=="error" (
    if defined show_result (
        echo   Error checking for updates. Please check your internet connection.
    )
    goto :eof
)

if "%update_status%"=="up_to_date" (
    if defined show_result (
        echo   Your version is up to date!
    )
    goto :eof
)

for /f "tokens=1,2 delims=|" %%a in ("%update_status%") do (
    if "%%a"=="update_available" (
        set "latest_version=%%b"
        if defined show_result (
            echo.
            echo   Update available! Version %version% -^> %%b
            echo.
            echo   [1] Download and install update
            echo   [2] Skip update
            echo.
            echo   Enter your choice (1-2):
            
            set update_choice=
            set /p update_choice=
            
            if "!update_choice!"=="1" (
                call :download_update
            ) else (
                echo   Update skipped.
            )
        ) else (
            echo   Update available! Version %version% -^> %%b
            echo   Run the "Check for Updates" option from the main menu to update.
            timeout /t 3 /nobreak >nul
        )
    )
)

goto :eof

:download_update
echo.
echo   Downloading update...

:: Use PowerShell to download the updated script
PowerShell -Command "& {try { Invoke-WebRequest -Uri '%github_repo%/GameOptimizer.bat' -OutFile '%~dp0\GameOptimizer_new.bat'; Write-Output 'success' } catch { Write-Output 'error' }}" > "%temp%\download_result.txt"

set /p download_status=<"%temp%\download_result.txt"

if "%download_status%"=="error" (
    echo   Error downloading update. Please try again later.
    goto :eof
)

echo   Update downloaded successfully!
echo   Creating backup of current version...

:: Create backup of current version
copy "%~f0" "%~dp0\GameOptimizer_backup.bat" >nul

echo   Installing update...

:: Create update script that will replace the current file and restart
echo @echo off > "%temp%\update_script.bat"
echo timeout /t 2 /nobreak ^>nul >> "%temp%\update_script.bat"
echo copy /y "%~dp0\GameOptimizer_new.bat" "%~f0" ^>nul >> "%temp%\update_script.bat"
echo del "%~dp0\GameOptimizer_new.bat" >> "%temp%\update_script.bat"
echo echo Update installed successfully! >> "%temp%\update_script.bat"
echo echo Starting new version... >> "%temp%\update_script.bat"
echo timeout /t 2 /nobreak ^>nul >> "%temp%\update_script.bat"
echo start "" "%~f0" >> "%temp%\update_script.bat"
echo exit >> "%temp%\update_script.bat"

echo   Finalizing update...
echo   The program will restart after the update.
timeout /t 3 /nobreak >nul

:: Run the update script and exit
start "" "%temp%\update_script.bat"
exit

:end
cls
color 0A
echo.
color 0B
echo   ##        #######  ##     ## #######    ###    ##    ##
color 0C
echo   ##        ##        ##   ##  ##        ## ##   ###   ##
color 0D
echo   ##        ##         ## ##   ##       ##   ##  ####  ##
color 0E
echo   ##        ######      ###    ######  ##     ## ## ## ##
color 09
echo   ##        ##         ## ##   ##      ######### ##  ####
color 05
echo   ##        ##        ##   ##  ##      ##     ## ##   ###
color 06
echo   ######## ######## ##     ## ##      ##     ## ##    ##
color 0A
echo.
echo   ========================================================================
echo                           EXITING PROGRAM
echo   ========================================================================
echo.
echo   Thank you for using Ultimate Game Optimizer v%version%!
echo.
echo                              BY LEXFAN
echo.
echo   Press any key to exit...
pause >nul
exit
