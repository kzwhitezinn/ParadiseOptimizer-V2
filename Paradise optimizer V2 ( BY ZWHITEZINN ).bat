@echo off
color 9
echo.
echo                    OTIMIZACAO AUTOMATICA  - PARADISE OPTIMIZER ( BY WHITE )
echo.
echo                    #####    ##     #####      ##     ######    ##   #####  #####                   
echo                   ##   ##  ####    ##  ##    ####    ##   ###  ##  ##      ##                      
echo                   ##   ##  #  #    ##  ##    #  ##   ##    ##  ##  ###     ##                      
echo                   ######  ##  ##   #####    ##  ##   ##    ##  ##     ###  ## ##                   
echo                   ##     ########  ##  ##  ########  ##   ###  ##      ##  ##                      
echo                   ##     ##     #  ##   ## ##     #  ######    ##  #####   #####                   
echo.
echo.
pause

echo Executando comandos aguarde...
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_DWORD /d 10 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d 04000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 00000005 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 00000008 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 00000006 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes

del /q /s C:\Windows\*.log
for /f "tokens=*" %%G in ('wevtutil.exe el') DO (wevtutil.exe cl "%%G")

del /q /s C:\Windows\Temp\*.*

rd /s /q C:\$Recycle.bin

echo.
set /p choice="Deseja Entrar no nosso servidor no discord? (S/N): "
echo.
if /i "%choice%"=="S" (
    start "" "https://discord.gg/F3KvN6RdRh"
) else (
    exit
)

echo.
set /p choice="Deseja se inscrever no canal do criador? (S/N): "
echo.
if /i "%choice%"=="S" (
    start "" "https://bit.ly/3FF99Zd"
) else (
    exit
)

echo.
echo Todos os comandos foram executados! 

@echo off
echo.
echo     ####   #   ##    ###### ##   ##   #  #    ##  #  ######  #### ######  #   ##   ##  ##    #     
echo     #  ##  ##  #         ##  #  ###  ##  #    ##  #    ##   ##        ##  ##  ###  ##  ###   #     
echo     #####   ###         #    ## # ## #   #######  #    ##   #####    #    ##  # ## ##  #  #  #     
echo     #   #    ##       ##      ###  ###   #    ##  #    ##   ##     ##     ##  #  ####  ##  ###     
echo     #####    #       ######   ##   ##    #    ##  #    ##   ##### ######  ##  #   ###  ##   ##     
echo.
echo.
pause
