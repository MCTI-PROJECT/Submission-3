@echo off
setlocal enabledelayedexpansion

REM Configuration
set "GHIDRA_PATH=C:\Users\MCTI Student\Downloads\ghidra"
set "PROJECT_PATH=C:\Users\MCTI Student\Desktop\Sub 3\GhidraProject"
set "USER_SCRIPTS_DIR=%USERPROFILE%\ghidra_scripts"
set "MALWARE_DIR=C:\Users\MCTI Student\Desktop\Sub 3\Unpacked_Samples"
set "LOG_DIR=C:\Users\MCTI Student\Desktop\Sub 3\logs"
set "TEMP_DIR=C:\Users\MCTI Student\Desktop\Sub 3\temp"

echo Starting malware analysis process...
echo ============================
echo Configuration:
echo GHIDRA_PATH: %GHIDRA_PATH%
echo PROJECT_PATH: %PROJECT_PATH%
echo USER_SCRIPTS_DIR: %USER_SCRIPTS_DIR%
echo MALWARE_DIR: %MALWARE_DIR%
echo LOG_DIR: %LOG_DIR%
echo ============================
echo.

REM Create necessary directories
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"
if not exist "%USER_SCRIPTS_DIR%" mkdir "%USER_SCRIPTS_DIR%"
if not exist "%PROJECT_PATH%" mkdir "%PROJECT_PATH%"

REM Create main log file
set "MAIN_LOG=%LOG_DIR%\main_process.log"
echo Analysis started at %date% %time% > "%MAIN_LOG%"

REM Copy script to Ghidra user scripts directory
copy /Y "opcode_extractor.py" "%USER_SCRIPTS_DIR%\" >nul

REM Process each APT folder
for /d %%a in ("%MALWARE_DIR%\*") do (
    echo.
    echo Processing APT folder: %%~nxa
    echo Processing APT folder: %%~nxa >> "%MAIN_LOG%"
    
    REM Create opcodes directory
    set "OPCODE_DIR=%%a\opcodes"
    if not exist "!OPCODE_DIR!" mkdir "!OPCODE_DIR!"
    
    if exist "%%a\exe" (
        for %%f in ("%%a\exe\*") do (
            if not exist "%%f\" (
                echo.
                echo Processing binary: %%~nxf
                
                REM Create temporary copy with simple name
                set "TEMP_FILE=%TEMP_DIR%\sample.bin"
                copy "%%f" "!TEMP_FILE!" >nul
                
                REM Run Ghidra analysis with correct processor specification
                echo Running Ghidra analysis...
                call "%GHIDRA_PATH%\support\analyzeHeadless.bat" ^
                    "%PROJECT_PATH%" ^
                    "temp_project" ^
                    -import "!TEMP_FILE!" ^
                    -processor "x86:LE:64:default" ^
                    -scriptPath "%USER_SCRIPTS_DIR%" ^
                    -postScript "opcode_extractor.py" ^
                    -overwrite 2>> "%LOG_DIR%\ghidra_errors.log"
                
                REM If first attempt fails, try 32-bit
                if errorlevel 1 (
                    echo Retrying with 32-bit processor...
                    call "%GHIDRA_PATH%\support\analyzeHeadless.bat" ^
                        "%PROJECT_PATH%" ^
                        "temp_project" ^
                        -import "!TEMP_FILE!" ^
                        -processor "x86:LE:32:default" ^
                        -scriptPath "%USER_SCRIPTS_DIR%" ^
                        -postScript "opcode_extractor.py" ^
                        -overwrite 2>> "%LOG_DIR%\ghidra_errors.log"
                )
                
                REM Check if analysis was successful
                if errorlevel 1 (
                    echo Failed to analyze: %%~nxf
                    echo Failed to analyze: %%~nxf >> "%MAIN_LOG%"
                ) else (
                    echo Successfully analyzed: %%~nxf
                    echo Successfully analyzed: %%~nxf >> "%MAIN_LOG%"
                )
                
                REM Cleanup
                del "!TEMP_FILE!" 2>nul
                if exist "%PROJECT_PATH%\temp_project.gpr" del /F /Q "%PROJECT_PATH%\temp_project.gpr"
                if exist "%PROJECT_PATH%\temp_project.rep" rmdir /S /Q "%PROJECT_PATH%\temp_project.rep"
            )
        )
    ) else (
        echo No exe folder found in: %%~nxa
        echo No exe folder found in: %%~nxa >> "%MAIN_LOG%"
    )
)

REM Final cleanup
rmdir /S /Q "%TEMP_DIR%" 2>nul

echo.
echo ============================
echo Analysis process completed!
echo End Timestamp: %date% %time%
echo Analysis completed at %date% %time% >> "%MAIN_LOG%"

pause