@echo off
:: הגדרת קידוד לתמיכה בעברית ובתווים מיוחדים
chcp 65001 >nul
title AegisCore Smart Search

:search_loop
cls
echo ===================================================
echo       AegisCore - Smart Developer Search
echo ===================================================
echo.

:: בקשת קלט מהמשתמש
set /p search_term="[?] String to search (or type 'exit' to quit): "

:: יציאה אם המשתמש ביקש
if /i "%search_term%"=="exit" exit

echo.
echo [*] Searching for: "%search_term%"
echo [*] Ignoring: venv, pycache, .git
echo ---------------------------------------------------

:: ביצוע החיפוש עם סינון תיקיות כבדות
findstr /s /i /m "%search_term%" *.* | find /v "venv" | find /v "__pycache__" | find /v ".git"

if %errorlevel% neq 0 (
    echo.
    echo [-] No matches found.
)

echo.
echo ---------------------------------------------------
echo [DONE] The search is finished.
echo.

:: פקודת ההשהיה
echo Press any key to search again, or close the window to exit...
pause >nul

:: חזרה להתחלה לחיפוש נוסף
goto search_loop