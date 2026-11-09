@echo off
cd /d "%~dp0"
if not exist node_modules (
  echo Installing for the first time...
  call npm install
)
echo.
echo Cafe rota is starting. Open http://localhost:3000 in your browser.
echo Keep this window open while the app is in use. Close it to stop the app.
echo.
call npm start
pause
