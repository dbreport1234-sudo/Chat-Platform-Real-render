@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Install Node.js 20+ first.
  pause
  exit /b 1
)
if not exist node_modules (
  echo Installing packages...
  call npm install
  if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
)
if not exist .env (
  echo Creating secure .env...
  node -e "const fs=require('fs'),c=require('crypto');fs.writeFileSync('.env','PORT=3000\nJWT_SECRET='+c.randomBytes(48).toString('hex')+'\nMAX_UPLOAD_MB=25\nMAX_UPLOAD_FILES=10\nCORS_ORIGINS=http://localhost:3000\nNODE_ENV=development\n')"
)
start "Chat Platform Server" cmd /k "node server.js"
timeout /t 2 /nobreak >nul
start "" http://localhost:3000
