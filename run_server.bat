@echo off
title Seniors Platform Server
cd /d "D:\thanaweya-platform (18)\thanaweya-platform"
:loop
echo [%date% %time%] server starting... >> server.log
python app.py >> server.log 2>&1
echo [%date% %time%] server exited. restarting in 5s >> server.log
timeout /t 5 /nobreak >nul
goto loop
