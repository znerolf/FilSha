@echo off
cd /d "C:\Users\flore\Desktop\FilSha"
echo Starting Flask application and Cloudflare tunnel...

start "Flask Application" cmd /k "python -m flask run --host=0.0.0.0 --port=5000 --debug"

echo Waiting 8 seconds for Flask to initialize...
echo [                    ] 0%% 
timeout /t 1 /nobreak >nul
echo [====                ] 25%% 
timeout /t 2 /nobreak >nul
echo [========            ] 50%% 
timeout /t 2 /nobreak >nul
echo [================    ] 75%% 
timeout /t 3 /nobreak >nul
echo [====================] 100%% 
echo Delay complete!

start "Cloudflare Tunnel" cloudflared tunnel run filsha

echo Both applications have been started!
echo - Flask app: http://0.0.0.0:5000
echo - Cloudflare tunnel started after 8-second delay
pause