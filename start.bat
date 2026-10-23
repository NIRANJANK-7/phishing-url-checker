
@echo off
cd /d "%~dp0"
start "" http://127.0.0.1:5000
python -c "from app import app; app.run(debug=False, use_reloader=False)"
pause
