git pull origin master
git submodule update --init --recursive
@IF %ERRORLEVEL% NEQ 0 GOTO err

"C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" /m Katy.sln /p:Configuration=Release "/p:Platform=Win32"
@IF %ERRORLEVEL% NEQ 0 GOTO err

@exit /B 0
:err
@PAUSE
@exit /B 1