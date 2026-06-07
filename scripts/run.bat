call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
set INCLUDE

cd ..
moon run .\cmd\main\ --target native  
