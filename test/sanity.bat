@echo off

REM Test Setup
rd /s /q c:\gatekeeper_test
mkdir c:\gatekeeper_test
xcopy .\gatectl.exe c:\gatekeeper_test\
PUSHD c:\gatekeeper_test

gatectl directory c:\gatekeeper_test || exit /b 1
gatectl directory c:\gatekeeper_test || exit /b 1
gatectl clear || exit /b 1
gatectl directory c:\gatekeeper_test || exit /b 1

REM Test simple revoke
gatectl revoke "foo"
gatectl directory c:\gatekeeper_test || exit /b 1
copy NUL bat || exit /b 1
copy NUL foo
if %errorlevel% EQU 0 (
	echo expected access denied due to revoke & exit /b 1
)

REM Test simple unrevoke
gatectl unrevoke "foo"
echo "" > foo || exit /b 1
gatectl unrevoke "foo"
if %errorlevel% EQU 0 (
	echo expected not found & exit /b 1
)


gatectl clear || exit /b 1
gatectl clear || exit /b 1
gatectl revoke aa || exit /b 1
gatectl directory .\ || exit /b 1
gatectl revoke bb || exit /b 1
gatectl revoke cc || exit /b 1
gatectl revoke bb || exit /b 1
gatectl revoke kk || exit /b 1
gatectl unrevoke cc || exit /b 1
gatectl unrevoke notfound
if %errorlevel% EQU 0 (
	echo expected not found & exit /b 1
)
copy NUL k.txt || exit /b 1
copy NUL abba.txt
if %errorlevel% EQU 0 (
	echo expected access denied due to revoke & exit /b 1
)
copy NUL abba.txt
if %errorlevel% EQU 0 (
	echo expected access denied due to revoke & exit /b 1
)
copy NUL aabb.txt
if %errorlevel% EQU 0 (
	echo expected access denied due to revoke & exit /b 1
)
gatectl unrevoke bb || exit /b 1
copy NUL abba.txt
if %errorlevel% EQU 0 (
	echo expected access denied due to revoke & exit /b 1
)
gatectl clear || exit /b 1
copy NUL abba.txt || exit /b 1


REM Test Teardown
gatectl clear
POPD