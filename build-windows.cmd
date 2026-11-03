@echo off
:: Builds PCAudit.exe on any Windows PC using the C# compiler that ships with .NET Framework 4.x.
:: Optional: sign the result afterwards, e.g.
::   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a dist\PCAudit.exe
setlocal
cd /d "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist dist mkdir dist

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:Microsoft.CSharp.dll ^
  /r:lib\Microsoft.Web.WebView2.Core.dll /r:lib\Microsoft.Web.WebView2.WinForms.dll ^
  /win32res:build\app.res ^
  /resource:scripts\Invoke-PCAudit.ps1,Invoke-PCAudit.ps1 ^
  /resource:scripts\report-template.html,report-template.html ^
  /resource:scripts\Invoke-PCAuditAction.ps1,Invoke-PCAuditAction.ps1 ^
  /resource:lib\Microsoft.Web.WebView2.Core.dll,bin.Microsoft.Web.WebView2.Core.dll ^
  /resource:lib\Microsoft.Web.WebView2.WinForms.dll,bin.Microsoft.Web.WebView2.WinForms.dll ^
  /resource:lib\x64\WebView2Loader.dll,bin.x64.WebView2Loader.dll ^
  /resource:lib\x86\WebView2Loader.dll,bin.x86.WebView2Loader.dll ^
  /resource:lib\arm64\WebView2Loader.dll,bin.arm64.WebView2Loader.dll ^
  /out:dist\PCAudit.exe src\PCAudit.cs src\ScriptHost.cs src\Actions.cs
if errorlevel 1 (echo Build failed & exit /b 1)
echo Built dist\PCAudit.exe
