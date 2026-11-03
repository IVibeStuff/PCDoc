#!/bin/bash
# Builds dist/PCDoc.exe (single file, .NET Framework 4.8) with the Mono C# compiler, from the repo.
# Needs: mono (mcs, 4.8-api reference assemblies) and python3.
set -e
cd "$(dirname "$0")/.."
VER=$(sed -n 's/.*public const string Version = "\([0-9.]*\)".*/\1/p' src/PCDoc.cs)
OUT=dist; mkdir -p $OUT obj
python3 build/mkres.py $VER.0 build/app.ico obj/app.res
API=/usr/lib/mono/4.8-api
mcs -nologo -target:winexe -platform:anycpu -optimize+ -langversion:5 -nostdlib -noconfig \
  -r:$API/mscorlib.dll -r:$API/System.dll -r:$API/System.Core.dll -r:$API/System.Drawing.dll -r:$API/System.Windows.Forms.dll -r:$API/Microsoft.CSharp.dll \
  -r:lib/Microsoft.Web.WebView2.Core.dll -r:lib/Microsoft.Web.WebView2.WinForms.dll \
  -win32res:obj/app.res \
  -resource:scripts/Invoke-PCDoc.ps1,Invoke-PCDoc.ps1 \
  -resource:scripts/report-template.html,report-template.html \
  -resource:scripts/Invoke-PCDocAction.ps1,Invoke-PCDocAction.ps1 \
  -resource:lib/Microsoft.Web.WebView2.Core.dll,bin.Microsoft.Web.WebView2.Core.dll \
  -resource:lib/Microsoft.Web.WebView2.WinForms.dll,bin.Microsoft.Web.WebView2.WinForms.dll \
  -resource:lib/x64/WebView2Loader.dll,bin.x64.WebView2Loader.dll \
  -resource:lib/x86/WebView2Loader.dll,bin.x86.WebView2Loader.dll \
  -resource:lib/arm64/WebView2Loader.dll,bin.arm64.WebView2Loader.dll \
  -out:$OUT/PCDoc.exe src/PCDoc.cs src/ScriptHost.cs src/Actions.cs
ls -la $OUT/PCDoc.exe
