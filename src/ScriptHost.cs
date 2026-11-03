// Runs a PowerShell script inside this process using the PowerShell engine that ships with Windows
// (System.Management.Automation). No powershell.exe child process and no script file on disk.
// The engine is loaded by reflection, so nothing extra has to be referenced or shipped.
// C# 5 compatible (builds with the compiler included in Windows).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace PCDoc
{
    public class ScriptHost : IDisposable
    {
        dynamic ps;           // System.Management.Automation.PowerShell
        dynamic runspace;     // System.Management.Automation.Runspaces.Runspace
        dynamic handle;       // IAsyncResult from BeginInvoke
        int infoIdx, errIdx, warnIdx;

        public string FailureMessage { get; private set; }

        public static Assembly LoadEngine()
        {
            foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                if (a.GetName().Name == "System.Management.Automation") return a;
            return Assembly.Load("System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        }

        public static bool IsAvailable()
        {
            try { return LoadEngine() != null; } catch { return false; }
        }

        /// <summary>Starts the script asynchronously. Parameters with a null value are passed as switches.</summary>
        public void Start(string scriptText, IList<KeyValuePair<string, object>> parameters, string workingDirectory)
        {
            Assembly sma = LoadEngine();
            Type issType = sma.GetType("System.Management.Automation.Runspaces.InitialSessionState", true);
            object iss = issType.GetMethod("CreateDefault", Type.EmptyTypes).Invoke(null, null);

            // The script runs from memory, so execution policy only matters for the built-in modules it loads.
            Type epType = sma.GetType("Microsoft.PowerShell.ExecutionPolicy", false);
            PropertyInfo epProp = issType.GetProperty("ExecutionPolicy");
            if (epType != null && epProp != null && Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                try { epProp.SetValue(iss, Enum.Parse(epType, "RemoteSigned"), null); } catch { }   // not supported off Windows
            }

            Type rf = sma.GetType("System.Management.Automation.Runspaces.RunspaceFactory", true);
            MethodInfo create = rf.GetMethods().First(m => m.Name == "CreateRunspace" && m.GetParameters().Length == 1 && m.GetParameters()[0].ParameterType == issType);
            runspace = create.Invoke(null, new object[] { iss });
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                try { runspace.ApartmentState = ApartmentState.STA; } catch { }   // COM (Windows Update) prefers STA
            }
            runspace.Open();
            if (!string.IsNullOrEmpty(workingDirectory))
            {
                try { runspace.SessionStateProxy.Path.SetLocation(workingDirectory); } catch { }
            }

            Type psType = sma.GetType("System.Management.Automation.PowerShell", true);
            ps = psType.GetMethod("Create", Type.EmptyTypes).Invoke(null, null);
            ps.Runspace = runspace;
            ps.AddScript(scriptText);
            foreach (KeyValuePair<string, object> kv in parameters)
            {
                if (kv.Value == null) ps.AddParameter(kv.Key);
                else ps.AddParameter(kv.Key, kv.Value);
            }
            handle = ps.BeginInvoke();
        }

        /// <summary>Collects new output lines (Write-Host, warnings, errors). Returns true when the script has finished.</summary>
        public bool Poll(Action<string, bool> onLine)
        {
            if (ps == null) return true;
            dynamic streams = ps.Streams;

            dynamic info = streams.Information;
            int n = info.Count;
            for (; infoIdx < n; infoIdx++)
            {
                dynamic rec = info[infoIdx];
                object data = rec.MessageData;
                onLine(data == null ? "" : data.ToString(), false);
            }
            dynamic warn = streams.Warning;
            n = warn.Count;
            for (; warnIdx < n; warnIdx++) { dynamic w = warn[warnIdx]; onLine("[!] " + (string)w.Message, false); }
            dynamic err = streams.Error;
            n = err.Count;
            for (; errIdx < n; errIdx++) { dynamic e = err[errIdx]; onLine(e.ToString(), true); }

            string state = ps.InvocationStateInfo.State.ToString();
            if (state == "Completed" || state == "Failed" || state == "Stopped")
            {
                if (state == "Failed")
                {
                    object reason = ps.InvocationStateInfo.Reason;
                    FailureMessage = reason != null ? ((Exception)reason).Message : "The script failed.";
                }
                try { ps.EndInvoke(handle); }
                catch (Exception ex) { if (FailureMessage == null && state != "Stopped") FailureMessage = (ex.InnerException ?? ex).Message; }
                return true;
            }
            return false;
        }

        public void Stop()
        {
            dynamic p = ps;
            if (p == null) return;
            ThreadPool.QueueUserWorkItem(delegate { try { p.Stop(); } catch { } });
        }

        public void Dispose()
        {
            try { if (ps != null) ps.Dispose(); } catch { }
            try { if (runspace != null) runspace.Dispose(); } catch { }
            ps = null; runspace = null;
        }
    }
}
