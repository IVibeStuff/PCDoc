// PCDoc - download / install actions started from the report's buttons.
// The report page (in WebView2) posts "prepare|<id>", "openfolder" or "openpath|<path>".
// Each step runs Invoke-PCDocAction.ps1 in-process; the app asks the user before anything is installed or opened.
// C# 5 compatible.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace PCDoc
{
    partial class MainForm
    {
        ScriptHost actHost;
        Process actProc;
        string actId, actStage;
        Dictionary<string, string> actRes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Timer actTimer;
        Panel actStrip;
        Label actLabel;
        ProgressLine actBar;
        FlatBtn btnDlFolder;
        string downloadsFolder;

        void BuildActionStrip(Panel resultView)
        {
            actStrip = new Panel { Dock = DockStyle.Bottom, Height = 44, BackColor = Theme.Rail };
            actStrip.Paint += (s, e) => { using (Pen p = new Pen(Theme.LineSoft)) e.Graphics.DrawLine(p, 0, 0, actStrip.Width, 0); };
            actLabel = new Label { AutoSize = false, AutoEllipsis = true, ForeColor = Theme.Muted, BackColor = Theme.Rail, Text = "", TextAlign = ContentAlignment.MiddleLeft };
            actBar = new ProgressLine { Height = 4, Visible = false };
            btnDlFolder = new FlatBtn("Open downloads folder");
            btnDlFolder.Click += (s, e) => OpenDownloadsFolder(null);
            actStrip.Controls.AddRange(new Control[] { actLabel, actBar, btnDlFolder });
            actStrip.Resize += (s, e) => LayoutStrip();
            resultView.Controls.Add(actStrip);
            actTimer = new Timer { Interval = 120 };
            actTimer.Tick += (s, e) => PollAction();
        }

        void LayoutStrip()
        {
            btnDlFolder.Location = new Point(actStrip.Width - 20 - btnDlFolder.Width, (actStrip.Height - btnDlFolder.Height) / 2);
            int w = Math.Max(100, btnDlFolder.Left - 24 - 24);
            actLabel.SetBounds(24, 6, w, 24);
            actBar.SetBounds(24, 31, Math.Min(w, 420), 4);
        }

        void ResetActionStrip()
        {
            downloadsFolder = ReadDownloadsFolder();
            actLabel.ForeColor = Theme.Muted;
            actLabel.Text = "Downloads are saved to " + (downloadsFolder ?? "your Downloads folder\\PCDoc") + ". Nothing is installed without asking you first.";
            actBar.Visible = false; actBar.Active = false;
            LayoutStrip();
        }

        string ReadDownloadsFolder()
        {
            try
            {
                string json = File.ReadAllText(Path.Combine(outDir, "audit.json"), Encoding.UTF8);
                Match m = Regex.Match(json, "\"DownloadsFolder\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (m.Success) return Regex.Unescape(m.Groups[1].Value);
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "PCDoc", Environment.MachineName);
        }

        void OpenDownloadsFolder(string sub)
        {
            string root = downloadsFolder ?? ReadDownloadsFolder();
            string target = root;
            if (!string.IsNullOrEmpty(sub))
            {
                // Only folders inside the PCDoc downloads folder can be opened from the page
                try
                {
                    string full = Path.GetFullPath(sub), r = Path.GetFullPath(Path.GetDirectoryName(root.TrimEnd('\\', '/')));
                    if (full.StartsWith(r, StringComparison.OrdinalIgnoreCase) && Directory.Exists(full)) target = full;
                }
                catch { }
            }
            try { Directory.CreateDirectory(target); } catch { }
            Program.OpenExternal(target);
        }

        // ------------------------------------------------------------------ messages from the page
        void OnWebMessage(string msg)
        {
            if (string.IsNullOrEmpty(msg)) return;
            string[] p = msg.Split(new[] { '|' }, 2);
            switch (p[0])
            {
                case "prepare":
                    if (p.Length < 2 || !Regex.IsMatch(p[1], @"^a\d{1,4}$")) return;
                    if (actHost != null || actProc != null)
                    {
                        Post("status|" + p[1] + "|error|Another download is still running. Try again when it has finished.|");
                        return;
                    }
                    RunAction(p[1], "Prepare");
                    break;
                case "dismiss":
                case "restore":
                    SaveDismissal(p[0], p.Length > 1 ? p[1] : "");
                    break;
                case "window":
                    int days;
                    if (p.Length > 1 && int.TryParse(p[1], out days) && (days == 0 || days == 1 || days == 7 || days == 30)) SaveWindow(days);
                    break;
                case "openfolder": OpenDownloadsFolder(null); break;
                case "openpath": OpenDownloadsFolder(p.Length > 1 ? p[1] : null); break;
            }
        }

        // ------------------------------------------------------------------ dismissed items
        // Kept per PC next to the report folders: Documents\PCDoc reports\<PC>.dismissed.jsonl, one JSON object per line.
        // The next scan reads it; the open report updates at once.
        string DismissalsFile()
        {
            try
            {
                string json = File.ReadAllText(Path.Combine(outDir, "audit.json"), Encoding.UTF8);
                Match m = Regex.Match(json, "\"DismissalsFile\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (m.Success) return Regex.Unescape(m.Groups[1].Value);
            }
            catch { }
            return Path.Combine(Path.GetDirectoryName(outDir.TrimEnd('\\', '/')), Environment.MachineName + ".dismissed.jsonl");
        }

        static string J(string s)
        {
            StringBuilder b = new StringBuilder("\"");
            foreach (char c in s ?? "")
            {
                if (c == '"' || c == '\\') b.Append('\\').Append(c);
                else if (c < 0x20) b.AppendFormat("\\u{0:x4}", (int)c);
                else b.Append(c);
            }
            return b.Append('"').ToString();
        }

        void SaveDismissal(string op, string rest)
        {
            string[] parts = rest.Split('|');
            string encKeys = parts[0];
            string title = parts.Length > 1 ? SafeUnescape(parts[1]) : "";
            if (title.Length > 200) title = title.Substring(0, 200);
            List<string> keys = encKeys.Split(',').Select(SafeUnescape).Where(k => k.Length > 0 && k.Length <= 400).Take(200).ToList();
            if (keys.Count == 0) return;
            string at = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");
            try
            {
                StringBuilder lines = new StringBuilder();
                foreach (string k in keys)
                    lines.Append("{\"Op\":" + J(op) + ",\"Key\":" + J(k) + ",\"At\":" + J(at) + ",\"Title\":" + J(title) + "}\n");
                string file = DismissalsFile();
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                File.AppendAllText(file, lines.ToString(), new UTF8Encoding(false));
                Post((op == "dismiss" ? "dismissed|" : "restored|") + encKeys + "|" + at);
                actLabel.ForeColor = Theme.Muted;
                actLabel.Text = op == "dismiss" ? "Dismissed: " + (title.Length > 0 ? title : "item") + ". It comes back if it happens again." : "Restored.";
            }
            catch (Exception ex) { actLabel.ForeColor = Theme.High; actLabel.Text = "Could not save: " + ex.Message; }
        }

        void SaveWindow(int days)
        {
            try
            {
                string file = DismissalsFile();
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                File.AppendAllText(file, "{\"Op\":\"window\",\"Key\":\"$window\",\"Days\":" + days + ",\"At\":" + J(DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss")) + "}\n", new UTF8Encoding(false));
                actLabel.ForeColor = Theme.Muted;
                actLabel.Text = days == 0 ? "Showing issues of any age." : "Hiding issues older than " + days + (days == 1 ? " day" : " days") + " on this PC. Current problems still show.";
            }
            catch (Exception ex) { actLabel.ForeColor = Theme.High; actLabel.Text = "Could not save: " + ex.Message; }
        }

        static string SafeUnescape(string s) { try { return Uri.UnescapeDataString(s ?? ""); } catch { return ""; } }

        void Post(string msg) { if (web != null) { try { WebViewHost.Post(web, msg); } catch { } } }

        static string Clean(string s) { return (s ?? "").Replace("|", "/").Replace("\r", " ").Replace("\n", " "); }

        void Status(string id, string state, string text, int pct)
        {
            Post("status|" + id + "|" + state + "|" + Clean(text) + "|" + (pct >= 0 ? pct.ToString() : ""));
            actLabel.Text = text;
            actLabel.ForeColor = state == "error" ? Theme.High : state == "blocked" || state == "manual" ? Theme.Med : state == "done" || state == "ready" ? Theme.Ok : Theme.Text;
            actBar.Visible = state == "working"; actBar.Active = state == "working";
            if (pct >= 0) actBar.Value = pct;
        }

        // ------------------------------------------------------------------ running the action script
        void RunAction(string id, string stage)
        {
            actId = id; actStage = stage; actRes.Clear();
            btnAgain.Enabled = false;
            Post("busy|1");
            Status(id, "working", stage == "Prepare" ? "Starting the download…" : stage == "Install" ? "Installing…" : "Opening the installer…", 0);
            fullLog.AppendLine("== Action " + id + " " + stage);

            List<KeyValuePair<string, object>> pars = new List<KeyValuePair<string, object>>();
            pars.Add(new KeyValuePair<string, object>("AuditJson", Path.Combine(outDir, "audit.json")));
            pars.Add(new KeyValuePair<string, object>("ActionId", id));
            pars.Add(new KeyValuePair<string, object>("Stage", stage));
            try
            {
                if (ScriptHost.IsAvailable() && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PCDOC_TEST_CMD")))
                {
                    actHost = new ScriptHost();
                    actHost.Start(Program.ReadResourceText("Invoke-PCDocAction.ps1"), pars, Path.Combine(Program.AppDir, "app"));
                }
                else
                {
                    string script = Program.Extract("Invoke-PCDocAction.ps1", Path.Combine("app", "Invoke-PCDocAction.ps1"));
                    StringBuilder a = new StringBuilder("-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File \"" + script + "\"");
                    foreach (KeyValuePair<string, object> kv in pars) a.Append(" -" + kv.Key + " \"" + kv.Value + "\"");
                    string exe = Environment.GetEnvironmentVariable("PCDOC_TEST_ACTION_CMD");
                    string args = exe != null ? (Environment.GetEnvironmentVariable("PCDOC_TEST_ACTION_ARGS") ?? "") + " " + id + " " + stage : a.ToString();
                    ProcessStartInfo psi = new ProcessStartInfo(exe ?? Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), args)
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
                    actProc = new Process { StartInfo = psi, EnableRaisingEvents = true };
                    actProc.OutputDataReceived += (s, e) => { if (e.Data != null) BeginInvokeSafe(() => OnActLine(e.Data, false)); };
                    actProc.ErrorDataReceived += (s, e) => { if (e.Data != null) BeginInvokeSafe(() => OnActLine(e.Data, true)); };
                    actProc.Exited += (s, e) => BeginInvokeSafe(() => { if (actProc != null) { actProc.WaitForExit(); actProc = null; ActionFinished(null); } });
                    actProc.Start(); actProc.BeginOutputReadLine(); actProc.BeginErrorReadLine();
                }
            }
            catch (Exception ex) { actHost = null; actProc = null; ActionFinished("Could not start: " + ex.Message); return; }
            actTimer.Start();
        }

        void PollAction()
        {
            actBar.Tick();
            if (actHost == null) return;
            bool done;
            try { done = actHost.Poll(OnActLine); }
            catch (Exception ex) { OnActLine("Internal error: " + ex.Message, true); done = true; }
            if (done)
            {
                string f = actHost.FailureMessage;
                actHost.Dispose(); actHost = null;
                ActionFinished(f);
            }
        }

        void OnActLine(string line, bool isErr)
        {
            fullLog.AppendLine("  " + line);
            Match m;
            if ((m = Regex.Match(line, @"^PROGRESS (\d+) (.*)$")).Success) Status(actId, "working", m.Groups[2].Value, int.Parse(m.Groups[1].Value));
            else if ((m = Regex.Match(line, @"^R:(\w+)=(.*)$")).Success) actRes[m.Groups[1].Value] = m.Groups[2].Value;
            else if (isErr && !actRes.ContainsKey("Error")) actRes["Note"] = line;
        }

        string R(string k) { string v; return actRes.TryGetValue(k, out v) ? v : null; }

        void ActionFinished(string failure)
        {
            actTimer.Stop();
            Post("busy|0");
            btnAgain.Enabled = true;
            SaveLog();
            string id = actId, stage = actStage;
            if (failure != null || R("Ok") == null) { Status(id, "error", "Stopped: " + (failure ?? R("Error") ?? R("Note") ?? "the helper ended without a result."), -1); return; }
            if (!string.Equals(R("Ok"), "True", StringComparison.OrdinalIgnoreCase))
            {
                Status(id, "error", R("Error") ?? R("Outcome") ?? "Failed.", -1);
                if (stage == "Install") Dialog.Show(this, "The driver was not installed", (R("Outcome") ?? R("Error") ?? "") + "\n\nThe files are still in the downloads folder.", "Close", null, null);
                return;
            }
            string title = R("Title") ?? "this update", signer = R("Signer");
            if (stage == "Prepare")
            {
                string next = R("Next");
                string signedBy = signer != null ? "signed by " + signer : "signature checked";
                if (next == "install")
                {
                    Status(id, "ready", "Downloaded and verified (" + signedBy + "). Waiting for your OK to install.", -1);
                    string body = title + "\n\n" +
                        (R("FromVersion") != null ? "Installed now:  " + R("FromVersion") + "\nNew version:   " + R("ToVersion") + "\n\n" : "") +
                        "The package is " + signedBy + ". PCDoc will create a System Restore point first, then install it with Windows' own driver installer (pnputil).\n\n" +
                        "If something goes wrong, roll back in Device Manager (device > Properties > Driver > Roll Back Driver) or use the restore point.";
                    int r = Dialog.Show(this, "Install this driver?", body, "Install", "Not now", "Show files");
                    if (r == 1) { RunAction(id, "Install"); return; }
                    if (r == 2) OpenDownloadsFolder(R("Folder"));
                    Status(id, "done", "Downloaded, not installed. The files are in the downloads folder.", -1);
                }
                else if (next == "launch")
                {
                    Status(id, "ready", "Downloaded and verified (" + signedBy + "). Waiting for your OK to open it.", -1);
                    string body = title + "\n\n" + (R("ToVersion") != null ? "Version:  " + R("ToVersion") + "\n" : "") +
                        "Signed by:  " + (signer ?? "?") + "\n\n" +
                        "The manufacturer's own installer will open. It shows its own screens and asks before it changes anything. Nothing has been installed yet.";
                    int r = Dialog.Show(this, "Open the installer?", body, "Open installer", "Not now", "Show files");
                    if (r == 1) { RunAction(id, "Launch"); return; }
                    if (r == 2) OpenDownloadsFolder(R("Folder"));
                    Status(id, "done", "Downloaded, not opened. The file is in the downloads folder.", -1);
                }
                else if (next == "blocked")
                {
                    Status(id, "blocked", R("Note") ?? "Blocked for safety.", -1);
                    if (Dialog.Show(this, "Stopped for safety", (R("Note") ?? "") + "\n\nSigned by: " + (signer ?? "nobody") + " (" + (R("SignatureStatus") ?? "?") + ")\n\nThe file was kept so you can inspect it. Get the update from the manufacturer's website instead.", "Close", null, "Show files") == 2)
                        OpenDownloadsFolder(R("Folder"));
                }
                else
                {
                    Status(id, "manual", "Downloaded. " + (R("Note") ?? "Finish this step by hand."), -1);
                    if (Dialog.Show(this, "Downloaded", title + "\n\n" + (R("Note") ?? "This one needs a manual step.") + "\n\nThe files are in:\n" + R("Folder"), "Close", null, "Show files") == 2)
                        OpenDownloadsFolder(R("Folder"));
                }
            }
            else if (stage == "Install")
            {
                string code = R("ExitCode");
                string outcome = R("Outcome") ?? "Installed";
                Status(id, "done", outcome + ". Scan again to see it under Change history.", -1);
                if (code == "3010") Dialog.Show(this, "Restart needed", title + " is installed. Restart Windows to finish.", "OK", null, null);
                if (R("RestorePoint") != null && R("RestorePoint").StartsWith("Skipped")) fullLog.AppendLine("Restore point: " + R("RestorePoint"));
            }
            else if (stage == "Launch")
                Status(id, "done", "Installer opened. Follow its steps, then scan again to confirm.", -1);
        }

        void StopAction()
        {
            try { if (actHost != null) actHost.Stop(); } catch { }
            try { if (actProc != null && !actProc.HasExited) actProc.Kill(); } catch { }
        }
    }

    /// <summary>Small dark dialog. Returns 1 for the main button, 2 for the extra button, 0 otherwise.</summary>
    static class Dialog
    {
        public static int Show(IWin32Window owner, string title, string body, string okText, string cancelText, string extraText)
        {
            int result = 0;
            using (Form f = new Form())
            {
                f.Text = "PCDoc"; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MaximizeBox = false; f.MinimizeBox = false; f.ShowInTaskbar = false;
                f.StartPosition = FormStartPosition.CenterParent; f.BackColor = Theme.Panel; f.ForeColor = Theme.Text;
                f.Font = Theme.F(Theme.TextFace, 9.75f); f.AutoScaleMode = AutoScaleMode.Dpi; f.AutoScaleDimensions = new SizeF(96f, 96f);
                f.ClientSize = new Size(520, 100);
                Label t = new Label { Text = title, AutoSize = false, Location = new Point(24, 20), Size = new Size(472, 30), Font = Theme.F(Theme.Display, 13f, FontStyle.Bold), ForeColor = Theme.Text };
                // Body text painted directly: wraps the same way it is measured, on every Windows version
                Font bf = Theme.F(Theme.TextFace, 9.75f);
                TextFormatFlags tf = TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix | TextFormatFlags.TextBoxControl;
                Panel b = new Panel { Location = new Point(24, 58), BackColor = Theme.Panel };
                b.Paint += (s, e) => TextRenderer.DrawText(e.Graphics, body, bf, new Rectangle(0, 0, b.Width, b.Height), Theme.Muted, tf);
                f.Controls.Add(t); f.Controls.Add(b);
                FlatBtn ok = new FlatBtn(okText, true);
                ok.Click += (s, e) => { result = 1; f.Close(); };
                List<Control> btns = new List<Control> { ok };
                if (cancelText != null) { FlatBtn c = new FlatBtn(cancelText); c.Click += (s, e) => { result = 0; f.Close(); }; btns.Add(c); f.CancelButton = c; }
                else f.CancelButton = ok;
                FlatBtn x = null;
                if (extraText != null) { x = new FlatBtn(extraText); x.Click += (s, e) => { result = 2; f.Close(); }; }
                foreach (Control c in btns) f.Controls.Add(c);
                if (x != null) f.Controls.Add(x);
                f.Load += (s, e) =>
                {
                    int w = f.ClientSize.Width - 48;
                    Size sz = TextRenderer.MeasureText(body, bf, new Size(w, 4000), tf);
                    b.Size = new Size(w, sz.Height + bf.Height);
                    int y = b.Bottom + 14;
                    int right = f.ClientSize.Width - 24;
                    foreach (Control c in btns) { right -= c.Width; c.Location = new Point(right, y); right -= 8; }
                    if (x != null) x.Location = new Point(24, y);
                    f.ClientSize = new Size(f.ClientSize.Width, y + ok.Height + 20);
                    try { int on = 1; NativeDark(f.Handle, on); } catch { }
                };
                f.AcceptButton = ok;
                f.ShowDialog(owner);
            }
            return result;
        }

        [System.Runtime.InteropServices.DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
        static void NativeDark(IntPtr h, int on) { if (DwmSetWindowAttribute(h, 20, ref on, 4) != 0) DwmSetWindowAttribute(h, 19, ref on, 4); }
    }
}
