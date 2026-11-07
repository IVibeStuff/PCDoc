// PCDoc - Windows front end for the PC health scan (read-only) and the download/install helper.
// Runs Invoke-PCDoc.ps1 hidden, shows progress, then shows the report in an embedded WebView2.
// Target: .NET Framework 4.8 (built in to Windows 10/11). Single EXE: script, template and WebView2 files are embedded.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: AssemblyTitle("PCDoc")]
[assembly: AssemblyDescription("Read-only PC health, driver and update scan")]
[assembly: AssemblyProduct("PCDoc")]
[assembly: AssemblyVersion("0.4.6.0")]
[assembly: AssemblyFileVersion("0.4.6.0")]

namespace PCDoc
{
    static class Program
    {
        public const string Version = "0.4.6";
        public static string AppDir;

        [STAThread]
        static void Main(string[] args)
        {
            AppDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCDoc", Version);
            Directory.CreateDirectory(AppDir);
            // PCDoc was called "PC Audit" up to 0.4.4: carry the reports (history, dismissals) and downloads over
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            MoveIfNew(Path.Combine(docs, "PC Audit reports"), Path.Combine(docs, "PCDoc reports"));
            MoveIfNew(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "PC Audit"),
                      Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "PCDoc"));
            AppDomain.CurrentDomain.AssemblyResolve += ResolveEmbedded;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args));
            Environment.Exit(0);   // also ends any PowerShell pipeline thread still winding down
        }

        static void MoveIfNew(string from, string to)
        {
            try { if (Directory.Exists(from) && !Directory.Exists(to)) Directory.Move(from, to); } catch { }
        }

        public static string ReadResourceText(string resName)
        {
            using (Stream rs = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            using (StreamReader r = new StreamReader(rs, Encoding.UTF8, true)) return r.ReadToEnd();
        }

        static Assembly ResolveEmbedded(object sender, ResolveEventArgs e)
        {
            string name = new AssemblyName(e.Name).Name;
            if (name.StartsWith("Microsoft.Web.WebView2", StringComparison.OrdinalIgnoreCase))
            {
                string p = Extract("bin." + name + ".dll", Path.Combine("bin", name + ".dll"));
                if (p != null) return Assembly.LoadFrom(p);
            }
            return null;
        }

        /// <summary>Writes an embedded resource to AppDir\relPath if missing or different. Returns the path, or null.</summary>
        public static string Extract(string resName, string relPath)
        {
            string path = Path.Combine(AppDir, relPath);
            using (Stream rs = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {
                if (rs == null) return null;
                byte[] data = new byte[rs.Length];
                int read = 0;
                while (read < data.Length) { int n = rs.Read(data, read, data.Length - read); if (n <= 0) break; read += n; }
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                bool same = File.Exists(path) && new FileInfo(path).Length == data.Length && File.ReadAllBytes(path).SequenceEqual(data);
                if (!same)
                {
                    try { File.WriteAllBytes(path, data); }
                    catch (IOException) { if (!File.Exists(path)) throw; } // in use by another instance: keep existing copy
                }
            }
            return path;
        }

        /// <summary>Open a URL or file through Explorer so it runs un-elevated in the user's normal browser.</summary>
        public static void OpenExternal(string target)
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", "\"" + target + "\"") { UseShellExecute = true }); }
            catch { try { Process.Start(target); } catch { } }
        }
    }

    static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(20, 26, 35);
        public static readonly Color Rail = Color.FromArgb(15, 20, 27);
        public static readonly Color Panel = Color.FromArgb(25, 33, 44);
        public static readonly Color Panel2 = Color.FromArgb(31, 41, 53);
        public static readonly Color Sunk = Color.FromArgb(21, 28, 37);
        public static readonly Color Line = Color.FromArgb(42, 53, 66);
        public static readonly Color LineSoft = Color.FromArgb(35, 45, 57);
        public static readonly Color Text = Color.FromArgb(228, 233, 240);
        public static readonly Color Muted = Color.FromArgb(141, 153, 169);
        public static readonly Color Faint = Color.FromArgb(94, 106, 122);
        public static readonly Color Accent = Color.FromArgb(108, 196, 214);
        public static readonly Color High = Color.FromArgb(240, 122, 114);
        public static readonly Color Med = Color.FromArgb(230, 174, 85);
        public static readonly Color Ok = Color.FromArgb(92, 197, 146);

        static readonly HashSet<string> Installed = new HashSet<string>(new InstalledFontCollection().Families.Select(f => f.Name), StringComparer.OrdinalIgnoreCase);
        static string Pick(params string[] names) { foreach (string n in names) if (Installed.Contains(n)) return n; return SystemFonts.MessageBoxFont.FontFamily.Name; }
        public static readonly string Display = Pick("Segoe UI Variable Display", "Segoe UI Semibold", "Segoe UI");
        public static readonly string TextFace = Pick("Segoe UI Variable Text", "Segoe UI");
        public static readonly string Mono = Pick("Cascadia Mono", "Cascadia Code", "Consolas", "Courier New");
        public static Font F(string face, float size, FontStyle st = FontStyle.Regular) { return new Font(face, size, st, GraphicsUnit.Point); }
    }

    /// <summary>Thin progress line with a soft moving highlight while work is in progress.</summary>
    class ProgressLine : Control
    {
        float value; float shimmer; public bool Active = true;
        public float Value { get { return value; } set { this.value = Math.Max(0, Math.Min(100, value)); Invalidate(); } }
        public ProgressLine() { DoubleBuffered = true; SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true); }
        public void Tick() { shimmer = (shimmer + 0.012f) % 1.4f; Invalidate(); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            RectangleF r = new RectangleF(0, 0, Width - 1, Height - 1);
            using (GraphicsPath p = Round(r, Height / 2f)) using (SolidBrush b = new SolidBrush(Theme.Panel2)) g.FillPath(b, p);
            float w = (Width - 1) * value / 100f;
            if (w > 1)
            {
                RectangleF f = new RectangleF(0, 0, Math.Max(w, Height), Height - 1);
                using (GraphicsPath p = Round(f, Height / 2f))
                {
                    using (SolidBrush b = new SolidBrush(Theme.Accent)) g.FillPath(b, p);
                    if (Active)
                    {
                        float cx = (shimmer - 0.2f) * f.Width, hw = Math.Max(60, f.Width * 0.18f);
                        RectangleF hl = new RectangleF(cx - hw, 0, hw * 2, Height);
                        if (hl.Width > 0)
                            using (LinearGradientBrush lb = new LinearGradientBrush(hl, Color.FromArgb(0, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 0f))
                            {
                                ColorBlend cb = new ColorBlend(3);
                                cb.Colors = new[] { Color.FromArgb(0, 255, 255, 255), Color.FromArgb(90, 255, 255, 255), Color.FromArgb(0, 255, 255, 255) };
                                cb.Positions = new[] { 0f, 0.5f, 1f };
                                lb.InterpolationColors = cb;
                                Region old = g.Clip; g.SetClip(p); g.FillRectangle(lb, hl); g.Clip = old;
                            }
                    }
                }
            }
        }
        static GraphicsPath Round(RectangleF r, float rad)
        {
            GraphicsPath p = new GraphicsPath(); float d = Math.Min(rad * 2, Math.Min(r.Width, r.Height));
            if (d <= 0) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p;
        }
    }

    /// <summary>The app mark (chip glyph), drawn so it is crisp at any DPI.</summary>
    class Logo : Control
    {
        public Logo() { SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Parent != null ? Parent.BackColor : Theme.Rail);
            float S = Math.Min(Width, Height) - 1;
            using (GraphicsPath p = RoundRect(new RectangleF(0, 0, S, S), S * 0.22f))
            using (SolidBrush b = new SolidBrush(Theme.Panel)) using (Pen o = new Pen(Theme.Line)) { g.FillPath(b, p); g.DrawPath(o, p); }
            float w = Math.Max(1.5f, S * 0.06f);
            using (Pen a = new Pen(Theme.Accent, w)) using (SolidBrush ab = new SolidBrush(Theme.Accent))
            {
                float c0 = S * 0.30f, c1 = S * 0.70f;
                using (GraphicsPath p = RoundRect(new RectangleF(c0, c0, c1 - c0, c1 - c0), S * 0.06f)) g.DrawPath(a, p);
                g.FillRectangle(ab, S * 0.42f, S * 0.42f, S * 0.16f, S * 0.16f);
                foreach (float f in new[] { 0.42f, 0.58f })
                {
                    float x = S * f;
                    g.DrawLine(a, x, S * 0.14f, x, c0); g.DrawLine(a, x, c1, x, S * 0.86f);
                    g.DrawLine(a, S * 0.14f, x, c0, x); g.DrawLine(a, c1, x, S * 0.86f, x);
                }
            }
        }
        static GraphicsPath RoundRect(RectangleF r, float rad)
        {
            GraphicsPath p = new GraphicsPath(); float d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p;
        }
    }

    class FlatBtn : Button
    {
        public FlatBtn(string text, bool primary = false)
        {
            Text = text; FlatStyle = FlatStyle.Flat; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(10, 3, 10, 3); Cursor = Cursors.Hand; UseVisualStyleBackColor = false;
            BackColor = primary ? Color.FromArgb(34, 58, 66) : Theme.Panel2;
            ForeColor = primary ? Theme.Accent : Theme.Text;
            FlatAppearance.BorderColor = primary ? Color.FromArgb(56, 98, 110) : Theme.Line;
            FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(42, 72, 82) : Color.FromArgb(39, 50, 64);
            FlatAppearance.MouseDownBackColor = Theme.Panel;
            Font = Theme.F(Theme.TextFace, 9.75f);
        }
    }

    partial class MainForm : Form
    {
        // ---- state ----
        readonly string[] passArgs;
        Process proc;
        ScriptHost host;
        int pollTick;
        string reportPath, outDir;
        DateTime started;
        float target, stepEnd = 4, shown;
        int warnings;
        string lastProblem;
        readonly StringBuilder fullLog = new StringBuilder();
        readonly Random rnd = new Random();
        int humorIdx = -1; DateTime humorAt;
        bool closingAfterKill;

        // ---- ui ----
        Panel header, scanView, resultView, webHost, errorView;
        Label lblTitle, lblSub, lblStep, lblPct, lblTime, lblHumor, lblLogHead, lblResTitle, lblResPath, lblErr;
        ProgressLine bar;
        RichTextBox log;
        FlatBtn btnCancel, btnBrowser, btnFolder, btnAgain, btnErrAgain, btnErrLog;
        Timer timer;
        Control web;   // the WebView2 control (typed as Control so WebView2 is only loaded when needed)

        static readonly string[] Humor = {
            "Asking each driver politely how old it is.",
            "Reminding the BIOS that time has moved on since it was installed.",
            "Counting blue screens so you don't have to.",
            "Translating 0x800F0922 into human.",
            "Checking whether the USB hub is having a moment.",
            "Reading event logs nobody has opened since installation day.",
            "Comparing version numbers. The version numbers are not comparing back.",
            "Negotiating with the Microsoft Update Catalog's search box.",
            "Interviewing the network card about its recent dropouts.",
            "Not changing anything. Just looking. Promise.",
            "Sorting real errors from DCOM's usual complaints.",
            "Making sure every device knows its own name.",
            "Dusting the crash dumps for fingerprints.",
            "Counting the hours since the last restart. There are a few.",
            "Measuring SSD wear without adding to it.",
            "Cross-referencing hardware IDs with a stern expression.",
            "Convincing a manufacturer's website that we are a polite visitor.",
            "Explaining to Realtek that 10.x and 1125.x are different families.",
            "Checking whether the chipset driver remembers this decade.",
            "Asking Windows Update what it has been up to.",
            "Looking for drivers that were promised 'later'.",
            "Reading the fine print in setupapi.dev.log.",
            "Waiting for the slowest website on the internet. Respectfully.",
            "Lining up the findings from most to least alarming.",
        };

        // Script section name (prefix) -> friendly text and progress range
        static readonly string[][] Steps = {
            new[] { "System, BIOS",            "Reading the motherboard and BIOS",                                   "0",  "4" },
            new[] { "CPU, memory",             "Checking processor, memory, graphics and disks",                    "4",  "8" },
            new[] { "Devices and drivers",     "Listing every device and its driver",                                 "8",  "18" },
            new[] { "Windows version",         "Checking the Windows version and upgrade history",                   "18", "20" },
            new[] { "Windows Update history",  "Reading the Windows Update history",                                 "20", "24" },
            new[] { "Searching Windows Update","Asking Windows Update what it's offering (can take a few minutes)",  "24", "44" },
            new[] { "Event logs",              "Scanning event logs for driver and hardware errors",                 "44", "54" },
            new[] { "Crashes",                 "Looking for blue screens and crash dumps",                           "54", "56" },
            new[] { "Driver install log",      "Reading the driver install log",                                     "56", "59" },
            new[] { "Servicing",               "Checking servicing and Windows upgrade logs",                        "59", "62" },
            new[] { "Reliability",             "Reading 12 months of reliability history",                           "62", "67" },
            new[] { "Online:",                 "Checking manufacturers' websites for BIOS and driver updates",       "67", "76" },
            new[] { "Building findings",       "Putting the findings together",                                      "97", "99" },
            new[] { "Writing report",          "Writing the report",                                                 "99", "100" },
        };

        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);

        public MainForm(string[] args)
        {
            passArgs = args.Where(a => Regex.IsMatch(a, @"^-?[A-Za-z0-9_\.]+$")).ToArray();
            Text = "PCDoc";
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            BackColor = Theme.Bg; ForeColor = Theme.Text;
            Font = Theme.F(Theme.TextFace, 9.75f);
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new SizeF(96f, 96f);
            Size = new Size(1220, 820); MinimumSize = new Size(900, 600);
            BuildUi();
            timer = new Timer { Interval = 33 };
            timer.Tick += OnTick;
            Shown += (s, e) => StartScan();
            FormClosing += OnClosingForm;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            int on = 1;
            try { if (DwmSetWindowAttribute(Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(Handle, 19, ref on, 4); } catch { }
        }

        // ------------------------------------------------------------------ UI
        void BuildUi()
        {
            SuspendLayout();
            header = new Panel { Dock = DockStyle.Top, Height = 72, BackColor = Theme.Rail };
            header.Paint += (s, e) => { using (Pen p = new Pen(Theme.LineSoft)) e.Graphics.DrawLine(p, 0, header.Height - 1, header.Width, header.Height - 1); };
            Logo logo = new Logo { Size = new Size(34, 34), Location = new Point(24, 19), BackColor = Theme.Rail };
            lblTitle = new Label { Text = "PCDoc", AutoSize = true, Location = new Point(68, 14), Font = Theme.F(Theme.Display, 15f, FontStyle.Bold), ForeColor = Theme.Text, BackColor = Theme.Rail };
            lblSub = new Label { Text = "Health scan of " + Environment.MachineName + ". The scan only reads; updates are installed only when you ask.", AutoSize = true, Location = new Point(70, 44), ForeColor = Theme.Muted, BackColor = Theme.Rail };
            header.Controls.AddRange(new Control[] { logo, lblTitle, lblSub });

            // ---- scan view ----
            scanView = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
            lblStep = new Label { AutoSize = false, Height = 40, Font = Theme.F(Theme.Display, 17f, FontStyle.Bold), ForeColor = Theme.Text, Text = "Getting ready…", AutoEllipsis = true };
            bar = new ProgressLine { Height = 8 };
            lblPct = new Label { AutoSize = true, ForeColor = Theme.Muted, Text = "0%" };
            lblTime = new Label { AutoSize = true, ForeColor = Theme.Faint, Text = "", TextAlign = ContentAlignment.TopRight };
            lblHumor = new Label { AutoSize = false, Height = 26, ForeColor = Theme.Muted, Font = Theme.F(Theme.TextFace, 10.5f, FontStyle.Italic), Text = "" };
            lblLogHead = new Label { AutoSize = true, ForeColor = Theme.Faint, Text = "Diagnostics" };
            log = new RichTextBox { ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = Theme.Sunk, ForeColor = Theme.Muted, Font = Theme.F(Theme.Mono, 9f), DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, WordWrap = true, TabStop = false };
            btnCancel = new FlatBtn("Cancel scan");
            btnCancel.Click += (s, e) => CancelScan();
            scanView.Controls.AddRange(new Control[] { lblStep, bar, lblPct, lblTime, lblHumor, lblLogHead, log, btnCancel });
            scanView.Resize += (s, e) => LayoutScan();

            // ---- result view ----
            resultView = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Visible = false };
            Panel bar2 = new Panel { Dock = DockStyle.Top, Height = 52, BackColor = Theme.Rail };
            bar2.Paint += (s, e) => { using (Pen p = new Pen(Theme.LineSoft)) e.Graphics.DrawLine(p, 0, bar2.Height - 1, bar2.Width, bar2.Height - 1); };
            lblResTitle = new Label { AutoSize = true, Location = new Point(24, 9), Font = Theme.F(Theme.TextFace, 10.5f, FontStyle.Bold), ForeColor = Theme.Text, BackColor = Theme.Rail, Text = "Report ready" };
            lblResPath = new Label { AutoSize = true, Location = new Point(24, 29), ForeColor = Theme.Faint, BackColor = Theme.Rail, Font = Theme.F(Theme.TextFace, 8.5f) };
            btnBrowser = new FlatBtn("Open in browser"); btnFolder = new FlatBtn("Open reports folder"); btnAgain = new FlatBtn("Scan again", true);
            btnBrowser.Click += (s, e) => { if (reportPath != null) Program.OpenExternal(reportPath); };
            btnFolder.Click += (s, e) => { if (outDir != null) Program.OpenExternal(outDir); };
            btnAgain.Click += (s, e) => StartScan();
            bar2.Controls.AddRange(new Control[] { lblResTitle, lblResPath, btnBrowser, btnFolder, btnAgain });
            bar2.Resize += (s, e) =>
            {
                int x = bar2.Width - 20;
                foreach (Control b in new Control[] { btnAgain, btnFolder, btnBrowser }) { x -= b.Width; b.Location = new Point(x, (bar2.Height - b.Height) / 2); x -= 8; }
            };
            webHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
            resultView.Controls.Add(webHost);
            resultView.Controls.Add(bar2);
            BuildActionStrip(resultView);

            // ---- error view ----
            errorView = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Visible = false };
            lblErr = new Label { AutoSize = false, Location = new Point(48, 48), Size = new Size(860, 200), ForeColor = Theme.Text, Font = Theme.F(Theme.TextFace, 11f) };
            btnErrAgain = new FlatBtn("Try again", true); btnErrLog = new FlatBtn("Open scan log");
            btnErrAgain.Location = new Point(48, 262); btnErrLog.Location = new Point(160, 262);
            btnErrAgain.Click += (s, e) => StartScan();
            btnErrLog.Click += (s, e) => { string p = SaveLog(); if (p != null) Program.OpenExternal(p); };
            errorView.Controls.AddRange(new Control[] { lblErr, btnErrAgain, btnErrLog });

            Controls.Add(scanView); Controls.Add(resultView); Controls.Add(errorView); Controls.Add(header);
            ResumeLayout();
        }

        void LayoutScan()
        {
            int w = Math.Min(860, scanView.ClientSize.Width - 96), x = (scanView.ClientSize.Width - w) / 2, y = Math.Max(36, scanView.ClientSize.Height / 12);
            lblStep.SetBounds(x, y, w, 40); y += 50;
            bar.SetBounds(x, y, w, 8); y += 18;
            lblPct.Location = new Point(x, y);
            lblTime.Location = new Point(x + w - lblTime.PreferredWidth, y); y += 34;
            lblHumor.SetBounds(x, y, w, 26); y += 52;
            lblLogHead.Location = new Point(x, y); y += 24;
            int bottom = scanView.ClientSize.Height - 32 - btnCancel.Height - 16;
            log.SetBounds(x, y, w, Math.Max(80, bottom - y));
            btnCancel.Location = new Point(x + w - btnCancel.Width, scanView.ClientSize.Height - 32 - btnCancel.Height);
        }

        void ShowView(Panel v)
        {
            scanView.Visible = v == scanView; resultView.Visible = v == resultView; errorView.Visible = v == errorView;
            if (v == scanView) LayoutScan();
        }

        // ------------------------------------------------------------------ scan
        void StartScan()
        {
            ShowView(scanView);
            log.Clear(); fullLog.Clear(); warnings = 0; reportPath = null; lastProblem = null;
            if (host != null) { host.Dispose(); host = null; }
            proc = null;
            target = 0; shown = 0; stepEnd = 4; bar.Value = 0; bar.Active = true;
            SetStep("Getting ready…", 0, 2);
            started = DateTime.Now; humorAt = DateTime.MinValue;
            btnCancel.Enabled = true;

            string template;
            try { template = Program.Extract("report-template.html", Path.Combine("app", "report-template.html")); }
            catch (Exception ex) { ShowError("Could not prepare the report template in " + Program.AppDir + ".\n\n" + ex.Message); return; }

            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            outDir = Path.Combine(docs, "PCDoc reports", Environment.MachineName + "_" + DateTime.Now.ToString("yyyy-MM-dd_HHmmss"));
            AppendLog("PCDoc " + Program.Version + " - reports folder: " + outDir, Theme.Faint);

            // Script parameters: fixed ones plus anything passed on the PCDoc.exe command line (-Name [value])
            List<KeyValuePair<string, object>> pars = new List<KeyValuePair<string, object>>();
            pars.Add(new KeyValuePair<string, object>("NoOpen", null));
            pars.Add(new KeyValuePair<string, object>("OutputDir", outDir));
            pars.Add(new KeyValuePair<string, object>("TemplatePath", template));
            bool noWu = false;
            for (int i = 0; i < passArgs.Length; i++)
            {
                if (!passArgs[i].StartsWith("-")) continue;
                string name = passArgs[i].TrimStart('-');
                if (name.Equals("NoWindowsUpdate", StringComparison.OrdinalIgnoreCase) || name.Equals("Offline", StringComparison.OrdinalIgnoreCase)) noWu = true;
                if (name.Equals("NoWindowsUpdate", StringComparison.OrdinalIgnoreCase)) continue;
                if (i + 1 < passArgs.Length && !passArgs[i + 1].StartsWith("-")) { pars.Add(new KeyValuePair<string, object>(name, passArgs[i + 1])); i++; }
                else pars.Add(new KeyValuePair<string, object>(name, null));
            }
            if (!noWu) pars.Add(new KeyValuePair<string, object>("CheckWindowsUpdate", null));

            string testCmd = Environment.GetEnvironmentVariable("PCDOC_TEST_CMD");
            if (string.IsNullOrEmpty(testCmd) && ScriptHost.IsAvailable())
            {
                // Normal path: run the scan inside this process with Windows' own PowerShell engine.
                try
                {
                    string scriptText = Program.ReadResourceText("Invoke-PCDoc.ps1");
                    host = new ScriptHost();
                    host.Start(scriptText, pars, Path.Combine(Program.AppDir, "app"));
                }
                catch (Exception ex) { ShowError("The PowerShell engine built into Windows could not be started.\n\n" + ex.Message); return; }
                timer.Start();
                return;
            }

            // Fallback (or test hook): run as a separate process
            ProcessStartInfo psi;
            if (!string.IsNullOrEmpty(testCmd)) psi = new ProcessStartInfo(testCmd, Environment.GetEnvironmentVariable("PCDOC_TEST_ARGS") ?? "");
            else
            {
                string script = Program.Extract("Invoke-PCDoc.ps1", Path.Combine("app", "Invoke-PCDoc.ps1"));
                StringBuilder a = new StringBuilder("-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File \"" + script + "\"");
                foreach (KeyValuePair<string, object> kv in pars) { a.Append(" -" + kv.Key); if (kv.Value != null) a.Append(" \"" + kv.Value + "\""); }
                psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), a.ToString());
            }
            psi.UseShellExecute = false; psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8; psi.StandardErrorEncoding = Encoding.UTF8;
            psi.WorkingDirectory = Path.Combine(Program.AppDir, "app");
            try
            {
                proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
                proc.OutputDataReceived += (s, e) => { if (e.Data != null) BeginInvokeSafe(() => OnLine(e.Data, false)); };
                proc.ErrorDataReceived += (s, e) => { if (e.Data != null) BeginInvokeSafe(() => OnLine(e.Data, true)); };
                proc.Exited += (s, e) => BeginInvokeSafe(OnExited);
                proc.Start();
                proc.BeginOutputReadLine(); proc.BeginErrorReadLine();
            }
            catch (Exception ex) { ShowError("Windows PowerShell could not be started.\n\n" + ex.Message); return; }
            timer.Start();
        }

        void BeginInvokeSafe(Action a) { try { if (!IsDisposed && IsHandleCreated) BeginInvoke(a); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { } }

        void SetStep(string text, float start, float end)
        {
            lblStep.Text = text;
            target = Math.Max(target, start); stepEnd = Math.Max(end, target);
        }

        void OnLine(string line, bool isErr)
        {
            fullLog.AppendLine(line);
            string t = line.Trim();
            if (t.Length == 0) return;
            Match m;
            if (t.StartsWith("[*]"))
            {
                string name = t.Substring(3).Trim();
                foreach (string[] s in Steps)
                    if (name.StartsWith(s[0], StringComparison.OrdinalIgnoreCase)) { SetStep(s[1], float.Parse(s[2]), float.Parse(s[3])); break; }
                AppendLog(name, Theme.Accent);
            }
            else if ((m = Regex.Match(t, @"MS Catalog (\d+)/(\d+):\s*(.*)$")).Success)
            {
                float i = float.Parse(m.Groups[1].Value), n = Math.Max(1, float.Parse(m.Groups[2].Value));
                SetStep("Checking the Microsoft Update Catalog (" + m.Groups[1].Value + " of " + m.Groups[2].Value + ")", 76 + 20 * (i - 1) / n, 76 + 20 * i / n);
                AppendLog("  Catalog: " + m.Groups[3].Value, Theme.Muted);
            }
            else if (t.StartsWith("[!]") || t.StartsWith("[lookup]") || isErr)
            {
                warnings++; lastProblem = t;
                AppendLog("  " + t, Theme.Med);
            }
            else if ((m = Regex.Match(t, @"^Report:\s*(.+\.html)\s*$")).Success)
            {
                reportPath = m.Groups[1].Value.Trim();
                AppendLog(t, Theme.Ok);
            }
            else if (t.StartsWith("Findings:")) AppendLog(t, Theme.Text);
            else AppendLog("  " + t, Theme.Muted);
        }

        void AppendLog(string text, Color c)
        {
            log.SelectionStart = log.TextLength; log.SelectionLength = 0; log.SelectionColor = c;
            log.AppendText(text + Environment.NewLine);
            log.SelectionColor = log.ForeColor;
            log.ScrollToCaret();
        }

        void OnTick(object sender, EventArgs e)
        {
            if (host != null && ++pollTick % 4 == 0)
            {
                bool done = false;
                try { done = host.Poll(OnLine); }
                catch (Exception ex) { OnLine("Internal error while reading scan output: " + ex.Message, true); done = true; }
                if (done) { OnExited(); return; }
            }
            // creep towards the end of the current step, never reaching it until the next step starts
            float cap = Math.Max(target, stepEnd - 0.6f);
            target = Math.Min(cap, target + (cap - target) * 0.004f + 0.003f);
            shown += (target - shown) * 0.12f;
            bar.Value = shown; bar.Tick();
            lblPct.Text = ((int)Math.Floor(shown)) + "%";
            TimeSpan el = DateTime.Now - started;
            lblTime.Text = string.Format("{0}:{1:00} elapsed{2}", (int)el.TotalMinutes, el.Seconds, warnings > 0 ? "  ·  " + warnings + " note" + (warnings == 1 ? "" : "s") : "");
            lblTime.Left = lblStep.Left + lblStep.Width - lblTime.PreferredWidth;
            if ((DateTime.Now - humorAt).TotalSeconds > 5.5)
            {
                int next; do { next = rnd.Next(Humor.Length); } while (next == humorIdx && Humor.Length > 1);
                humorIdx = next; lblHumor.Text = Humor[next]; humorAt = DateTime.Now;
            }
        }

        void OnExited()
        {
            timer.Stop(); bar.Active = false;
            if (closingAfterKill) return;
            int code = 0; try { if (proc != null) code = proc.ExitCode; } catch { }
            string failure = host != null ? host.FailureMessage : null;
            if (failure != null) { lastProblem = failure; fullLog.AppendLine("FAILED: " + failure); }
            SaveLog();
            if (reportPath != null && File.Exists(reportPath))
            {
                target = shown = 100; bar.Value = 100; lblPct.Text = "100%";
                ShowResults();
            }
            else ShowError("The scan stopped before the report was written" + (proc != null ? " (exit code " + code + ")" : "") + ".\n\n" +
                (lastProblem != null ? "Last message: " + lastProblem + "\n\n" : "") +
                "The scan log shows the last step it reached. Open it, or try again. Running it a second time often gets past a slow website or a busy Windows Update service.");
        }

        string SaveLog()
        {
            try
            {
                string dir = (outDir != null && Directory.Exists(outDir)) ? outDir : Program.AppDir;
                string p = Path.Combine(dir, "scan-log.txt");
                File.WriteAllText(p, fullLog.ToString(), Encoding.UTF8); return p;
            }
            catch { return null; }
        }

        void CancelScan()
        {
            if (host != null) { btnCancel.Enabled = false; lblStep.Text = "Stopping…"; closingAfterKill = true; host.Stop(); Close(); return; }
            if (proc == null || proc.HasExited) { Close(); return; }
            btnCancel.Enabled = false; lblStep.Text = "Stopping…";
            KillTree();
            closingAfterKill = true;
            Close();
        }

        void KillTree()
        {
            try
            {
                if (proc != null && !proc.HasExited)
                {
                    Process k = Process.Start(new ProcessStartInfo("taskkill.exe", "/T /F /PID " + proc.Id) { CreateNoWindow = true, UseShellExecute = false });
                    if (k != null) k.WaitForExit(5000);
                    if (!proc.HasExited) proc.Kill();
                }
            }
            catch { try { proc.Kill(); } catch { } }
        }

        void OnClosingForm(object sender, FormClosingEventArgs e)
        {
            StopAction();
            if (host != null) { closingAfterKill = true; try { host.Stop(); } catch { } }
            if (proc != null) { try { if (!proc.HasExited) { closingAfterKill = true; KillTree(); } } catch { } }
        }

        void ShowError(string msg)
        {
            timer.Stop();
            lblErr.Text = msg;
            ShowView(errorView);
        }

        // ------------------------------------------------------------------ results
        void ShowResults()
        {
            lblResTitle.Text = "Report ready for " + Environment.MachineName + (warnings > 0 ? ". The scan logged " + warnings + " note" + (warnings == 1 ? "" : "s") + " (see Scan notes and Lookup problems in the report)." : "");
            lblResPath.Text = reportPath;
            outDir = Path.GetDirectoryName(reportPath);
            ShowView(resultView);
            ResetActionStrip();
            string testPost = Environment.GetEnvironmentVariable("PCDOC_TEST_POST");   // test hook: simulate a click in the report
            if (!string.IsNullOrEmpty(testPost)) { Timer t = new Timer { Interval = 1500 }; t.Tick += (s, e) => { t.Stop(); OnWebMessage(testPost); }; t.Start(); }
            ShowInWebView();
        }

        async void ShowInWebView()
        {
            string err = null;
            try
            {
                if (web == null) web = await WebViewHost.Create(webHost, OnWebMessage);
                WebViewHost.Navigate(web, reportPath);
                return;
            }
            catch (Exception ex) { err = ex.GetType().Name + ": " + ex.Message; }

            // WebView2 runtime missing or failed: show the report in Edge's app window, or the default browser
            webHost.Controls.Clear();
            Label note = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Theme.Muted, Font = Theme.F(Theme.TextFace, 11f),
                Text = "The report opened in a separate window.\n\nThe built-in viewer needs the Microsoft Edge WebView2 Runtime, which isn't available on this PC.\n(" + err + ")"
            };
            webHost.Controls.Add(note);
            OpenReportStandalone();
        }

        void OpenReportStandalone()
        {
            string[] edges = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe") };
            string edge = edges.FirstOrDefault(File.Exists);
            try
            {
                if (edge != null) { Process.Start(new ProcessStartInfo(edge, "--app=\"" + new Uri(reportPath).AbsoluteUri + "\"") { UseShellExecute = false }); return; }
            }
            catch { }
            Program.OpenExternal(reportPath);
        }
    }

    /// <summary>All WebView2 usage lives here so the WebView2 assemblies load only when the report is shown.</summary>
    static class WebViewHost
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static async Task<Control> Create(Panel host, Action<string> onMessage)
        {
            string arch = (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? "").Equals("ARM64", StringComparison.OrdinalIgnoreCase) ? "arm64"
                        : Environment.Is64BitProcess ? "x64" : "x86";
            string loader = Program.Extract("bin." + arch + ".WebView2Loader.dll", Path.Combine("bin", arch, "WebView2Loader.dll"));
            Program.Extract("bin.Microsoft.Web.WebView2.Core.dll", Path.Combine("bin", "Microsoft.Web.WebView2.Core.dll"));
            Program.Extract("bin.Microsoft.Web.WebView2.WinForms.dll", Path.Combine("bin", "Microsoft.Web.WebView2.WinForms.dll"));
            return await CreateCore(host, Path.GetDirectoryName(loader), onMessage);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static async Task<Control> CreateCore(Panel host, string loaderDir, Action<string> onMessage)
        {
            Microsoft.Web.WebView2.Core.CoreWebView2Environment.SetLoaderDllFolderPath(loaderDir);
            string udf = Path.Combine(Program.AppDir, "WebView2");
            var env = await Microsoft.Web.WebView2.Core.CoreWebView2Environment.CreateAsync(null, udf);
            var wv = new Microsoft.Web.WebView2.WinForms.WebView2 { Dock = DockStyle.Fill, DefaultBackgroundColor = Theme.Bg };
            host.Controls.Clear(); host.Controls.Add(wv);
            await wv.EnsureCoreWebView2Async(env);
            var core = wv.CoreWebView2;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreDefaultContextMenusEnabled = true;
            core.Settings.IsWebMessageEnabled = true;
            // Messages from the report's buttons, only from the local report file
            core.WebMessageReceived += (s, e) =>
            {
                if (!e.Source.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) return;
                string m = null; try { m = e.TryGetWebMessageAsString(); } catch { }
                if (m != null) onMessage(m);
            };
            // Links to manufacturers / downloads open in the user's normal browser
            core.NewWindowRequested += (s, e) => { e.Handled = true; Program.OpenExternal(e.Uri); };
            core.NavigationStarting += (s, e) =>
            {
                if (!e.Uri.StartsWith("file:", StringComparison.OrdinalIgnoreCase) && !e.Uri.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
                { e.Cancel = true; Program.OpenExternal(e.Uri); }
            };
            return wv;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void Post(Control c, string msg)
        {
            var wv = (Microsoft.Web.WebView2.WinForms.WebView2)c;
            if (wv.CoreWebView2 != null) wv.CoreWebView2.PostWebMessageAsString(msg);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void Navigate(Control c, string path)
        {
            var wv = (Microsoft.Web.WebView2.WinForms.WebView2)c;
            wv.CoreWebView2.Navigate(new Uri(path).AbsoluteUri);
        }
    }
}
