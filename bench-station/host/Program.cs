// Obligarth bench station: the window (see ObligarthBenchWindow.csproj).
//
//   obligarth-bench-window.exe --url http://127.0.0.1:<port>/?t=<token> --data <WebView2 user data folder>
//
// Shows the page of the local server of the station, and nothing else: a navigation outside that origin is refused
// (an https link the technician clicks opens in their browser), a new window is refused, no developer tools, no zoom keys, no status bar, no autofill, no password offer, and the
// context menu keeps only cut, copy, paste and select all. Exit codes: 0 the window was closed, 2 bad arguments,
// 3 no WebView2 runtime (the station then falls back to Edge), 4 WebView2 could not start. A line "focus" on the
// standard input brings the window to the front (the station sends it when it is asked to open again).
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ObligarthBench
{
    internal static class Program
    {
        internal const string Title = "Obligarth Bench";

        [STAThread]
        private static int Main(string[] args)
        {
            string url = null, data = null;
            for (int i = 0; i + 1 < args.Length; i++)
            {
                if (args[i] == "--url") url = args[i + 1];
                else if (args[i] == "--data") data = args[i + 1];
            }
            Uri start;
            if (url == null || data == null || !Uri.TryCreate(url, UriKind.Absolute, out start)
                || start.Scheme != Uri.UriSchemeHttp || start.Host != "127.0.0.1" || start.IsDefaultPort)
                return 2;

            string runtime = null;
            try { runtime = CoreWebView2Environment.GetAvailableBrowserVersionString(); } catch { runtime = null; }
            if (string.IsNullOrEmpty(runtime)) return 3;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var form = new HostForm(start, data);
            Application.Run(form);
            return form.ExitCode;
        }
    }

    internal sealed class HostForm : Form
    {
        private static readonly HashSet<string> KeptMenuItems = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cut", "copy", "paste", "selectAll", "pasteAndMatchStyle", "spellCheck", "other",
        };

        private readonly WebView2 web = new WebView2();
        private readonly Uri start;
        private readonly string data;
        internal int ExitCode;

        internal HostForm(Uri start, string data)
        {
            this.start = start;
            this.data = data;
            Text = Program.Title;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { /* the default icon */ }
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ClientSize = new Size(1200, 860);
            MinimumSize = new Size(800, 560);
            StartPosition = FormStartPosition.CenterScreen;
            web.Dock = DockStyle.Fill;
            web.DefaultBackgroundColor = SystemColors.Window;
            Controls.Add(web);
            Load += async (s, e) => await StartWebView();

            var reader = new Thread(ReadCommands) { IsBackground = true, Name = "stdin" };
            reader.Start();
        }

        private async System.Threading.Tasks.Task StartWebView()
        {
            try
            {
                // The page beeps when a card needs the technician, possibly before anybody clicked in the window.
                var options = new CoreWebView2EnvironmentOptions("--autoplay-policy=no-user-gesture-required");
                var env = await CoreWebView2Environment.CreateAsync(null, data, options);
                await web.EnsureCoreWebView2Async(env);
                var core = web.CoreWebView2;
                var settings = core.Settings;
                settings.AreDevToolsEnabled = false;
                settings.IsStatusBarEnabled = false;
                settings.IsZoomControlEnabled = false;
                settings.AreBrowserAcceleratorKeysEnabled = false;
                settings.IsPasswordAutosaveEnabled = false;
                settings.IsGeneralAutofillEnabled = false;
                settings.AreHostObjectsAllowed = false;
                settings.IsWebMessageEnabled = false;
                settings.AreDefaultContextMenusEnabled = true;
                core.ContextMenuRequested += (o, a) =>
                {
                    var items = a.MenuItems;
                    for (int i = items.Count - 1; i >= 0; i--)
                        if (!KeptMenuItems.Contains(items[i].Name)) items.RemoveAt(i);
                    // Separators left at the ends or doubled are dropped too.
                    for (int i = items.Count - 1; i >= 0; i--)
                        if (items[i].Kind == CoreWebView2ContextMenuItemKind.Separator
                            && (i == 0 || i == items.Count - 1 || items[i - 1].Kind == CoreWebView2ContextMenuItemKind.Separator))
                            items.RemoveAt(i);
                    if (items.Count == 0) a.Handled = true;
                };
                core.DocumentTitleChanged += (o, a) =>
                {
                    var title = core.DocumentTitle;
                    Text = string.IsNullOrWhiteSpace(title) ? Program.Title : title;
                };
                // Never leaves the page of the station. A link the technician clicks to an https page (a licence, a
                // help page) opens in their browser, not here.
                core.NavigationStarting += (o, a) =>
                {
                    if (SameOrigin(a.Uri)) return;
                    a.Cancel = true;
                    if (a.IsUserInitiated) OpenOutside(a.Uri);
                };
                core.FrameNavigationStarting += (o, a) => { if (!SameOrigin(a.Uri)) a.Cancel = true; };
                core.NewWindowRequested += (o, a) =>
                {
                    a.Handled = true;
                    if (a.IsUserInitiated && !SameOrigin(a.Uri)) OpenOutside(a.Uri);
                };
                core.DownloadStarting += (o, a) => { a.Cancel = true; };
                core.PermissionRequested += (o, a) => { a.State = CoreWebView2PermissionState.Deny; };
                core.Navigate(start.AbsoluteUri);
            }
            catch (Exception ex)
            {
                ExitCode = 4;
                MessageBox.Show(this, "The window of the station could not start.\n\n" + ex.Message, Program.Title,
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close();
            }
        }

        private bool SameOrigin(string uri)
        {
            Uri u;
            return Uri.TryCreate(uri, UriKind.Absolute, out u) && u.Scheme == start.Scheme && u.Host == start.Host && u.Port == start.Port;
        }

        private static void OpenOutside(string uri)
        {
            Uri u;
            if (!Uri.TryCreate(uri, UriKind.Absolute, out u) || u.Scheme != Uri.UriSchemeHttps) return;
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); }
            catch { /* no browser: nothing */ }
        }

        private void ReadCommands()
        {
            try
            {
                string line;
                while ((line = Console.In.ReadLine()) != null)
                {
                    if (line.Trim() == "focus" && IsHandleCreated) BeginInvoke((Action)BringToFront);
                }
            }
            catch
            {
                // No standard input: nothing to read.
            }
        }

        private new void BringToFront()
        {
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Show();
            Activate();
            TopMost = true;
            TopMost = false;
        }
    }
}
