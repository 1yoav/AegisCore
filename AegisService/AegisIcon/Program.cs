using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.ServiceProcess;
using System.Windows.Forms;

namespace AegisTray
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new AegisTrayForm());
        }
    }

    public class AegisTrayForm : Form
    {
        private NotifyIcon _trayIcon;
        private ContextMenuStrip _rightClickMenu;

        // Navigate from AegisIcon\bin\Debug\ up 4 levels to AegisCore install root
        private static readonly string InstallRoot = Path.GetFullPath(
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..\..")
        );

        public AegisTrayForm()
        {
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Minimized;
            this.FormBorderStyle = FormBorderStyle.None;
            this.Opacity = 0;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            // ── Menu ──────────────────────────────────────────────────
            _rightClickMenu = new ContextMenuStrip();
            _rightClickMenu.RenderMode = ToolStripRenderMode.System;

            _rightClickMenu.Items.Add("Open AegisCore", null, OnOpenSettings);
            _rightClickMenu.Items.Add("Manual Scan", null, OnManualScan);
            _rightClickMenu.Items.Add("-");
            _rightClickMenu.Items.Add("Close Antivirus", null, OnExit);

            // ── Tray icon ─────────────────────────────────────────────
            _trayIcon = new NotifyIcon();

            // Fixed: use absolute path via InstallRoot instead of bare relative path
            string iconPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Dependencies",
                "AegisCore_Icon.ico"
            );

            try
            {
                _trayIcon.Icon = new Icon(iconPath);
            }
            catch
            {
                // Fallback so tray still appears even if icon file is missing
                _trayIcon.Icon = SystemIcons.Shield;
            }

            _trayIcon.Text = "AegisCore — Protected";
            _trayIcon.ContextMenuStrip = _rightClickMenu;
            _trayIcon.Visible = true;
            _trayIcon.MouseClick += TrayIcon_MouseClick;
        }

        private void TrayIcon_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
                OnOpenSettings(null, null);
        }

        // ── Open Electron GUI ─────────────────────────────────────────
        private void OnOpenSettings(object sender, EventArgs e)
        {
            string guiPath = Path.Combine(
                InstallRoot, "gui", "dist", "win-unpacked", "AegisCore.exe"
            );

            if (File.Exists(guiPath))
            {
                try { Process.Start(guiPath); }
                catch (Exception ex)
                {
                    MessageBox.Show("Failed to launch AegisCore GUI:\n" + ex.Message,
                                    "AegisCore", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                MessageBox.Show("AegisCore GUI not found at:\n" + guiPath,
                                "AegisCore", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void OnManualScan(object sender, EventArgs e)
        {
            // Opens the GUI — user can navigate to manual scan from there
            OnOpenSettings(sender, e);
        }

        // ── Exit: kill everything then quit ──────────────────────────
        private void OnExit(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show(
                "Are you sure you want to stop AegisCore protection and exit?",
                "AegisCore — Warning",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes) return;

            // 1. Kill all AegisCore processes
            KillAegisProcesses();

            // 2. Stop the Windows service
            StopAegisService();

            // 3. Remove tray icon and exit
            _trayIcon.Visible = false;
            Application.Exit();
        }

        // Kills every process belonging to AegisCore
        private void KillAegisProcesses()
        {
            string[] targets = new[]
            {
                "aegiscore",        // main C++ engine
                "MainProcces",      // hooking engine
                "AegisCore",        // Electron GUI
                "main",             // deep analysis PyInstaller exe
                "virus_scanner",    // VT scanner PyInstaller exe
                "isolationForest",  // Python ML script (if running as process)
                "tlscheck2",
            };

            foreach (string name in targets)
            {
                try
                {
                    foreach (Process p in Process.GetProcessesByName(name))
                    {
                        p.Kill();
                        p.WaitForExit(3000);
                    }
                }
                catch { /* ignore — process may have already exited */ }
            }
        }

        private void StopAegisService()
        {
            // Try ServiceController first (works if already elevated)
            try
            {
                ServiceController sc = new ServiceController("AegisService");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    return;
                }
            }
            catch { }

            // Fallback: sc.exe with UAC elevation prompt
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = "stop AegisService",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });
            }
            catch { }
        }

        protected override void SetVisibleCore(bool value)
        {
            base.SetVisibleCore(false);
        }
    }
}