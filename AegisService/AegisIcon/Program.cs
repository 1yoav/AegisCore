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

            // Run the invisible form that manages the tray icon
            Application.Run(new AegisTrayForm());
        }
    }

    // We use a Form instead of ApplicationContext. 
    // This fixes the issue where a "tab" appears in the taskbar when you click the menu.
    public class AegisTrayForm : Form
    {
        private NotifyIcon _trayIcon;
        private ContextMenuStrip _rightClickMenu;

        public AegisTrayForm()
        {

            //Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);


            // 1. Hide this "Dummy" Form completely
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Minimized;
            this.FormBorderStyle = FormBorderStyle.None;
            this.Opacity = 0; // Make it invisible just in case

            // 2. Initialize the Menu and Icon
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            // --- SETUP MENU ---
            _rightClickMenu = new ContextMenuStrip();

            // FIX: This line makes the menu look like standard Windows (white) instead of old .NET style
            _rightClickMenu.RenderMode = ToolStripRenderMode.Professional;


            // Add Menu Items
            _rightClickMenu.Items.Add("Settings", null, OnOpenSettings);
            _rightClickMenu.Items.Add("Manual Deepscan", null, OnManualScan);
            _rightClickMenu.Items.Add("-"); // Separator
            _rightClickMenu.Items.Add("Close Antivirus", null, OnExit);

            // --- SETUP TRAY ICON ---
            _trayIcon = new NotifyIcon();
            _trayIcon.Icon = new Icon("Dependencies/AegisCore_Icon.ico"); // Replace with new Icon("path_to_icon.ico") for custom
            _trayIcon.Text = "Aegis Antivirus - Protected";
            _trayIcon.ContextMenuStrip = _rightClickMenu; // Attach menu to right-click automatically
            _trayIcon.Visible = true;

            // Hook up MouseClick to handle Left Click separately
            _trayIcon.MouseClick += TrayIcon_MouseClick;
        }

        private void TrayIcon_MouseClick(object sender, MouseEventArgs e)
        {
            // FIX: Left click opens Settings immediately
            if (e.Button == MouseButtons.Left)
            {
                OnOpenSettings(null, null);
            }
        }

        private void OnOpenSettings(object sender, EventArgs e)
        {
            string settingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AegisSettings.exe");

            if (File.Exists(settingsPath))
            {
                Process.Start(settingsPath);
            }
            else
            {
                // Note: MessageBox might spawn a temporary taskbar icon while it is open. This is normal.
                MessageBox.Show("Settings GUI not implemented yet.", "Aegis Antivirus");
            }
        }

        private void OnManualScan(object sender, EventArgs e)
        {
            // Example of how to trigger a deep scan
            MessageBox.Show("Deep scan initiated...", "Aegis Antivirus");
        }

        private void OnExit(object sender, EventArgs e)
        {
            // Optional: Ask for confirmation or stop the service here
            DialogResult result = MessageBox.Show("Are you sure you want to stop the Aegis Service and Exit?",
                                                 "Warning", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                StopService(); // Helper method to stop the service

                _trayIcon.Visible = false; // Remove icon from tray
                Application.Exit();        // Kill the app
            }
        }

        private void StopService()
        {
            try
            {
                ServiceController sc = new ServiceController("AegisService");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped);
                }
            }
            catch { /* Ignore permission errors if not admin */ }
        }

        // This prevents the dummy form from ever actually showing up if you accidentally restore it
        protected override void SetVisibleCore(bool value)
        {
            // Always keep false unless we explicitly want to show this empty form (we don't)
            base.SetVisibleCore(value ? false : false);
        }
    }
}