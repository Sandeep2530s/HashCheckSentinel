using System;
using System.IO;
using System.Windows.Forms;

namespace HashCheckSentinel
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                LogCrash(e.ExceptionObject != null ? e.ExceptionObject.ToString() : "Unknown AppDomain UnhandledException");
            };

            Application.ThreadException += (s, e) =>
            {
                LogCrash(e.Exception != null ? e.Exception.ToString() : "Unknown Application ThreadException");
            };

            try
            {
                LogCrash("START: Program.Main");
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                var form = new MainForm();
                LogCrash("MainForm instantiated.");
                Application.Run(form);
                LogCrash("Application.Run exited normally.");
            }
            catch (Exception ex)
            {
                LogCrash("EXCEPTION: " + ex.ToString());
                MessageBox.Show(ex.ToString(), "Startup Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static void LogCrash(string msg)
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_error.log");
                File.AppendAllText(path, $"[{DateTime.UtcNow:O}] {msg}\r\n\r\n");
            }
            catch { }
        }
    }
}
