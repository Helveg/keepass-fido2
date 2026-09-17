using System;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassFido2.Storage;
using KeePassFido2.UI;
using KeePassFido2.Unlock;
using KeePassLib;

namespace KeePassFido2
{
    public sealed class KeePassFido2Ext : Plugin
    {
        private const string Title = "KeePass FIDO2";
        private const string AutoStartConfigKey = "KeePassFido2.AutoStartPreferredMethod";

        private IPluginHost _host;
        private UnlockService _service;
        private KeyPromptIntegration _keyPrompt;

        public override string UpdateUrl => "https://raw.githubusercontent.com/Helveg/keepass-fido2/main/version.txt";

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            _host = host;
            _service = new UnlockService(new UnlockStore(UnlockStore.DefaultFilePath));
            _keyPrompt = new KeyPromptIntegration(_service, () => _host.CustomConfig.GetBool(AutoStartConfigKey, false));

            GlobalWindowManager.WindowAdded += OnWindowAdded;
            _host.MainWindow.FileOpened += OnFileOpened;
            _host.MainWindow.FileClosed += OnFileClosed;
            return true;
        }

        public override void Terminate()
        {
            GlobalWindowManager.WindowAdded -= OnWindowAdded;
            if (_host == null) return;
            _host.MainWindow.FileOpened -= OnFileOpened;
            _host.MainWindow.FileClosed -= OnFileClosed;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType type)
        {
            if (type != PluginMenuType.Main) return null;

            var root = new ToolStripMenuItem(Title);
            var addHello = new ToolStripMenuItem("Add Windows Hello unlock for this database", null,
                (s, e) => RunForOpenDatabase((hwnd, db) =>
                {
                    _service.AddWindowsHello(hwnd, db);
                    return "Windows Hello unlock was added.";
                }));
            var addKey = new ToolStripMenuItem("Add security key unlock for this database...", null, (s, e) => AddSecurityKey());
            var show = new ToolStripMenuItem("Show unlock methods for this database", null, (s, e) => ShowMethods());
            var removeAll = new ToolStripMenuItem("Remove all unlock methods for this database...", null, (s, e) => RemoveAll());
            var autoStart = new ToolStripMenuItem("Start Windows Hello automatically when unlocking") { CheckOnClick = true };
            autoStart.CheckedChanged += (s, e) => _host.CustomConfig.SetBool(AutoStartConfigKey, autoStart.Checked);

            root.DropDownItems.AddRange(new ToolStripItem[] { addHello, addKey, new ToolStripSeparator(), show, removeAll, new ToolStripSeparator(), autoStart });
            root.DropDownOpening += (s, e) =>
            {
                bool open = _host.Database != null && _host.Database.IsOpen;
                addHello.Enabled = open && WindowsHelloAuthenticator.IsAvailable;
                addKey.Enabled = open && Fido2Authenticator.IsAvailable;
                show.Enabled = open;
                removeAll.Enabled = open && _service.GetMethods(_host.Database.IOConnectionInfo.Path).Count > 0;
                autoStart.Checked = _host.CustomConfig.GetBool(AutoStartConfigKey, false);
            };
            return root;
        }

        private void OnWindowAdded(object sender, GwmWindowEventArgs e)
        {
            if (e.Form is KeyPromptForm keyPrompt)
                _keyPrompt.Attach(keyPrompt);
        }

        private void OnFileOpened(object sender, FileOpenedEventArgs e)
        {
            if (e.Database?.IOConnectionInfo != null)
                Guard(() => _service.OnDatabaseOpened(e.Database));
        }

        private void OnFileClosed(object sender, FileClosedEventArgs e)
        {
            if (e.IOConnectionInfo != null)
                _service.OnDatabaseClosed(e.IOConnectionInfo.Path);
        }

        private void AddSecurityKey()
        {
            if (!AddSecurityKeyDialog.Ask(_host.MainWindow, out bool requirePin)) return;

            RunForOpenDatabase((hwnd, db) =>
            {
                UnlockMethod method = _service.AddSecurityKey(hwnd, db, requirePin);
                string message = $"{method.Label} was added ({DescribeMode(method)}).";
                if (!requirePin && method.RequiresPin)
                    message += Environment.NewLine + Environment.NewLine +
                        "Windows asked for the key's PIN anyway because a PIN is set on it, so this key unlocks with PIN + touch.";
                return message;
            });
        }

        /// <param name="action">Runs off the UI thread and returns the success message.</param>
        private void RunForOpenDatabase(Func<IntPtr, PwDatabase, string> action)
        {
            PwDatabase database = _host.Database;
            Form owner = _host.MainWindow;
            IntPtr hwnd = owner.Handle;
            try
            {
                string successMessage = BackgroundCall.Run(() => action(hwnd, database));
                MessageBox.Show(owner, successMessage + Environment.NewLine + Environment.NewLine +
                    "Lock the workspace to try it out. The master key keeps working as a fallback.",
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (UnlockCancelledException)
            {
            }
            catch (Exception ex)
            {
                MessageBox.Show(owner, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ShowMethods()
        {
            var methods = _service.GetMethods(_host.Database.IOConnectionInfo.Path);
            var text = new StringBuilder();
            if (methods.Count == 0)
                text.Append("No unlock methods are set up for this database.");
            foreach (UnlockMethod method in methods.OrderBy(m => m.CreatedUtc))
                text.AppendLine($"{method.Label}: {DescribeMode(method)}, added {method.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm}");
            MessageBox.Show(_host.MainWindow, text.ToString(), Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string DescribeMode(UnlockMethod method) =>
            method.Kind == UnlockMethodKind.WindowsHello ? "face, fingerprint or Hello PIN"
            : method.RequiresPin ? "PIN + touch"
            : "touch only";

        private void RemoveAll()
        {
            string path = _host.Database.IOConnectionInfo.Path;
            if (MessageBox.Show(_host.MainWindow,
                    "Remove Windows Hello and all security keys as unlock methods for this database?" + Environment.NewLine + Environment.NewLine +
                    "The master key is not affected. Credentials stay on your security keys until you delete them there.",
                    Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;
            Guard(() => _service.RemoveAll(path));
        }

        private void Guard(Action action)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                MessageBox.Show(_host.MainWindow, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
