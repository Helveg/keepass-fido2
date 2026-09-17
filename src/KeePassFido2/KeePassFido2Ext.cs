using System;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassFido2.Agent;
using KeePassFido2.Storage;
using KeePassFido2.UI;
using KeePassFido2.Unlock;
using KeePassLib.Native;
using KeePassLib.Utility;

namespace KeePassFido2
{
    public sealed class KeePassFido2Ext : Plugin
    {
        private const string Title = "KeePass FIDO2";
        private const string AutoStartConfigKey = "KeePassFido2.AutoStartPreferredMethod";

        private IPluginHost _host;
        private UnlockService _service;
        private KeyPromptIntegration _keyPrompt;
        private SecretBroker _broker;
        private SecretServer _server;

        public override string UpdateUrl => "https://raw.githubusercontent.com/Helveg/keepass-fido2/main/version.txt";

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            if (NativeLib.IsUnix())
            {
                MessageService.ShowWarning(Title + " works only on Windows: it relies on Windows Hello and Windows' security key API.",
                    "The plugin is disabled. Remove KeePassFido2.dll from the Plugins folder to stop this message.");
                return false;
            }
            _host = host;
            _service = new UnlockService(new UnlockStore(UnlockStore.DefaultFilePath));
            _keyPrompt = new KeyPromptIntegration(_service, () => _host.CustomConfig.GetBool(AutoStartConfigKey, false));

            GlobalWindowManager.WindowAdded += OnWindowAdded;
            _host.MainWindow.FileOpened += OnFileOpened;
            _host.MainWindow.FileClosed += OnFileClosed;

            _broker = new SecretBroker(_host, _service);
            _server = new SecretServer(_broker.Handle);
            _server.Start();
            return true;
        }

        public override void Terminate()
        {
            _server?.Dispose();
            GlobalWindowManager.WindowAdded -= OnWindowAdded;
            if (_host == null) return;
            _host.MainWindow.FileOpened -= OnFileOpened;
            _host.MainWindow.FileClosed -= OnFileClosed;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType type)
        {
            if (type != PluginMenuType.Main) return null;

            var root = new ToolStripMenuItem(Title);
            var manage = new ToolStripMenuItem("Manage unlock methods for this database...", null,
                (s, e) => ManageMethodsDialog.Show(_host.MainWindow, _service, _host.Database));
            var autoStart = new ToolStripMenuItem("Start Windows Hello automatically when unlocking") { CheckOnClick = true };
            autoStart.CheckedChanged += (s, e) => _host.CustomConfig.SetBool(AutoStartConfigKey, autoStart.Checked);

            root.DropDownItems.AddRange(new ToolStripItem[] { manage, new ToolStripSeparator(), autoStart });
            root.DropDownOpening += (s, e) =>
            {
                manage.Enabled = _host.Database != null && _host.Database.IsOpen;
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
            if (e.Database?.IOConnectionInfo == null) return;
            try
            {
                _service.OnDatabaseOpened(e.Database);
            }
            catch (Exception ex)
            {
                MessageBox.Show(_host.MainWindow, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void OnFileClosed(object sender, FileClosedEventArgs e)
        {
            if (e.IOConnectionInfo != null)
                _service.OnDatabaseClosed(e.IOConnectionInfo.Path);
            _broker?.ForgetApprovals();
        }
    }
}
