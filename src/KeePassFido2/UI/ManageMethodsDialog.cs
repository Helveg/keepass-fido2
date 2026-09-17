using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using KeePassFido2.Storage;
using KeePassFido2.Unlock;
using KeePassLib;

namespace KeePassFido2.UI
{
    /// <summary>Lists, adds, renames and removes the unlock methods of one open database.</summary>
    internal sealed class ManageMethodsDialog : Form
    {
        private const string Title = "KeePass FIDO2";

        private readonly UnlockService _service;
        private readonly PwDatabase _database;
        private readonly string _path;
        private readonly ListView _list;
        private readonly Button _rename;
        private readonly Button _remove;
        private readonly Button _addHello;
        private readonly Button _addKey;

        private ManageMethodsDialog(UnlockService service, PwDatabase database)
        {
            _service = service;
            _database = database;
            _path = database.IOConnectionInfo.Path;

            Text = "Unlock methods";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            ShowIcon = false;
            AutoScaleMode = AutoScaleMode.Font;
            Font = SystemFonts.MessageBoxFont;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);

            var layout = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Fill };

            var heading = new Label
            {
                Text = "Ways to unlock " + Path.GetFileName(_path) + " besides its master key:",
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 8),
            };
            layout.Controls.Add(heading);
            layout.SetColumnSpan(heading, 2);

            _list = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                HideSelection = false,
                LabelEdit = true,
                HeaderStyle = ColumnHeaderStyle.Nonclickable,
                Size = new Size(460, 180),
                Margin = new Padding(0, 0, 8, 0),
            };
            _list.Columns.Add("Name", 170);
            _list.Columns.Add("Unlocks with", 170);
            _list.Columns.Add("Added", 110);
            _list.SelectedIndexChanged += (s, e) => UpdateButtons();
            _list.AfterLabelEdit += OnAfterLabelEdit;
            _list.DoubleClick += (s, e) => BeginRename();
            _list.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.F2) BeginRename();
                if (e.KeyCode == Keys.Delete) Remove();
            };
            layout.Controls.Add(_list);

            var side = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Margin = new Padding(0), WrapContents = false };
            _addHello = SideButton(side, "Add Windows Hello", AddWindowsHello);
            _addKey = SideButton(side, "Add security key...", AddSecurityKey);
            side.Controls.Add(new Label { AutoSize = false, Height = 8 });
            _rename = SideButton(side, "Rename", BeginRename);
            _remove = SideButton(side, "Remove...", Remove);
            layout.Controls.Add(side);

            var note = new Label
            {
                Text = "Removing a method does not remove its credential from a security key. " +
                       "If a key was lost or stolen, also change the database's master key.",
                ForeColor = SystemColors.GrayText,
                AutoSize = true,
                MaximumSize = new Size(460, 0),
                Margin = new Padding(0, 8, 0, 8),
            };
            layout.Controls.Add(note);
            layout.SetColumnSpan(note, 2);

            var close = new Button { Text = "Close", DialogResult = DialogResult.Cancel, UseVisualStyleBackColor = true, Anchor = AnchorStyles.Right };
            layout.Controls.Add(close);
            layout.SetColumnSpan(close, 2);
            CancelButton = close;

            Controls.Add(layout);
            Reload(null);
        }

        public static void Show(IWin32Window owner, UnlockService service, PwDatabase database)
        {
            using (var dialog = new ManageMethodsDialog(service, database))
                dialog.ShowDialog(owner);
        }

        private Button SideButton(FlowLayoutPanel panel, string text, Action onClick)
        {
            var button = new Button { Text = text, AutoSize = true, MinimumSize = new Size(140, 0), UseVisualStyleBackColor = true, Margin = new Padding(0, 0, 0, 6) };
            button.Click += (s, e) => onClick();
            panel.Controls.Add(button);
            return button;
        }

        private void Reload(string selectId)
        {
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (UnlockMethod method in _service.GetMethods(_path).OrderBy(m => m.CreatedUtc))
            {
                var item = new ListViewItem(new[] { method.Label, DescribeMode(method), method.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm") }) { Tag = method };
                _list.Items.Add(item);
                if (method.Id == selectId) item.Selected = true;
            }
            _list.EndUpdate();
            UpdateButtons();
        }

        private void UpdateButtons()
        {
            bool selected = _list.SelectedItems.Count == 1;
            _rename.Enabled = selected;
            _remove.Enabled = selected;
            _addHello.Enabled = WindowsHelloAuthenticator.IsAvailable;
            _addHello.Text = _service.GetMethods(_path).Any(m => m.Kind == UnlockMethodKind.WindowsHello) ? "Set up Windows Hello again" : "Add Windows Hello";
            _addKey.Enabled = Fido2Authenticator.IsAvailable;
        }

        private UnlockMethod Selected => _list.SelectedItems.Count == 1 ? (UnlockMethod)_list.SelectedItems[0].Tag : null;

        private void AddWindowsHello()
        {
            Run(hwnd =>
            {
                _service.AddWindowsHello(hwnd, _database);
                return _service.GetMethods(_path).FirstOrDefault(m => m.Kind == UnlockMethodKind.WindowsHello);
            }, null);
        }

        private void AddSecurityKey()
        {
            if (!AddSecurityKeyDialog.Ask(this, out bool requirePin)) return;
            Run(hwnd => _service.AddSecurityKey(hwnd, _database, requirePin), method =>
            {
                if (!requirePin && method.RequiresPin)
                    MessageBox.Show(this, "Windows asked for the key's PIN anyway because a PIN is set on it, so this key unlocks with PIN + touch.",
                        Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            });
        }

        /// <summary>Runs an enrollment off the UI thread while the Windows prompts are shown.</summary>
        private void Run(Func<IntPtr, UnlockMethod> enroll, Action<UnlockMethod> afterwards)
        {
            IntPtr hwnd = Handle;
            UseWaitCursor = true;
            Enabled = false;
            try
            {
                UnlockMethod added = BackgroundCall.Run(() => enroll(hwnd));
                Reload(added?.Id);
                if (added != null) afterwards?.Invoke(added);
            }
            catch (UnlockCancelledException)
            {
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                Enabled = true;
                UseWaitCursor = false;
            }
        }

        private void BeginRename()
        {
            if (_list.SelectedItems.Count == 1) _list.SelectedItems[0].BeginEdit();
        }

        private void OnAfterLabelEdit(object sender, LabelEditEventArgs e)
        {
            var method = (UnlockMethod)_list.Items[e.Item].Tag;
            if (string.IsNullOrWhiteSpace(e.Label))
            {
                e.CancelEdit = true;
                return;
            }
            _service.RenameMethod(_path, method.Id, e.Label);
            method.Label = e.Label.Trim();
        }

        private void Remove()
        {
            UnlockMethod method = Selected;
            if (method == null) return;

            string message = $"Remove \"{method.Label}\" as a way to unlock this database?";
            if (_list.Items.Count == 1)
                message += Environment.NewLine + Environment.NewLine + "It is the last method: afterwards only the master key opens the database.";
            if (method.Kind == UnlockMethodKind.Fido2)
                message += Environment.NewLine + Environment.NewLine + "If this key was lost or stolen, change the database's master key as well.";

            if (MessageBox.Show(this, message, Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;

            try
            {
                _service.RemoveMethod(_path, method.Id);
            }
            catch (IOException ex)
            {
                MessageBox.Show(this, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            Reload(null);
        }

        internal static string DescribeMode(UnlockMethod method) =>
            method.Kind == UnlockMethodKind.WindowsHello ? "Face, fingerprint or Hello PIN"
            : method.RequiresPin ? "Security key: PIN + touch"
            : "Security key: touch only";
    }
}
