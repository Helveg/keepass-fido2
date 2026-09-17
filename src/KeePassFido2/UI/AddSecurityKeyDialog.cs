using System.Drawing;
using System.Windows.Forms;

namespace KeePassFido2.UI
{
    /// <summary>Asks how a new security key should unlock the database before it is enrolled.</summary>
    internal sealed class AddSecurityKeyDialog : Form
    {
        private readonly CheckBox _requirePin;

        private AddSecurityKeyDialog()
        {
            Text = "Add security key";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Font;
            Font = SystemFonts.MessageBoxFont;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);

            var layout = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Dock = DockStyle.Fill };

            layout.Controls.Add(new Label
            {
                Text = "Windows will ask you to touch your security key twice: once to create a credential on it " +
                       "and once to read the secret that unlocks this database.",
                AutoSize = true,
                MaximumSize = new Size(420, 0),
                Margin = new Padding(0, 0, 0, 12),
            });

            _requirePin = new CheckBox { Text = "Require the security key's PIN (recommended)", Checked = true, AutoSize = true };
            layout.Controls.Add(_requirePin);

            var hint = new Label
            {
                Text = "Without the PIN, anyone holding this key and your computer can open the database with a touch. " +
                       "Only turn this off for a key kept far away from the computer. " +
                       "Keys that have a PIN set may still be asked for it by Windows.",
                AutoSize = true,
                MaximumSize = new Size(420, 0),
                ForeColor = SystemColors.GrayText,
                Margin = new Padding(18, 2, 0, 12),
            };
            layout.Controls.Add(hint);
            _requirePin.CheckedChanged += (s, e) => hint.ForeColor = _requirePin.Checked ? SystemColors.GrayText : SystemColors.ControlText;

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, UseVisualStyleBackColor = true };
            var ok = new Button { Text = "Continue", DialogResult = DialogResult.OK, UseVisualStyleBackColor = true };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);

            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        /// <returns>False when the user cancelled.</returns>
        public static bool Ask(IWin32Window owner, out bool requirePin)
        {
            using (var dialog = new AddSecurityKeyDialog())
            {
                bool confirmed = dialog.ShowDialog(owner) == DialogResult.OK;
                requirePin = dialog._requirePin.Checked;
                return confirmed;
            }
        }
    }
}
