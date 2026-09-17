using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using KeePass.Forms;
using KeePassFido2.Storage;
using KeePassFido2.Unlock;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace KeePassFido2.UI
{
    /// <summary>
    /// Adds an "Or unlock with" row below KeePass's master key components and optionally starts
    /// the preferred method as soon as the prompt appears. A successful unlock fills the prompt's
    /// private composite key field and closes it with OK, exactly as if the master key had been
    /// typed.
    /// </summary>
    /// <remarks>
    /// The row sits apart from KeePass's checkboxes on purpose: those components are combined
    /// into one key, while each method here opens the database on its own.
    /// </remarks>
    internal sealed class KeyPromptIntegration
    {
        // Private fields of KeePass.Forms.KeyPromptForm (checked against KeePass 2.61).
        private static readonly FieldInfo IoInfoField = GetField("m_ioInfo");
        private static readonly FieldInfo KeyField = GetField("m_pKey");
        private static readonly FieldInfo UserAccountField = GetField("m_cbUserAccount");
        private static readonly FieldInfo OkButtonField = GetField("m_btnOK");
        private static readonly FieldInfo CancelButtonField = GetField("m_btnCancel");

        private readonly UnlockService _service;
        private readonly Func<bool> _autoStart;

        /// <param name="autoStart">Read on every prompt: whether to start the preferred method right away.</param>
        public KeyPromptIntegration(UnlockService service, Func<bool> autoStart)
        {
            _service = service;
            _autoStart = autoStart;
        }

        public static bool IsSupported => IoInfoField != null && KeyField != null && UserAccountField != null && OkButtonField != null;

        /// <summary>Called while the prompt loads, after WinForms has applied DPI scaling.</summary>
        public void Attach(KeyPromptForm form)
        {
            if (!IsSupported) return;
            string databasePath = (IoInfoField.GetValue(form) as IOConnectionInfo)?.Path;
            DatabaseRecord record = _service.FindRecord(databasePath);
            if (record == null || record.Methods.Count == 0) return;

            // OnKeyPrompt also detects a rejected injected key, so it runs on every prompt.
            bool autoStart = _service.OnKeyPrompt(databasePath) && _autoStart();
            bool hasHello = record.Methods.Any(m => m.Kind == UnlockMethodKind.WindowsHello) && WindowsHelloAuthenticator.IsAvailable;
            bool hasKey = record.Methods.Any(m => m.Kind == UnlockMethodKind.Fido2) && Fido2Authenticator.IsAvailable;
            if (!hasHello && !hasKey) return;

            var row = new UnlockRow(form);
            if (form.SecureDesktopMode)
            {
                // Windows Hello and security key prompts cannot appear on KeePass's secure desktop.
                row.AddNotice("Windows Hello and security keys are unavailable while \"Enter master key on secure desktop\" is on.");
                row.Insert();
                return;
            }

            var buttons = new List<Button>();
            if (hasHello) buttons.Add(row.AddButton("Windows Hello", () => Run(form, databasePath, UnlockMethodKind.WindowsHello, buttons)));
            if (hasKey) buttons.Add(row.AddButton("Security key", () => Run(form, databasePath, UnlockMethodKind.Fido2, buttons)));

            bool stale = _service.IsStale(databasePath);
            if (stale)
                row.AddNotice("The master key changed. Enter it once to update Windows Hello and security key unlock.");
            row.Insert();

            if (autoStart && !stale)
                form.Shown += (sender, args) =>
                    form.BeginInvoke(new Action(() => Run(form, databasePath, hasHello ? UnlockMethodKind.WindowsHello : UnlockMethodKind.Fido2, buttons)));
        }

        private void Run(KeyPromptForm form, string databasePath, UnlockMethodKind kind, List<Button> buttons)
        {
            if (form.IsDisposed || !form.Visible) return;
            IntPtr hwnd = form.Handle;
            foreach (Button button in buttons) button.Enabled = false;

            try
            {
                CompositeKey key = BackgroundCall.Run(() => kind == UnlockMethodKind.WindowsHello
                    ? _service.UnlockWithWindowsHello(hwnd, databasePath)
                    : _service.UnlockWithSecurityKey(hwnd, databasePath));

                KeyField.SetValue(form, key);
                form.DialogResult = DialogResult.OK;
                form.Close();
            }
            catch (UnlockCancelledException)
            {
                // The user can type the master key or pick another method.
            }
            catch (Exception ex)
            {
                MessageBox.Show(form, ex.Message, "KeePass FIDO2", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                if (!form.IsDisposed)
                    foreach (Button button in buttons) button.Enabled = true;
            }
        }

        private static FieldInfo GetField(string name) =>
            typeof(KeyPromptForm).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);

        /// <summary>
        /// Builds the row and makes room for it: every control below the "Windows user account"
        /// checkbox moves down and the dialog grows by the row's height.
        /// </summary>
        private sealed class UnlockRow
        {
            private readonly Form _form;
            private readonly Control _lastComponent;
            private readonly Control _ok;
            private readonly int _gap;
            private readonly List<Button> _buttons = new List<Button>();
            private readonly List<Label> _notices = new List<Label>();

            public UnlockRow(KeyPromptForm form)
            {
                _form = form;
                _lastComponent = (Control)UserAccountField.GetValue(form);
                _ok = (Control)OkButtonField.GetValue(form);
                var cancel = CancelButtonField?.GetValue(form) as Control;
                _gap = cancel != null && cancel.Left > _ok.Right ? cancel.Left - _ok.Right : 6;
            }

            public Button AddButton(string text, Action onClick)
            {
                var button = new Button { Text = text, UseVisualStyleBackColor = true, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink };
                button.Click += (sender, args) => onClick();
                _buttons.Add(button);
                return button;
            }

            public void AddNotice(string text)
            {
                _notices.Add(new Label { Text = text, AutoSize = false, ForeColor = SystemColors.GrayText });
            }

            public void Insert()
            {
                int left = _lastComponent.Left;
                int width = _ok.Right - left;
                int top = _lastComponent.Bottom + _gap * 2;
                var added = new List<Control>();

                if (_buttons.Count > 0)
                {
                    var caption = new Label { Text = "Or unlock with:", AutoSize = true };
                    _form.Controls.Add(caption);
                    int x = left + caption.PreferredWidth + _gap;
                    caption.Location = new Point(left, top + (_ok.Height - caption.PreferredHeight) / 2);
                    added.Add(caption);

                    foreach (Button button in _buttons)
                    {
                        _form.Controls.Add(button);
                        int buttonWidth = Math.Max(button.PreferredSize.Width, _ok.Width);
                        button.AutoSize = false;
                        button.Size = new Size(buttonWidth, _ok.Height);
                        button.Location = new Point(x, top);
                        added.Add(button);
                        x += buttonWidth + _gap;
                    }
                    top += _ok.Height + _gap;
                }

                foreach (Label notice in _notices)
                {
                    _form.Controls.Add(notice);
                    int height = TextRenderer.MeasureText(notice.Text, notice.Font, new Size(width, 0), TextFormatFlags.WordBreak).Height;
                    notice.Location = new Point(left, top);
                    notice.Size = new Size(width, height);
                    added.Add(notice);
                    top += height + _gap;
                }

                int shift = top - _lastComponent.Bottom;
                ShiftControlsBelow(_lastComponent.Bottom, shift, added);

                foreach (Control control in added)
                {
                    if (control.Parent == null) _form.Controls.Add(control);
                    control.Anchor = AnchorStyles.Top | AnchorStyles.Left;
                    control.BringToFront();
                }
            }

            /// <summary>
            /// Moves controls to absolute positions after growing the dialog, so bottom-anchored
            /// controls, which WinForms already moved while growing, end up in the same place.
            /// </summary>
            private void ShiftControlsBelow(int threshold, int shift, List<Control> added)
            {
                var below = _form.Controls.Cast<Control>()
                    .Where(c => !added.Contains(c) && c.Top >= threshold)
                    .Select(c => new { Control = c, Top = c.Top })
                    .ToList();

                _form.SuspendLayout();
                _form.ClientSize = new Size(_form.ClientSize.Width, _form.ClientSize.Height + shift);
                foreach (var item in below)
                    item.Control.Top = item.Top + shift;
                _form.ResumeLayout(true);
            }
        }
    }
}
