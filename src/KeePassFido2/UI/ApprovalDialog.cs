using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using KeePassFido2.Agent;
using KeePassFido2.Storage;

namespace KeePassFido2.UI
{
    internal sealed class ApprovalRequest
    {
        public string Heading { get; set; }
        public ClientProcess Client { get; set; }
        public string WorkingDirectory { get; set; }
        public string Command { get; set; }
        public string DatabaseName { get; set; }
        public IList<string> Items { get; set; }
        public bool CanRemember { get; set; }

        /// <summary>Methods to approve with; when empty the dialog offers a plain Allow button.</summary>
        public IList<UnlockMethodKind> Methods { get; set; }
    }

    internal enum ApprovalChoice
    {
        Denied,
        Allowed,
        WindowsHello,
        SecurityKey,
    }

    internal sealed class ApprovalResult
    {
        public ApprovalChoice Choice { get; set; }
        public bool Remember { get; set; }
    }

    /// <summary>
    /// Shows who is asking for what. Opens without an owner and on top, because KeePass's main
    /// window may be minimized to the tray while a terminal requests secrets.
    /// </summary>
    internal sealed class ApprovalDialog : Form
    {
        private readonly CheckBox _remember;
        private ApprovalChoice _choice = ApprovalChoice.Denied;

        private ApprovalDialog(ApprovalRequest request)
        {
            Text = "KeePass FIDO2";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            TopMost = true;
            ShowIcon = false;
            AutoScaleMode = AutoScaleMode.Font;
            Font = SystemFonts.MessageBoxFont;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);

            const int width = 480;
            var layout = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Dock = DockStyle.Fill };

            layout.Controls.Add(new Label
            {
                Text = request.Heading,
                Font = new Font(Font.FontFamily, Font.Size * 1.2f, FontStyle.Bold),
                AutoSize = true,
                MaximumSize = new Size(width, 0),
                Margin = new Padding(0, 0, 0, 10),
            });

            var details = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 0, 10) };
            AddDetail(details, "Program", Describe(request.Client.ImagePath, request.Client.ProcessId), width);
            if (request.Client.ParentImagePath != null)
                AddDetail(details, "Started by", Describe(request.Client.ParentImagePath, request.Client.ParentProcessId), width);
            if (!string.IsNullOrEmpty(request.Command)) AddDetail(details, "Command", request.Command, width);
            if (!string.IsNullOrEmpty(request.WorkingDirectory)) AddDetail(details, "Folder", request.WorkingDirectory, width);
            AddDetail(details, "Database", request.DatabaseName, width);
            layout.Controls.Add(details);

            var items = new ListBox { Width = width, IntegralHeight = true, SelectionMode = SelectionMode.None, Margin = new Padding(0, 0, 0, 10) };
            items.Items.AddRange(request.Items.Cast<object>().ToArray());
            items.Height = items.ItemHeight * Math.Min(Math.Max(request.Items.Count, 2), 10) + 4;
            layout.Controls.Add(items);

            _remember = new CheckBox
            {
                Text = "Don't ask again for this program, folder and these values for 8 hours",
                AutoSize = true,
                Visible = request.CanRemember,
                Margin = new Padding(0, 0, 0, 10),
            };
            if (request.CanRemember) layout.Controls.Add(_remember);

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            var deny = AddButton(buttons, "Deny", ApprovalChoice.Denied);
            CancelButton = deny;

            if (request.Methods.Count == 0)
            {
                AcceptButton = AddButton(buttons, "Allow", ApprovalChoice.Allowed);
                layout.Controls.Add(new Label
                {
                    Text = "Tip: add Windows Hello or a security key to this database (Tools → KeePass FIDO2) to require it here.",
                    ForeColor = SystemColors.GrayText,
                    AutoSize = true,
                    MaximumSize = new Size(width, 0),
                    Margin = new Padding(0, 0, 0, 10),
                });
            }
            else
            {
                if (request.Methods.Contains(UnlockMethodKind.Fido2)) AddButton(buttons, "Allow with security key", ApprovalChoice.SecurityKey);
                if (request.Methods.Contains(UnlockMethodKind.WindowsHello)) AddButton(buttons, "Allow with Windows Hello", ApprovalChoice.WindowsHello);
            }
            layout.Controls.Add(buttons);

            Controls.Add(layout);
            Shown += (s, e) => Activate();
        }

        public static ApprovalResult Ask(ApprovalRequest request)
        {
            using (var dialog = new ApprovalDialog(request))
            {
                dialog.ShowDialog();
                return new ApprovalResult { Choice = dialog._choice, Remember = dialog._remember.Checked };
            }
        }

        private Button AddButton(FlowLayoutPanel panel, string text, ApprovalChoice choice)
        {
            var button = new Button { Text = text, AutoSize = true, UseVisualStyleBackColor = true, MinimumSize = new Size(88, 0) };
            button.Click += (s, e) =>
            {
                _choice = choice;
                DialogResult = choice == ApprovalChoice.Denied ? DialogResult.Cancel : DialogResult.OK;
            };
            panel.Controls.Add(button);
            return button;
        }

        private static void AddDetail(TableLayoutPanel panel, string label, string value, int width)
        {
            panel.Controls.Add(new Label { Text = label + ":", AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 2, 8, 2) });
            panel.Controls.Add(new Label { Text = value ?? "unknown", AutoSize = true, MaximumSize = new Size(width - 90, 0), Margin = new Padding(0, 2, 0, 2) });
        }

        private static string Describe(string imagePath, int processId) =>
            imagePath == null ? $"unknown (process {processId})" : $"{System.IO.Path.GetFileName(imagePath)}  —  {imagePath}";
    }
}
