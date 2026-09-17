using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using KeePass.Forms;
using KeePassFido2.Agent;
using KeePassFido2.Ipc;
using KeePassFido2.References;
using KeePassFido2.Storage;
using KeePassLib;

namespace KeePassFido2.UI
{
    internal sealed class ContextPickerRequest
    {
        public string ContextName { get; set; }
        public ClientProcess Client { get; set; }
        public string WorkingDirectory { get; set; }
        public string Command { get; set; }

        /// <summary>Variable names the command requires; each must be assigned before sharing.</summary>
        public IList<string> Slots { get; set; }

        /// <summary>The existing context, whose assignments are kept and can be changed.</summary>
        public SavedContext Previous { get; set; }

        public Func<IEnumerable<PwDatabase>, IList<UnlockMethodKind>> MethodsFor { get; set; }

        /// <summary>Called on Share; returns the response to send, or null to keep the picker open.</summary>
        public Func<PickedContext, KpResponse> Complete { get; set; }

        /// <summary>Called exactly once, when the picker closes.</summary>
        public Action<KpResponse> Finished { get; set; }
    }

    internal sealed class PickedContext
    {
        public List<PickedRow> Rows { get; set; }
        public ApprovalChoice Choice { get; set; }
        public bool Remember { get; set; }
    }

    internal sealed class PickedRow
    {
        public string VariableName { get; set; }

        /// <summary>A slot the command requires; it cannot be removed, only reassigned.</summary>
        public bool Required { get; set; }

        /// <summary>Null while unassigned.</summary>
        public PwEntry Entry { get; set; }

        public PwDatabase Database { get; set; }
        public string Field { get; set; }
        public string Label { get; set; }
    }

    /// <summary>
    /// A small window next to KeePass's main window that assigns entry fields to a context's
    /// variables: the user selects a variable here, an entry in KeePass's own list, a field, and
    /// clicks Assign. Modeless and owned by the main window, which stays fully usable meanwhile.
    /// </summary>
    internal sealed class ContextPickerDialog : Form
    {
        private static readonly string[] StandardFields = { PwDefs.PasswordField, PwDefs.UserNameField, PwDefs.UrlField, PwDefs.TitleField, PwDefs.NotesField };

        private readonly MainForm _main;
        private readonly ContextPickerRequest _request;
        private readonly ListView _rows;
        private readonly ComboBox _field;
        private readonly Button _assign;
        private readonly Button _addVariable;
        private readonly Button _remove;
        private readonly Label _selection;
        private readonly CheckBox _remember;
        private readonly FlowLayoutPanel _shareButtons;
        private readonly Timer _selectionTimer;
        private KpResponse _response;
        private PwEntry _lastSelected;

        private ContextPickerDialog(MainForm main, ContextPickerRequest request)
        {
            _main = main;
            _request = request;

            Text = "KeePass FIDO2 - assign values";
            FormBorderStyle = FormBorderStyle.FixedToolWindow;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Font;
            Font = SystemFonts.MessageBoxFont;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(12);

            const int width = 460;
            var layout = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Dock = DockStyle.Fill };

            layout.Controls.Add(new Label
            {
                Text = $"Values for context \"{request.ContextName}\"",
                Font = new Font(Font.FontFamily, Font.Size * 1.15f, FontStyle.Bold),
                AutoSize = true,
                MaximumSize = new Size(width, 0),
            });
            layout.Controls.Add(new Label
            {
                Text = $"Requested by {request.Client.DisplayName}" +
                       (request.Client.ParentDisplayName != null ? $", started by {request.Client.ParentDisplayName}" : string.Empty) +
                       (string.IsNullOrEmpty(request.Command) ? string.Empty : Environment.NewLine + request.Command) +
                       (string.IsNullOrEmpty(request.WorkingDirectory) ? string.Empty : Environment.NewLine + "in " + request.WorkingDirectory),
                ForeColor = SystemColors.GrayText,
                AutoSize = true,
                MaximumSize = new Size(width, 0),
                Margin = new Padding(0, 4, 0, 10),
            });
            layout.Controls.Add(new Label
            {
                Text = "Select a variable below, select an entry in KeePass's list, choose the field and click Assign.",
                AutoSize = true,
                MaximumSize = new Size(width, 0),
                Margin = new Padding(0, 0, 0, 6),
            });

            _rows = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                HideSelection = false,
                HeaderStyle = ColumnHeaderStyle.Nonclickable,
                Size = new Size(width, 150),
                Margin = new Padding(0, 0, 0, 6),
            };
            _rows.Columns.Add("Variable", 170);
            _rows.Columns.Add("Value from", width - 174);
            _rows.SelectedIndexChanged += (s, e) => UpdateState();
            _rows.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Delete) RemoveSelected();
            };
            layout.Controls.Add(_rows);

            var assignRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            assignRow.Controls.Add(new Label { Text = "Field:", AutoSize = true, Margin = new Padding(0, 7, 4, 0) });
            _field = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130 };
            _field.Items.AddRange(StandardFields.Cast<object>().ToArray());
            _field.SelectedIndex = 0;
            assignRow.Controls.Add(_field);
            _assign = new Button { Text = "Assign", AutoSize = true, UseVisualStyleBackColor = true };
            _assign.Click += (s, e) => AssignSelected();
            assignRow.Controls.Add(_assign);
            _addVariable = new Button { Text = "Add as new variable", AutoSize = true, UseVisualStyleBackColor = true };
            _addVariable.Click += (s, e) => AddVariable();
            assignRow.Controls.Add(_addVariable);
            _remove = new Button { Text = "Remove", AutoSize = true, UseVisualStyleBackColor = true };
            _remove.Click += (s, e) => RemoveSelected();
            assignRow.Controls.Add(_remove);
            layout.Controls.Add(assignRow);

            _selection = new Label { AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(width, 0), Margin = new Padding(0, 4, 0, 8) };
            layout.Controls.Add(_selection);

            _remember = new CheckBox { Text = "Don't ask again for this program and folder for 8 hours", AutoSize = true, Margin = new Padding(0, 0, 0, 8) };
            layout.Controls.Add(_remember);

            _shareButtons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            var cancel = new Button { Text = "Cancel", AutoSize = true, UseVisualStyleBackColor = true };
            cancel.Click += (s, e) => Close();
            _shareButtons.Controls.Add(cancel);
            layout.Controls.Add(_shareButtons);

            Controls.Add(layout);
            LoadRows();

            _selectionTimer = new Timer { Interval = 400 };
            _selectionTimer.Tick += (s, e) => UpdateState();
            _selectionTimer.Start();

            FormClosed += (s, e) =>
            {
                _selectionTimer.Dispose();
                request.Finished(_response ?? KpResponse.Failure("Cancelled in KeePass."));
            };
            UpdateState();
        }

        public static void Open(MainForm main, ContextPickerRequest request)
        {
            main.EnsureVisibleForegroundWindow(true, true);
            var dialog = new ContextPickerDialog(main, request);
            dialog.Show(main);
            Rectangle screen = Screen.FromControl(main).WorkingArea;
            dialog.Location = new Point(
                Math.Max(screen.Left, Math.Min(main.Right - dialog.Width - 24, screen.Right - dialog.Width)),
                Math.Max(screen.Top, Math.Min(main.Top + 80, screen.Bottom - dialog.Height)));
            dialog.Activate();
        }

        /// <summary>Required slots first, in the command's order, then the context's other variables.</summary>
        private void LoadRows()
        {
            var previous = (_request.Previous?.Variables ?? new List<ContextVariable>()).ToList();
            foreach (string slot in _request.Slots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                ContextVariable assigned = previous.FirstOrDefault(v => string.Equals(v.Name, slot, StringComparison.OrdinalIgnoreCase));
                AddRow(RowFor(slot, assigned, required: true));
            }
            foreach (ContextVariable variable in previous.Where(v => !_request.Slots.Any(s => string.Equals(s, v.Name, StringComparison.OrdinalIgnoreCase))))
                AddRow(RowFor(variable.Name, variable, required: false));

            ListViewItem firstMissing = _rows.Items.Cast<ListViewItem>().FirstOrDefault(i => ((PickedRow)i.Tag).Entry == null);
            if (firstMissing != null) firstMissing.Selected = true;
        }

        private PickedRow RowFor(string name, ContextVariable assigned, bool required)
        {
            var row = new PickedRow { VariableName = name, Required = required };
            if (assigned == null || !SecretReference.TryParse(assigned.Reference, out SecretReference reference, out _) || reference.EntryUuid == null)
                return row;

            var uuid = new PwUuid(Enumerable.Range(0, 16).Select(i => Convert.ToByte(reference.EntryUuid.Substring(i * 2, 2), 16)).ToArray());
            foreach (PwDatabase database in _main.DocumentManager.GetOpenDatabases())
            {
                PwEntry entry = database.RootGroup.FindEntry(uuid, true);
                if (entry == null) continue;
                Assign(row, entry, reference.Field);
                break;
            }
            return row;
        }

        private void AddRow(PickedRow row)
        {
            var item = new ListViewItem(new[] { row.VariableName, string.Empty }) { Tag = row };
            _rows.Items.Add(item);
            ShowAssignment(item);
        }

        private static void ShowAssignment(ListViewItem item)
        {
            var row = (PickedRow)item.Tag;
            item.SubItems[1].Text = row.Entry == null ? "not assigned" : row.Label;
            item.ForeColor = row.Entry == null ? Color.Firebrick : SystemColors.WindowText;
        }

        private IEnumerable<PickedRow> Rows() => _rows.Items.Cast<ListViewItem>().Select(i => (PickedRow)i.Tag);

        private PwEntry SelectedEntry()
        {
            PwEntry[] entries = _main.GetSelectedEntries();
            return entries != null && entries.Length == 1 ? entries[0] : null;
        }

        private void AssignSelected()
        {
            PwEntry entry = SelectedEntry();
            if (entry == null || _rows.SelectedItems.Count != 1 || _field.SelectedItem == null) return;
            ListViewItem item = _rows.SelectedItems[0];
            Assign((PickedRow)item.Tag, entry, (string)_field.SelectedItem);
            ShowAssignment(item);

            ListViewItem nextMissing = _rows.Items.Cast<ListViewItem>().FirstOrDefault(i => ((PickedRow)i.Tag).Entry == null);
            if (nextMissing != null) nextMissing.Selected = true;
            UpdateState();
        }

        private void AddVariable()
        {
            PwEntry entry = SelectedEntry();
            if (entry == null || _field.SelectedItem == null) return;
            string field = (string)_field.SelectedItem;
            var row = new PickedRow
            {
                VariableName = ContextStore.VariableName(entry.Strings.ReadSafe(PwDefs.TitleField), field, Rows().Select(r => r.VariableName.ToUpperInvariant()).ToList()),
            };
            Assign(row, entry, field);
            AddRow(row);
            _rows.Items[_rows.Items.Count - 1].Selected = true;
            UpdateState();
        }

        private void Assign(PickedRow row, PwEntry entry, string field)
        {
            row.Entry = entry;
            row.Database = _main.DocumentManager.FindContainerOf(entry);
            row.Field = field;
            row.Label = Describe(entry, field);
        }

        private void RemoveSelected()
        {
            if (_rows.SelectedItems.Count != 1) return;
            ListViewItem item = _rows.SelectedItems[0];
            var row = (PickedRow)item.Tag;
            if (row.Required)
            {
                row.Entry = null;
                row.Database = null;
                ShowAssignment(item);
            }
            else
            {
                _rows.Items.Remove(item);
            }
            UpdateState();
        }

        private void UpdateState()
        {
            if (IsDisposed) return;

            PwEntry entry = SelectedEntry();
            if (entry != _lastSelected)
            {
                _lastSelected = entry;
                RefreshFieldChoices(entry);
            }

            _selection.Text = entry != null
                ? "Selected in KeePass: " + Describe(entry, null)
                : _main.GetSelectedEntriesCount() > 1 ? "Select a single entry in KeePass." : "No entry selected in KeePass.";

            bool rowSelected = _rows.SelectedItems.Count == 1;
            _assign.Enabled = entry != null && rowSelected;
            _addVariable.Enabled = entry != null;
            _remove.Enabled = rowSelected;
            _remove.Text = rowSelected && ((PickedRow)_rows.SelectedItems[0].Tag).Required ? "Unassign" : "Remove";

            List<PickedRow> rows = Rows().ToList();
            bool complete = rows.Count > 0 && rows.All(r => r.Entry != null);
            IList<UnlockMethodKind> methods = _request.MethodsFor(rows.Where(r => r.Database != null).Select(r => r.Database).Distinct());
            string signature = string.Join(",", methods) + "|" + complete;
            if ((string)_shareButtons.Tag == signature) return;
            _shareButtons.Tag = signature;

            foreach (Control control in _shareButtons.Controls.Cast<Control>().Where(c => c.Tag is ApprovalChoice).ToList())
                _shareButtons.Controls.Remove(control);
            if (methods.Count == 0)
                ShareButton("Share", ApprovalChoice.Allowed, complete);
            if (methods.Contains(UnlockMethodKind.Fido2))
                ShareButton("Share with security key", ApprovalChoice.SecurityKey, complete);
            if (methods.Contains(UnlockMethodKind.WindowsHello))
                ShareButton("Share with Windows Hello", ApprovalChoice.WindowsHello, complete);
        }

        /// <summary>Standard fields plus the custom fields of the entry selected in KeePass.</summary>
        private void RefreshFieldChoices(PwEntry entry)
        {
            string current = _field.SelectedItem as string;
            IEnumerable<string> custom = entry == null
                ? Enumerable.Empty<string>()
                : entry.Strings.GetKeys().Where(k => !PwDefs.IsStandardField(k)).OrderBy(k => k, StringComparer.OrdinalIgnoreCase);

            _field.BeginUpdate();
            _field.Items.Clear();
            _field.Items.AddRange(StandardFields.Concat(custom).Cast<object>().ToArray());
            _field.SelectedItem = current != null && _field.Items.Contains(current) ? current : PwDefs.PasswordField;
            _field.EndUpdate();
        }

        private void ShareButton(string text, ApprovalChoice choice, bool enabled)
        {
            var button = new Button { Text = text, AutoSize = true, UseVisualStyleBackColor = true, Tag = choice, Enabled = enabled };
            button.Click += (s, e) => Share(choice);
            _shareButtons.Controls.Add(button);
        }

        private void Share(ApprovalChoice choice)
        {
            List<PickedRow> rows = Rows().ToList();
            if (rows.Count == 0 || rows.Any(r => r.Entry == null)) return;

            Enabled = false;
            _selectionTimer.Stop();
            try
            {
                KpResponse response = _request.Complete(new PickedContext { Rows = rows, Choice = choice, Remember = _remember.Checked });
                if (response == null) return;
                _response = response;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                if (!IsDisposed)
                {
                    Enabled = true;
                    _selectionTimer.Start();
                }
            }
        }

        private static string Describe(PwEntry entry, string field)
        {
            string group = entry.ParentGroup?.GetFullPath(" / ", false);
            string title = entry.Strings.ReadSafe(PwDefs.TitleField);
            string location = string.IsNullOrEmpty(group) ? title : group + " / " + title;
            return field == null ? location : location + " / " + field;
        }
    }
}
