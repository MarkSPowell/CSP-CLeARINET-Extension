// The CSP Rule Collector tab, built with Avalonia (CLeARINET's UI toolkit,
// on Windows and macOS). It replaces the original extension's WinForms tab
// and does the same things:
//
//   - "Enable Rule Collection" and "Verbose Logging" check boxes.
//   - A list of document URIs that have reported violations.
//   - Selecting one or more shows each document's generated policy, both
//     as one line and one directive per line.
//
// One difference: there's no right-click "Copy". Select the text in the
// policy box and copy it from there instead.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace ClearinetCSP
{
    public class RuleCollectionView : UserControl
    {
        private readonly ObservableCollection<string> documentUris = new ObservableCollection<string>();
        private readonly Dictionary<string, string> rules = new Dictionary<string, string>();
        private readonly ListBox documentList;
        private readonly TextBox selectedRuleText;

        public RuleCollectionView(CSPRuleCollector collector)
        {
            var enableRuleCollection = new CheckBox
            {
                Content = "Enable Rule Collection",
                IsChecked = CspExtension.Settings.enabled,
            };
            enableRuleCollection.IsCheckedChanged += (sender, e) =>
                CspExtension.Settings.enabled = enableRuleCollection.IsChecked == true;

            var verboseLogging = new CheckBox
            {
                Content = "Verbose Logging",
                IsChecked = CspExtension.Settings.verboseLogging,
            };
            verboseLogging.IsCheckedChanged += (sender, e) =>
                CspExtension.Settings.verboseLogging = verboseLogging.IsChecked == true;

            var help = new Button { Content = "Help..." };
            help.Click += (sender, e) => Clearinet.CompatShim.Utilities.LaunchHyperlink("https://github.com/MarkSPowell/CSP-CLeARINET-Extension");

            var options = new StackPanel
            {
                Orientation = Avalonia.Layout.Orientation.Horizontal,
                Spacing = 16,
                Margin = new Thickness(0, 0, 0, 8),
            };
            options.Children.Add(enableRuleCollection);
            options.Children.Add(verboseLogging);
            options.Children.Add(help);

            documentList = new ListBox
            {
                ItemsSource = documentUris,
                SelectionMode = SelectionMode.Multiple,
            };
            documentList.SelectionChanged += (sender, e) => ShowSelectedRules();

            selectedRuleText = new TextBox
            {
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
            };

            var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Columns };

            var lists = new Grid { ColumnDefinitions = new ColumnDefinitions("*,4,*") };
            Grid.SetColumn(documentList, 0);
            Grid.SetColumn(splitter, 1);
            Grid.SetColumn(selectedRuleText, 2);
            lists.Children.Add(documentList);
            lists.Children.Add(splitter);
            lists.Children.Add(selectedRuleText);

            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(options, Dock.Top);
            layout.Children.Add(options);
            layout.Children.Add(lists);
            Content = layout;

            // Reports arrive on proxy threads; the list belongs to the UI thread.
            collector.OnRuleAddedOrModified += (uri, rule) => Dispatcher.UIThread.Post(() => AddOrUpdate(uri, rule));
        }

        private void AddOrUpdate(string uri, string rule)
        {
            rules[uri] = rule;
            if (!documentUris.Contains(uri))
            {
                documentUris.Add(uri);
            }

            ShowSelectedRules();
        }

        // The same text the original WinForms tab showed for its selected document.
        private void ShowSelectedRules()
        {
            var text = new StringBuilder();
            if (documentList.SelectedItems != null)
            {
                foreach (var item in documentList.SelectedItems)
                {
                    var uri = item as string;
                    string rule;
                    if (uri == null || !rules.TryGetValue(uri, out rule))
                    {
                        continue;
                    }

                    var formattedRule = rule.Replace("Content-Security-Policy: ", "").Replace("; ", "\n\n").Replace(" ", "\n\t");
                    if (text.Length > 0)
                    {
                        text.Append("\n\n----------\n\n");
                    }

                    text.Append("Document: ").Append(uri).Append("\n\n").Append(rule).Append("\n\n").Append(formattedRule);
                }
            }

            selectedRuleText.Text = text.ToString();
        }
    }
}
