using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Password_Manager.core.cryptography;

namespace Password_Manager.GUI;

public partial class VaultSelectorWindow : Window
{
    private bool _isPasswordVisible = false;

    public Vault? ActiveVault { get; private set; }

    public VaultSelectorWindow()
    {
        InitializeComponent();
    }

    private void BrowseVaultButton_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog openFileDialog = new OpenFileDialog
        {
            Title = "Select Vault File",
            Filter = "Vault Files (*.vlt)|*.vlt|All Files (*.*)|*.*",
            Multiselect = false
        };

        if (openFileDialog.ShowDialog() == true)
        {
            VaultFileTextBox.Text = openFileDialog.FileName;
            ClearStatus();
        }
    }

    private void BrowseKeyButton_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog openFileDialog = new OpenFileDialog
        {
            Title = "Select Key File",
            Filter = "Key Files (*.key;*.dat;*.bin)|*.key;*.dat;*.bin|All Files (*.*)|*.*",
            Multiselect = false
        };

        if (openFileDialog.ShowDialog() == true)
        {
            KeyFileTextBox.Text = openFileDialog.FileName;
            ClearStatus();
        }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;

        string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
        if (files == null || files.Length == 0) return;

        foreach (string file in files)
        {
            string ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext == ".vlt")
            {
                VaultFileTextBox.Text = file;
                ClearStatus();
            }
            else if (ext == ".key" || ext == ".dat" || ext == ".bin")
            {
                KeyFileTextBox.Text = file;
                ClearStatus();
            }
        }
    }

    private void TogglePasswordVisibilityButton_Click(object sender, RoutedEventArgs e)
    {
        _isPasswordVisible = !_isPasswordVisible;

        if (_isPasswordVisible)
        {
            MasterPasswordVisibleTextBox.Text = MasterPasswordBox.Password;
            MasterPasswordBox.Visibility = Visibility.Collapsed;
            MasterPasswordVisibleTextBox.Visibility = Visibility.Visible;
            MasterPasswordVisibleTextBox.Focus();
            MasterPasswordVisibleTextBox.CaretIndex = MasterPasswordVisibleTextBox.Text.Length;
            TogglePasswordVisibilityButton.Content = "🔒";
        }
        else
        {
            MasterPasswordBox.Password = MasterPasswordVisibleTextBox.Text;
            MasterPasswordVisibleTextBox.Visibility = Visibility.Collapsed;
            MasterPasswordBox.Visibility = Visibility.Visible;
            MasterPasswordBox.Focus();
            TogglePasswordVisibilityButton.Content = "👁";
        }
    }

    private void MasterPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_isPasswordVisible)
        {
            MasterPasswordVisibleTextBox.Text = MasterPasswordBox.Password;
        }
    }

    private void MasterPasswordVisibleTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isPasswordVisible)
        {
            MasterPasswordBox.Password = MasterPasswordVisibleTextBox.Text;
        }
    }

    private string GetCurrentPassword()
    {
        return _isPasswordVisible ? MasterPasswordVisibleTextBox.Text : MasterPasswordBox.Password;
    }

    private string GetSelectedCipher()
    {
        if (CipherComboBox.SelectedItem is ComboBoxItem item)
        {
            string text = item.Content.ToString() ?? "";
            if (text.Contains("ChaCha", StringComparison.OrdinalIgnoreCase))
            {
                return "ChaCha20";
            }
        }
        return "AES";
    }

    private void UnlockVaultButton_Click(object sender, RoutedEventArgs e)
    {
        string vaultPath = VaultFileTextBox.Text.Trim();
        string password = GetCurrentPassword();
        string cipher = GetSelectedCipher();

        if (string.IsNullOrWhiteSpace(vaultPath))
        {
            ShowStatus("Please select a vault file (.vlt).", isError: true);
            return;
        }

        if (!File.Exists(vaultPath))
        {
            ShowStatus("The specified vault file does not exist.", isError: true);
            return;
        }

        if (string.IsNullOrEmpty(password))
        {
            ShowStatus("Please enter your master password.", isError: true);
            return;
        }

        try
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            ActiveVault = Vault.Open(vaultPath, passwordBytes, cipher);
            ShowStatus("Vault unlocked successfully!", isError: false);
        }
        catch (Exception ex)
        {
            ShowStatus($"Failed to unlock vault: {ex.Message}", isError: true);
        }
    }

    private void CreateVaultButton_Click(object sender, RoutedEventArgs e)
    {
        string password = GetCurrentPassword();
        string cipher = GetSelectedCipher();

        if (string.IsNullOrEmpty(password))
        {
            ShowStatus("Please enter a master password for the new vault.", isError: true);
            return;
        }

        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Title = "Create New Vault File",
            Filter = "Vault Files (*.vlt)|*.vlt",
            DefaultExt = ".vlt",
            FileName = "vault"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            try
            {
                string destination = saveFileDialog.FileName;
                if (destination.EndsWith(".vlt", StringComparison.OrdinalIgnoreCase))
                {
                    destination = destination.Substring(0, destination.Length - 4);
                }

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                ActiveVault = Vault.Create(destination, passwordBytes, cipher);
                VaultFileTextBox.Text = destination + ".vlt";
                ShowStatus("New vault created successfully!", isError: false);
            }
            catch (Exception ex)
            {
                ShowStatus($"Failed to create vault: {ex.Message}", isError: true);
            }
        }
    }

    private void ShowStatus(string message, bool isError)
    {
        StatusMessageTextBlock.Text = message;
        StatusMessageTextBlock.Foreground = isError 
            ? (Brush)FindResource("DangerBrush") 
            : (Brush)FindResource("SuccessBrush");
        StatusMessageTextBlock.Visibility = Visibility.Visible;
    }

    private void ClearStatus()
    {
        StatusMessageTextBlock.Text = string.Empty;
        StatusMessageTextBlock.Visibility = Visibility.Collapsed;
    }
}
