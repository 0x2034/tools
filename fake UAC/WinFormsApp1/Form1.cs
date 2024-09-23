using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinFormsApp1
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            this.FormBorderStyle = FormBorderStyle.None; // Remove the border and X button
            this.ShowInTaskbar = false; // Hide Form1 from the taskbar
            this.Load += Form1_Load;
        }

        private async void Form1_Load(object sender, EventArgs e)
        {
            // Get the screen's working area (excluding taskbars, etc.)
            var workingArea = Screen.PrimaryScreen.WorkingArea;

            // Position the form in the bottom-right corner, 0.5 cm higher
            int offset = (int)(18.9); // 0.5 cm in pixels (approximately)
            this.Location = new Point(workingArea.Right - this.Width, workingArea.Bottom - this.Height - offset);

            // Wait for 2 seconds before displaying Form2
            await Task.Delay(2000);

            // Create and show Form2 centered
            Form2 form2 = new Form2();
            form2.StartPosition = FormStartPosition.CenterScreen; // Ensure Form2 appears at the center
            form2.Show();
        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {

        }
    }
}