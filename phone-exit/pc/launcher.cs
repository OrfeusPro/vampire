using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

static class PhoneExitLauncher {
    [STAThread] static void Main(){
        try{
            string root=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string script=Path.Combine(root,"pc","desktop.ps1");
            if(!File.Exists(script))throw new IOException("Не найдены файлы Phone Exit. Сохраните EXE рядом с папкой pc.");
            var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\v1.0\\powershell.exe"),
                "-NoProfile -STA -ExecutionPolicy Bypass -File \""+script+"\"");
            start.WorkingDirectory=root;start.UseShellExecute=false;start.CreateNoWindow=true;
            Process.Start(start);
        }catch(Exception error){MessageBox.Show(error.Message,"Phone Exit — ошибка запуска",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }
}
