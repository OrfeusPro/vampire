using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Threading;

static class PhoneExitLauncher {
    [DllImport("shell32.dll",CharSet=CharSet.Unicode)] static extern int SetCurrentProcessExplicitAppUserModelID(string id);
    [STAThread] static void Main(string[] args){
        try{
            string root=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string script=Path.Combine(root,"pc","desktop.ps1");
            if(!File.Exists(script))throw new IOException("Не найдены файлы Phone Exit. Сохраните EXE рядом с папкой pc.");
            SetCurrentProcessExplicitAppUserModelID("PhoneExit.Desktop");
            Directory.SetCurrentDirectory(root);
            var initial=InitialSessionState.CreateDefault();initial.ExecutionPolicy=Microsoft.PowerShell.ExecutionPolicy.Bypass;
            using(var runspace=RunspaceFactory.CreateRunspace(initial)){
                runspace.ApartmentState=ApartmentState.STA;runspace.ThreadOptions=PSThreadOptions.UseCurrentThread;runspace.Open();
                using(var command=PowerShell.Create()){
                    command.Runspace=runspace;command.AddCommand(script);
                    if(Array.IndexOf(args,"--self-test")>=0)command.AddParameter("SelfTest");
                    if(Array.IndexOf(args,"--startup-test")>=0)command.AddParameter("StartupTest");
                    command.Invoke();
                    if(command.HadErrors)throw new InvalidOperationException("Не удалось запустить Phone Exit. Проверьте файлы программы.");
                }
            }
        }catch(Exception error){MessageBox.Show(error.Message,"Phone Exit — ошибка запуска",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }
}
