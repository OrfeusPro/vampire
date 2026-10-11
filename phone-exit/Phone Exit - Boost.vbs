Option Explicit
Dim shell, files, app, taskEnv
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
Set taskEnv = shell.Environment("PROCESS")
taskEnv("PHONE_EXIT_PEERS") = "4"
app = files.BuildPath(files.GetParentFolderName(WScript.ScriptFullName), "Phone Exit.exe")
shell.Run """" & app & """", 0, False
