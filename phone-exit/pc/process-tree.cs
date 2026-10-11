using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace PhoneExit {
    public sealed class ProcessRecord {
        public int Id, ParentId;
        public long Born;
        public string Path;
        public ProcessRecord(int id,int parent,long born,string path){Id=id;ParentId=parent;Born=born;Path=path;}
    }
    // No command lines, destinations or persistent process history are collected.
    public sealed class ProcessTree {
        readonly HashSet<string> roots;
        readonly HashSet<string> paths;
        Dictionary<int,long> tracked=new Dictionary<int,long>();
        Dictionary<int,string> launcherBranches=new Dictionary<int,string>();
        public bool AtLimit {get;private set;}
        public ProcessTree(string[] selected){roots=new HashSet<string>(selected,StringComparer.OrdinalIgnoreCase);paths=new HashSet<string>(roots,StringComparer.OrdinalIgnoreCase);}
        public string[] Observe(ProcessRecord[] snapshot){
            var selected=new Dictionary<int,long>();
            var restricted=new Dictionary<int,string>();
            foreach(var p in snapshot){long born;
                if(p.Path!=null&&(roots.Contains(p.Path)||(tracked.TryGetValue(p.Id,out born)&&born==p.Born))){
                    selected[p.Id]=p.Born;
                    if(roots.Contains(p.Path)){
                        var name=Path.GetFileName(p.Path).ToLowerInvariant();var directory=Path.GetDirectoryName(p.Path)+Path.DirectorySeparatorChar;
                        bool launcher=name.IndexOf("launcher")>=0||name=="steam.exe"||name=="galaxyclient.exe"||name=="battle.net.exe"||name=="eadesktop.exe"||name=="ubisoftconnect.exe";
                        if(launcher)foreach(var root in roots)if(!root.StartsWith(directory,StringComparison.OrdinalIgnoreCase)){restricted[p.Id]=directory;break;}
                    }else{string directory;if(launcherBranches.TryGetValue(p.Id,out directory))restricted[p.Id]=directory;}
                }
            }
            bool changed=true;
            while(changed){changed=false;foreach(var p in snapshot){long parentBorn;
                if(!selected.ContainsKey(p.Id)&&p.Path!=null&&selected.TryGetValue(p.ParentId,out parentBorn)&&parentBorn<=p.Born){
                    string directory;if(restricted.TryGetValue(p.ParentId,out directory)){
                        if(!p.Path.StartsWith(directory,StringComparison.OrdinalIgnoreCase))continue;
                        var relative=p.Path.Substring(directory.Length);
                        if(relative.IndexOf(Path.DirectorySeparatorChar)>=0&&!relative.StartsWith("resources\\",StringComparison.OrdinalIgnoreCase)&&!relative.StartsWith("bin\\",StringComparison.OrdinalIgnoreCase))continue;
                        restricted[p.Id]=directory;
                    }
                    selected[p.Id]=p.Born;changed=true;
                }
            }}
            foreach(var p in snapshot)if(selected.ContainsKey(p.Id)&&p.Path!=null&&!paths.Contains(p.Path)){
                if(paths.Count>=512){AtLimit=true;continue;}paths.Add(p.Path);
            }
            tracked=selected;launcherBranches=restricted;var result=new string[paths.Count];paths.CopyTo(result);Array.Sort(result,StringComparer.OrdinalIgnoreCase);return result;
        }
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Entry {
            public uint Size,Usage,Id;public UIntPtr Heap;public uint Module,Threads,Parent;public int Priority;public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string Exe;
        }
        [DllImport("kernel32.dll")]static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32FirstW(IntPtr handle,ref Entry entry);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32NextW(IntPtr handle,ref Entry entry);
        [DllImport("kernel32.dll")]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageNameW(IntPtr process,int flags,StringBuilder path,ref int size);
        [DllImport("kernel32.dll")]static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
        [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
        public string[] Poll(){return Observe(Snapshot());}
        // Include the selected branch, launcher ancestors and their own helpers.
        // Never turn a shell or another game's sibling branch into a VPN root.
        public static string[] RelatedPaths(ProcessRecord[] snapshot,int id) {
            var byId=new Dictionary<int,ProcessRecord>();foreach(var p in snapshot)byId[p.Id]=p;
            ProcessRecord seed;if(!byId.TryGetValue(id,out seed)||seed.Path==null)return new string[0];
            var selected=new HashSet<int>();selected.Add(id);
            bool changed=true;
            while(changed){changed=false;foreach(var p in snapshot){ProcessRecord parent;
                if(!selected.Contains(p.Id)&&p.Path!=null&&selected.Contains(p.ParentId)&&byId.TryGetValue(p.ParentId,out parent)&&parent.Born<=p.Born){selected.Add(p.Id);changed=true;}
            }}
            var ancestors=new List<ProcessRecord>();var current=seed;
            for(int n=0;n<8;n++){
                ProcessRecord parent;if(!byId.TryGetValue(current.ParentId,out parent)||parent.Path==null||parent.Born>current.Born||selected.Contains(parent.Id))break;
                var name=Path.GetFileName(parent.Path).ToLowerInvariant();
                if(name=="explorer.exe"||name=="cmd.exe"||name=="powershell.exe"||name=="pwsh.exe"||name=="services.exe"||name=="svchost.exe"||name=="taskmgr.exe"||name=="phone exit.exe")break;
                // An arbitrary host parent is not evidence of a game launcher.
                var dir=Path.GetDirectoryName(parent.Path)+Path.DirectorySeparatorChar;
                if(!seed.Path.StartsWith(dir,StringComparison.OrdinalIgnoreCase)&&name.IndexOf("launcher")<0&&name!="steam.exe"&&name!="epicgameslauncher.exe"&&name!="galaxyclient.exe"&&name!="battle.net.exe"&&name!="eadesktop.exe"&&name!="ubisoftconnect.exe")break;
                selected.Add(parent.Id);ancestors.Add(parent);current=parent;
            }
            foreach(var ancestor in ancestors){
                var directory=Path.GetDirectoryName(ancestor.Path)+Path.DirectorySeparatorChar;
                changed=true;
                while(changed){changed=false;foreach(var p in snapshot){ProcessRecord parent;
                    if(p.Path==null||selected.Contains(p.Id)||!selected.Contains(p.ParentId)||!byId.TryGetValue(p.ParentId,out parent)||parent.Born>p.Born)continue;
                    if(!p.Path.StartsWith(directory,StringComparison.OrdinalIgnoreCase))continue;
                    var relative=p.Path.Substring(directory.Length);
                    if(relative.IndexOf(Path.DirectorySeparatorChar)>=0&&!relative.StartsWith("resources\\",StringComparison.OrdinalIgnoreCase)&&!relative.StartsWith("bin\\",StringComparison.OrdinalIgnoreCase))continue;
                    selected.Add(p.Id);changed=true;
                }}
            }
            var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var p in snapshot)if(selected.Contains(p.Id)&&p.Path!=null)paths.Add(p.Path);
            var result=new string[paths.Count];paths.CopyTo(result);Array.Sort(result,StringComparer.OrdinalIgnoreCase);return result;
        }
        public static ProcessRecord[] Snapshot(){
            var rows=new List<ProcessRecord>();var handle=CreateToolhelp32Snapshot(2,0);
            if(handle==new IntPtr(-1))throw new InvalidOperationException("Process snapshot unavailable");
            try{var entry=new Entry();entry.Size=(uint)Marshal.SizeOf(entry);
                if(Process32FirstW(handle,ref entry))do{
                    var proc=OpenProcess(0x1000,false,entry.Id);if(proc==IntPtr.Zero)continue;
                    try{var path=new StringBuilder(32768);int size=path.Capacity;long born,exit,kernel,user;
                        if(QueryFullProcessImageNameW(proc,0,path,ref size)&&GetProcessTimes(proc,out born,out exit,out kernel,out user))rows.Add(new ProcessRecord((int)entry.Id,(int)entry.Parent,born,path.ToString()));
                    }finally{CloseHandle(proc);}
                }while(Process32NextW(handle,ref entry));
            }finally{CloseHandle(handle);}return rows.ToArray();
        }
    }
}
