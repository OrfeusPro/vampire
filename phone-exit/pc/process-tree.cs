using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        public bool AtLimit {get;private set;}
        public ProcessTree(string[] selected){roots=new HashSet<string>(selected,StringComparer.OrdinalIgnoreCase);paths=new HashSet<string>(roots,StringComparer.OrdinalIgnoreCase);}
        public string[] Observe(ProcessRecord[] snapshot){
            var selected=new Dictionary<int,long>();
            foreach(var p in snapshot){long born;
                if(p.Path!=null&&(roots.Contains(p.Path)||(tracked.TryGetValue(p.Id,out born)&&born==p.Born)))selected[p.Id]=p.Born;
            }
            bool changed=true;
            while(changed){changed=false;foreach(var p in snapshot){long parentBorn;
                if(!selected.ContainsKey(p.Id)&&p.Path!=null&&selected.TryGetValue(p.ParentId,out parentBorn)&&parentBorn<=p.Born){selected[p.Id]=p.Born;changed=true;}
            }}
            foreach(var p in snapshot)if(selected.ContainsKey(p.Id)&&p.Path!=null&&!paths.Contains(p.Path)){
                if(paths.Count>=512){AtLimit=true;continue;}paths.Add(p.Path);
            }
            tracked=selected;var result=new string[paths.Count];paths.CopyTo(result);Array.Sort(result,StringComparer.OrdinalIgnoreCase);return result;
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
