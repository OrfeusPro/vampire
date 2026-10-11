using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
class RecoveryProbe {
    static int Main(string[] args){try{
        if(args[0]=="child"){
            var info=new ProcessStartInfo(args[1],"https "+args[2]);info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;
            using(var process=Process.Start(info)){var output=process.StandardOutput.ReadToEnd();process.WaitForExit();Console.Write(output);return process.ExitCode;}
        }
        if(args[0]=="https"){
            ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
            Thread.Sleep(1500);var request=(HttpWebRequest)WebRequest.Create(args[1]);request.Proxy=null;request.Timeout=12000;
            using(var response=request.GetResponse())using(var reader=new System.IO.StreamReader(response.GetResponseStream()))Console.Write(reader.ReadToEnd());return 0;
        }
        using(var udp=new UdpClient()){
            udp.Client.ReceiveTimeout=5000;udp.Connect("stun.l.google.com",19302);
            var packet=new byte[]{0,1,0,0,0x21,0x12,0xa4,0x42,1,2,3,4,5,6,7,8,9,16,17,18};
            for(int i=0;i<3;i++){udp.Send(packet,packet.Length);try{var remote=new IPEndPoint(IPAddress.Any,0);var result=udp.Receive(ref remote);if(result.Length<20||result[0]!=1||result[1]!=1)continue;bool same=true;for(int n=8;n<20;n++)if(result[n]!=packet[n])same=false;if(same)return 0;}catch(SocketException){}}
            return 2;
        }
    }catch{return 1;}}
}
