using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

class AkuisisiVSS
{
    static string VhdPath = "evidence.vhd";
    static string MountLetter = "Z";
    static string ShadowLetter = "X";

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: akuisisi.exe <folder1> <folder2> ...");
            return;
        }

        Console.WriteLine("[+] Creating VSS snapshot");
        CreateVSS();

        Console.WriteLine("[+] Creating VHD");
        CreateVHD(50);
        MountVHD();

        using (var hashLog = new StreamWriter("hashes.txt"))
        using (var meta = new StreamWriter("manifest.json"))
        {
            meta.WriteLine("{");

            foreach (string path in args)
            {
                string shadowPath = ShadowLetter + ":\\" + path.Substring(3);
                if (!Directory.Exists(shadowPath)) continue;

                AcquireFolder(shadowPath, MountLetter + ":\\" + Sanitize(path), hashLog, meta);
            }

            meta.WriteLine("\"completed\": true");
            meta.WriteLine("}");
        }

        Console.WriteLine("[+] Capturing $MFT");
        CaptureMFT();

        Console.WriteLine("[+] Done. Evidence ready.");
    }

    static void AcquireFolder(string src, string dst, StreamWriter hashLog, StreamWriter meta)
    {
        Directory.CreateDirectory(dst);

        foreach (string file in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
        {
            string rel = file.Substring(src.Length).TrimStart('\\');
            string target = Path.Combine(dst, rel);

            Directory.CreateDirectory(Path.GetDirectoryName(target));
            File.Copy(file, target, true);

            string hash = SHA256File(file);
            var fi = new FileInfo(file);

            hashLog.WriteLine($"{hash}  {file}");

            meta.WriteLine($"\"{file}\": {{");
            meta.WriteLine($"  \"sha256\": \"{hash}\",");
            meta.WriteLine($"  \"created\": \"{fi.CreationTimeUtc}\",");
            meta.WriteLine($"  \"modified\": \"{fi.LastWriteTimeUtc}\",");
            meta.WriteLine($"  \"accessed\": \"{fi.LastAccessTimeUtc}\"");
            meta.WriteLine("},");
        }
    }

    static string SHA256File(string path)
    {
        using (var sha = SHA256.Create())
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
        }
    }

    static void CaptureMFT()
    {
        using (var src = new FileStream(@"\\.\C:\$MFT", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var dst = new FileStream("mft.bin", FileMode.Create))
        {
            src.CopyTo(dst);
        }
    }

    static void CreateVSS()
    {
        string script =
@"SET CONTEXT PERSISTENT NOWRITERS
BEGIN BACKUP
ADD VOLUME C: ALIAS MyShadow
CREATE
EXPOSE %MyShadow% X:
END BACKUP";

        RunDiskshadow(script);
    }

    static void CreateVHD(int sizeGB)
    {
        string script =
$@"create vdisk file={VhdPath} maximum={sizeGB * 1024} type=fixed
select vdisk file={VhdPath}
attach vdisk
create partition primary
format fs=ntfs quick
assign letter={MountLetter}
exit";

        RunDiskpart(script);
    }

    static void MountVHD()
    {
        RunDiskpart($"select vdisk file={VhdPath}\nattach vdisk\nassign letter={MountLetter}\nexit");
    }

    static void RunDiskshadow(string script)
    {
        string f = Path.GetTempFileName();
        File.WriteAllText(f, script);
        Process.Start("diskshadow", "/s " + f).WaitForExit();
        File.Delete(f);
    }

    static void RunDiskpart(string script)
    {
        string f = Path.GetTempFileName();
        File.WriteAllText(f, script);
        Process.Start("diskpart", "/s " + f).WaitForExit();
        File.Delete(f);
    }

    static string Sanitize(string p)
    {
        return p.Replace(":", "");
    }
}
