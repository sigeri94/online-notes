using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MFTParser
{
    class Program
    {
        const int MFT_RECORD_SIZE = 1024;

        static Dictionary<long, MFTEntry> Entries = new Dictionary<long, MFTEntry>();

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: mftparser.exe <mft.bin> <path1> [path2]");
                return;
            }

            string mftPath = args[0];
            List<string> targets = new List<string>();

            for (int i = 1; i < args.Length; i++)
                targets.Add(args[i].ToLower());

            ParseMFT(mftPath);
            ResolvePaths();

            foreach (var e in Entries.Values)
            {
                if (string.IsNullOrEmpty(e.FullPath)) continue;

                foreach (var t in targets)
                {
                    if (e.FullPath.StartsWith(t))
                    {
                        Console.WriteLine(e);
                        break;
                    }
                }
            }
        }

        static void ParseMFT(string path)
        {
            byte[] buffer = new byte[MFT_RECORD_SIZE];

            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                long index = 0;
                while (fs.Read(buffer, 0, buffer.Length) == buffer.Length)
                {
                    if (Encoding.ASCII.GetString(buffer, 0, 4) != "FILE")
                    {
                        index++;
                        continue;
                    }

                    ushort flags = BitConverter.ToUInt16(buffer, 22);
                    bool inUse = (flags & 0x01) != 0;

                    ushort attrOffset = BitConverter.ToUInt16(buffer, 20);
                    int pos = attrOffset;

                    while (pos < buffer.Length)
                    {
                        uint attrType = BitConverter.ToUInt32(buffer, pos);
                        if (attrType == 0xFFFFFFFF) break;

                        uint attrLen = BitConverter.ToUInt32(buffer, pos + 4);
                        if (attrType == 0x30) // FILE_NAME
                        {
                            int contentOffset = BitConverter.ToUInt16(buffer, pos + 20);
                            int fn = pos + contentOffset;

                            long parentRef = BitConverter.ToInt64(buffer, fn) & 0xFFFFFFFFFFFF;
                            DateTime c = FromFileTime(fn + 8, buffer);
                            DateTime m = FromFileTime(fn + 16, buffer);
                            DateTime mft = FromFileTime(fn + 24, buffer);
                            DateTime a = FromFileTime(fn + 32, buffer);

                            byte nameLen = buffer[fn + 64];
                            string name = Encoding.Unicode.GetString(buffer, fn + 66, nameLen * 2);

                            Entries[index] = new MFTEntry
                            {
                                Index = index,
                                Parent = parentRef,
                                Name = name,
                                InUse = inUse,
                                Created = c,
                                Modified = m,
                                MFTModified = mft,
                                Accessed = a
                            };
                            break;
                        }
                        pos += (int)attrLen;
                    }
                    index++;
                }
            }
        }

        static void ResolvePaths()
        {
            foreach (var e in Entries.Values)
                e.FullPath = BuildPath(e);
        }

        static string BuildPath(MFTEntry e)
        {
            if (!Entries.ContainsKey(e.Parent) || e.Parent == e.Index)
                return e.Name;

            return BuildPath(Entries[e.Parent]) + "\\" + e.Name;
        }

        static DateTime FromFileTime(int offset, byte[] buf)
        {
            long ft = BitConverter.ToInt64(buf, offset);
            return DateTime.FromFileTimeUtc(ft);
        }
    }

    class MFTEntry
    {
        public long Index;
        public long Parent;
        public string Name;
        public bool InUse;
        public DateTime Created, Modified, MFTModified, Accessed;
        public string FullPath;

        public override string ToString()
        {
            return string.Format(
                "[{0}] {1}\n  Created: {2}\n  Modified: {3}\n  MFT Mod: {4}\n",
                InUse ? "ACTIVE" : "DELETED",
                FullPath,
                Created, Modified, MFTModified);
        }
    }
}
