// =============================================================================
//  JetPwd - recover the database password of a Microsoft Access (Jet 3 / Jet 4)
//           .mdb file from its header (offline, no engine, no OLEDB).
//
//  Jet header layout used:
//    * offset 0x04 = "Standard Jet DB"   (magic; we check 'S','t','a' + 'J','e')
//    * offset 0x14 = engine version byte  (0 = Jet3/Access97, 1 = Jet4/2000-2003)
//    * offset 0x42 = encrypted database password
//        - Jet3: single XOR with an 85-byte key (1-byte ASCII chars)
//        - Jet4: 40-byte block (UCS-2, up to ~18 chars) XOR a 40-byte key, with
//          an extra per-position "date salt" derived from the two encrypted
//          bytes that sit where chars 18/19 (the creation-date words) live:
//              v3 = key4[36] ^ enc[36]
//              v5 = key4[37] ^ enc[37]
//              out[i] = enc[i] ^ key4[i]
//              if (i % 4 == 0) out[i] ^= v3
//              if (i % 4 == 1) out[i] ^= v5
//          (i%4 == 2/3 get no salt -> those bytes are date-independent.)
//
//  Usage:  JetPwd <file1.mdb> [file2.mdb ...]
// =============================================================================

using System;
using System.IO;
using System.Text;

internal static class Program
{
    // Jet 4.0 key (40 bytes)
    private static readonly byte[] Key4 =
    {
        0xBA,0x6A,0xEC,0x37,0x61,0xD5,0x9C,0xFA,0xFA,0xCF,0x28,0xE6,0x2F,0x27,0x8A,0x60,
        0x68,0x05,0x7B,0x36,0xC9,0xE3,0xDF,0xB1,0x4B,0x65,0x13,0x43,0xF3,0x3E,0xB1,0x33,
        0x08,0xF0,0x79,0x5B,0xAE,0x24,0x7C,0x2A
    };

    // Jet 3.0 key (85 bytes)
    private static readonly byte[] Key3 =
    {
        0x86,0xFB,0xEC,0x37,0x5D,0x44,0x9C,0xFA,0xC6,0x5E,0x28,0xE6,0x13,0xB6,0x8A,0x60,
        0x54,0x94,0x7B,0x36,0x3D,0x7B,0xDF,0xB1,0x77,0xF4,0x13,0x43,0xCF,0xAF,0xB1,0x33,
        0x34,0x61,0x79,0x5B,0x92,0xB5,0x7C,0x2A,0x05,0xF1,0x7C,0x99,0x01,0x1B,0x98,0xFD,
        0x12,0x4F,0x4A,0x94,0x6C,0x3E,0x60,0x26,0x5F,0x95,0xF8,0xD0,0x89,0x24,0x85,0x67,
        0xC6,0x1F,0x27,0x44,0xD2,0xEE,0xCF,0x65,0xED,0xFF,0x07,0xC7,0x46,0xA1,0x78,0x16,
        0x0C,0xED,0xE9,0x2D,0x00
    };

    private const int PwOffset = 0x42;

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: JetPwd <file1.mdb> [file2.mdb ...]");
            return 1;
        }

        int rc = 0;
        foreach (string path in args)
        {
            Console.WriteLine($"== {path} ==");
            if (!File.Exists(path)) { Console.WriteLine("   [!] not found"); rc = 2; continue; }
            try
            {
                byte[] hdr = ReadHeader(path, 0x100);
                if (!(hdr[4] == (byte)'S' && hdr[5] == (byte)'t' && hdr[6] == (byte)'a'
                      && hdr[13] == (byte)'J' && hdr[14] == (byte)'e'))
                {
                    Console.WriteLine("   [!] not a Standard Jet DB (.mdb)");
                    rc = 3; continue;
                }

                byte engine = hdr[0x14];                 // 0=Jet3, 1=Jet4
                string ver  = engine == 0 ? "Jet 3 (Access 97)"
                            : engine == 1 ? "Jet 4 (Access 2000-2003)"
                            : $"unknown(0x{engine:X2})";
                Console.WriteLine($"   engine    : {ver}");

                string pw = engine == 0 ? DecodeJet3(hdr) : DecodeJet4(hdr);
                if (string.IsNullOrEmpty(pw))
                    Console.WriteLine("   password  : (none / not protected)");
                else
                    Console.WriteLine($"   password  : {pw}   [len={pw.Length}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   [!] {ex.GetType().Name}: {ex.Message}");
                rc = 4;
            }
        }
        return rc;
    }

    private static byte[] ReadHeader(string path, int n)
    {
        using var fs = File.OpenRead(path);
        byte[] b = new byte[n];
        int read = fs.Read(b, 0, n);
        if (read < PwOffset + 40)
            throw new IOException("file too small for a Jet header");
        return b;
    }

    // 40-byte UCS-2 block with date-salt on positions i%4 == 0/1.
    private static string DecodeJet4(byte[] hdr)
    {
        byte[] enc = new byte[40];
        Array.Copy(hdr, PwOffset, enc, 0, 40);

        byte v3 = (byte)(Key4[36] ^ enc[36]);
        byte v5 = (byte)(Key4[37] ^ enc[37]);

        byte[] dec = new byte[40];
        for (int i = 0; i < 40; i++)
        {
            byte d = (byte)(enc[i] ^ Key4[i]);
            if (i % 4 == 0) d ^= v3;
            else if (i % 4 == 1) d ^= v5;
            dec[i] = d;
        }

        // UCS-2 little-endian: char k = dec[2k] | dec[2k+1]<<8, stop at NUL.
        var sb = new StringBuilder(20);
        for (int k = 0; k < 20; k++)
        {
            int ch = dec[2 * k] | (dec[2 * k + 1] << 8);
            if (ch == 0) break;
            sb.Append((char)ch);
        }
        return sb.ToString();
    }

    // single XOR against the 85-byte key, 1-byte ASCII chars.
    private static string DecodeJet3(byte[] hdr)
    {
        var sb = new StringBuilder(40);
        for (int i = 0; i < Key3.Length; i++)
        {
            byte d = (byte)(hdr[PwOffset + i] ^ Key3[i]);
            if (d == 0) break;
            sb.Append((char)d);
        }
        return sb.ToString();
    }
}
