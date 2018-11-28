using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CamelliaManaged;
using System.Diagnostics;
namespace CamelliaConsoleTester
{
    public class Program
    {
        static void Main(string[] args)
        {
            if (!Camellia.RunSelfTests())
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** SELFTEST FAILED****");
            }
            else
                Console.WriteLine("SELF TEST OK!");
            byte[] P = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] K1 = new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] K2 = new byte[24] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
            byte[] K3 = new byte[32] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] result; int FirstDiff;

            result = Camellia.EncryptBlock(P, K1);
            if (!compareArrays(result, new byte[] { 0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43 }, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 1 FAILED****");
            }
            else
                Console.WriteLine("FULL ENCRYPTION TEST 1 OK!");
            result = Camellia.DecryptBlock(result, K1);
            if (!compareArrays(result, P, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 1 FAILED****");
            }
            else
                Console.WriteLine("FULL DECRYPTION TEST 1 OK!");


            result = Camellia.EncryptBlock(P, K2);
            if (!compareArrays(result, new byte[] { 0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8, 0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9 }, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 2 FAILED ****");
            }
            else
                Console.WriteLine("FULL ENCRYPTION TEST 2 OK!");
            result = Camellia.DecryptBlock(result, K2);
            if (!compareArrays(result, P, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 2 FAILED****");
            }
            else
                Console.WriteLine("FULL DECRYPTION TEST 2 OK!");


            result = Camellia.EncryptBlock(P, K3);
            if (!compareArrays(result, new byte[] { 0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c, 0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09 }, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 3 FAILED ****");
            }
            else
                Console.WriteLine("FULL ENCRYPTION TEST 3 OK!");
            result = Camellia.DecryptBlock(result, K3);
            if (!compareArrays(result, P, out FirstDiff))
            {
                //throw new Exception("FAILED TEST");
                Console.WriteLine("*** TEST 3 FAILED****");
            }
            else
                Console.WriteLine("FULL DECRYPTION TEST 3 OK!");


            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }

        private static bool compareArrays(byte[] a, byte[] b, out int firstDifference)
        {
            firstDifference = -1;
            if (a.Length != b.Length)
            {
                firstDifference = (int)Math.Min(a.Length, b.Length);
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    firstDifference = i;
                    return false;
                }
            }
            return true;
        }
    }
}
