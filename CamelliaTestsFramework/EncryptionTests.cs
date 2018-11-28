using CamelliaManaged;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CamelliaTests
{
    [TestClass]
    public class EncryptionTests
    {
        public struct Test
        {
            public byte[] P; // Plaintext
            public byte[] C; // expected Ciphertext
        }

        public struct TestBank
        {
            public byte[] Key;
            public Test[] Data;
        }

#if DEBUG
        [TestMethod]
        public void SelfTest() // working 11/20/2018 11:35 AM
        {
            Assert.IsTrue(Camellia.RunSelfTests());
        }
#endif

        [TestMethod]
        public void EncryptIntermediate128BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] result = Camellia.EncryptBlock(P, P);
            Assert.IsTrue(compareArrays(result, 
                new byte[16] { 0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43 }, out int FirstDiff));
        }

        [TestMethod]
        public void DecryptIntermediate128BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[] { 0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43 };
            byte[] K = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] result = Camellia.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }, out int FirstDiff));
        }

        [TestMethod]
        public void EncryptIntermediate192BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] K = new byte[24] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
            byte[] result = Camellia.EncryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8, 0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9 }, out int FirstDiff));
        }

        [TestMethod]
        public void DecryptIntermediate192BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[16] { 0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8, 0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9 };
            byte[] K = new byte[24] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
            byte[] result = Camellia.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }, out int FirstDiff));
        }

        [TestMethod]
        public void EncryptIntermediate256BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
            byte[] K = new byte[32] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
            byte[] result = Camellia.EncryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c, 0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09 }, out int FirstDiff));
        }

        [TestMethod]
        public void DecryptIntermediate256BitKey() // working 11/20/2018 11:35 AM
        {
            byte[] P = new byte[16] { 0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c, 0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09 };
            byte[] K = new byte[32] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
            byte[] result = Camellia.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }, out int FirstDiff));
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_NullData() // working 11/20/2018 11:35 AM
        {
            Camellia.EncryptBlock(null, new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_InvalidDataLength() // working 11/20/2018 11:35 AM
        {
            Camellia.EncryptBlock(new byte[3], new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_NullKey() // working 11/20/2018 11:35 AM
        {
            Camellia.EncryptBlock(new byte[16], null);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_InvalidKeyLength() // working 11/20/2018 11:35 AM
        {
            Camellia.EncryptBlock(new byte[16], new byte[1]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_NullData() // working 11/20/2018 11:35 AM
        {
            Camellia.DecryptBlock(null, new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_InvalidDataLength() // working 11/20/2018 11:35 AM
        {
            Camellia.DecryptBlock(new byte[3], new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_NullKey() // working 11/20/2018 11:35 AM
        {
            Camellia.DecryptBlock(new byte[16], null);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_InvalidKeyLength() // working 11/20/2018 11:35 AM
        {
            Camellia.DecryptBlock(new byte[16], new byte[1]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        public void zzz_Encrypt128bitKeys() // working 11/20/2018 11:35 AM
        {
            // setup
            //all test data is in TestSources128
            TestSources128 myTest = new TestSources128();
            // process
            int passedTests = 0; // should equal 128 tests per key * 10 kets
            int failedTests = 0; // should be 0
            // observe

            // confirm
            for (int b = 0; b <= myTest.Banks128.GetUpperBound(0); b++)
            {
                for (int d = 0; d <= myTest.Banks128[b].Data.GetUpperBound(0); d++)
                {
                    byte[] result = CamelliaManaged.Camellia.EncryptBlock(myTest.Banks128[b].Data[d].P, myTest.Banks128[b].Key);
                    bool outCome = compareArrays(result, myTest.Banks128[b].Data[d].C, out int FirstDiff);
                    
                    Assert.IsTrue(outCome, string.Format(
                        "TestBank128 #{0} FAILED at test #{1} at byte #{2} (all arrays are ZERO indexed).",
                        b,d,FirstDiff));
                    if (outCome) passedTests++; else failedTests++;
                }
            }
            Assert.IsTrue(passedTests == 128 * 10, "Unexpected number of passed tests: {passedTests}");
        }

        [TestMethod]
        public void zzz_Encrypt192bitKeys() // working 11/20/2018 11:35 AM
        {
            // setup
            //all test data is in TestSources128
            TestSources192 myTest = new TestSources192();
            // process
            int passedTests = 0; // should equal 128 tests per key * 10 kets
            int failedTests = 0; // should be 0
            // observe

            // confirm
            for (int b = 0; b <= myTest.Banks192.GetUpperBound(0); b++)
            {
                for (int d = 0; d <= myTest.Banks192[b].Data.GetUpperBound(0); d++)
                {
                    byte[] result = CamelliaManaged.Camellia.EncryptBlock(myTest.Banks192[b].Data[d].P, myTest.Banks192[b].Key);
                    bool outCome = compareArrays(result, myTest.Banks192[b].Data[d].C, out int FirstDiff);
                    Assert.IsTrue(outCome, string.Format(
                        "TestBank192 #{0} FAILED at test #{1} at byte #{2} (all arrays are ZERO indexed).",
                        b, d, FirstDiff));
                    if (outCome) passedTests++; else failedTests++;
                }
            }
            Assert.IsTrue(passedTests == 128 * 10, "Unexpected number of passed tests: {passedTests}");
        }

        [TestMethod]
        public void zzz_Encrypt256bitKeys() // working 11/20/2018 11:35 AM
        {
            // setup
            //all test data is in TestSources256
            TestSources256 myTest = new TestSources256();
            // process
            int passedTests = 0; // should equal 128 tests per key * 10 kets
            int failedTests = 0; // should be 0
            // observe

            // confirm
            for (int b = 0; b <= myTest.Banks256.GetUpperBound(0); b++)
            {
                for (int d = 0; d <= myTest.Banks256[b].Data.GetUpperBound(0); d++)
                {
                    byte[] result = CamelliaManaged.Camellia.EncryptBlock(myTest.Banks256[b].Data[d].P, myTest.Banks256[b].Key);
                    bool outCome = compareArrays(result, myTest.Banks256[b].Data[d].C, out int FirstDiff);
                    Assert.IsTrue(outCome, string.Format(
                        "TestBank256 #{0} FAILED at test #{1} at byte #{2} (all arrays are ZERO indexed).",
                        b, d, FirstDiff));
                    if (outCome) passedTests++; else failedTests++;
                }
            }
            Assert.IsTrue(passedTests == 128 * 10, "Unexpected number of passed tests: {passedTests}");
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
