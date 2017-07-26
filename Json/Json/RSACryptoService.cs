using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Json
{
    public class RSACryptoService
    {
        static int MAX_ENCRYPT_BLOCK = 117;
        static int MAX_DECRYPT_BLOCK = 128;



        /*test case
         * 测试公钥，私钥加解密都可行，秘钥从文件和字串中都可行
         * 1.公钥加密，私钥解密，秘钥从文件中提取
         * 2.私钥加密，公钥解密，秘钥从文件中提取
         * 3.公钥加密，私钥解密，秘钥从字串中提取
         * 4.私钥加密，公钥解密，秘钥从字串中提取
         * 
         * 基于以上测试结果，测试分段加解密可行
         * 1.长字符，公钥加密，私钥解密，秘钥从文件中提取
         * 2.长字符，私钥加密，公钥解密，秘钥从文件中提取
         * 
         * 测试采用不同的算法模式可行
         * 1.长字符
         * 2.短字符
         */
        public static void TestRSA()
        {
#if true
            string privateKey = "MIICXQIBAAKBgQC7PyjMEuniN6BPn8oqzIZ6AO1NjSTO9R3adCCIwKfKIEoWXXM+tHDpktdPKSaAsWJPTNAGvEvtxOfzXib/EMXKqD0eUy5MatfpRjRdf1hJVimmfrb09Qx2j7CsKLy7nD23m4xubdYBwvkjMwt/L3JxB5D6qryW1wei/j1c+/OCxQIDAQABAoGAT7vGYJgRNf4f6qgNS4pKHTu10RcwPFyOOM7IZ9M5380+HyXuBB6MEjowKwpH1fcy+LepwaR+5KG7b5uBGY4H2ticMtdysBd9gLwnY4Eh4j7LCWE54HvELpeWXkWpFQdb/NQhcqMAGwYsTnRPdBqkrUmJBTYqEGkIlqCQ5vUJOCECQQDhe0KGmbq1RWp6TDvgpA2dUmlt2fdP8oNW8O7MvbDaQRduoZnVRTPYCDKfzFqpNXL1hAYgth1N0vzDnv3VoLcpAkEA1JcY+rLv5js1g5Luv8LaI5/3uOg0CW7fmh/LfGuz8k/OxASN+cAOUjPHrxtc5xn1zat4/bnV5GEdlOp/DhquPQJBAIV2Fsdi4M+AueiPjPWHRQO0jvDVjfwFOFZSn5YSRUa6NmtmPY6tumUJXSWWqKb1GwlVTuc3xBqXYsNLLUWwLhkCQQDJUJCiD0LohhdGEqUuSKnj5H9kxddJO4pZXFSI7UEJbJQDwcBkyn+FTm2BH+tZGZdQfVnlA89OJr0poOpSg+eNAkAKY85SR9KASaTiDBoPpJ8N805XEhd0Kq+ghzSThxL3fVtKUQLiCh7Yd8oMd/G5S3xWJHUXSioATT8uPRH2bOb/";
            string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7PyjMEuniN6BPn8oqzIZ6AO1NjSTO9R3adCCIwKfKIEoWXXM+tHDpktdPKSaAsWJPTNAGvEvtxOfzXib/EMXKqD0eUy5MatfpRjRdf1hJVimmfrb09Qx2j7CsKLy7nD23m4xubdYBwvkjMwt/L3JxB5D6qryW1wei/j1c+/OCxQIDAQAB";
            //LoadPrivateKeyByString(privateKey);
            string text = "test";

            //公钥加密，私钥解密，从字串加载
            byte[] cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPublicKeyByString(publicKey), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            byte[] plainText = RSACrypt(cipherText, LoadPrivateKeyByString(privateKey), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));

            //私钥加密，公钥解密，从字串加载
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPrivateKeyByString(privateKey), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPublicKeyByString(publicKey), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));

            string longText = "The code is almost the same. However, even when I provide exactly the same modulus and exponent for both, the result arrays are completely different also the strings";
            //公钥加密，私钥解密，从字串加载，分段加密
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(longText), LoadPublicKeyByString(publicKey), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPrivateKeyByString(privateKey), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));

            //私钥加密，公钥解密，从字串加载，分段加密
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(longText), LoadPrivateKeyByString(privateKey), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPublicKeyByString(publicKey), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));


            //公钥加密，私钥解密，从字串加载,RSA/ECB/PKCS1Padding
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPublicKeyByString(publicKey), "RSA/ECB/PKCS1Padding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPrivateKeyByString(privateKey), "RSA/ECB/PKCS1Padding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));

#else
            string text = "test";

            string publicStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChDzcjw/rWgFwnxunbKp7/4e8w/UmXx2jk6qEEn69t6N2R1i/LmcyDT1xr/T2AHGOiXNQ5V8W4iCaaeNawi7aJaRhtVx1uOH/2U378fscEESEG8XDqll0GCfB1/TjKI2aitVSzXOtRs8kYgGU78f7VmDNgXIlk3gdhnzh+uoEQywIDAQAB";
            string privateStr = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKEPNyPD+taAXCfG6dsqnv/h7zD9SZfHaOTqoQSfr23o3ZHWL8uZzINPXGv9PYAcY6Jc1DlXxbiIJpp41rCLtolpGG1XHW44f/ZTfvx+xwQRIQbxcOqWXQYJ8HX9OMojZqK1VLNc61GzyRiAZTvx/tWYM2BciWTeB2GfOH66gRDLAgMBAAECgYBp4qTvoJKynuT3SbDJY/XwaEtmu768SF9P0GlXrtwYuDWjAVue0VhBI9WxMWZTaVafkcP8hxX4QZqPh84td0zjcq3jDLOegAFJkIorGzq5FyK7ydBoU1TLjFV459c8dTZMTu+LgsOTD11/V/Jr4NJxIudoMBQ3c4cHmOoYv4uzkQJBANR+7Fc3e6oZgqTOesqPSPqljbsdF9E4x4eDFuOecCkJDvVLOOoAzvtHfAiUp+H3fk4hXRpALiNBEHiIdhIuX2UCQQDCCHiPHFd4gC58yyCM6Leqkmoa+6YpfRb3oxykLBXcWx7DtbX+ayKy5OQmnkEG+MW8XB8wAdiUl0/tb6cQFaRvAkBhvP94Hk0DMDinFVHlWYJ3xy4pongSA8vCyMj+aSGtvjzjFnZXK4gIjBjA2Z9ekDfIOBBawqp2DLdGuX2VXz8BAkByMuIh+KBSv76cnEDwLhfLQJlKgEnvqTvXTB0TUw8avlaBAXW34/5sI+NUB1hmbgyTK/T/IFcEPXpBWLGO+e3pAkAGWLpnH0ZhFae7oAqkMAd3xCNY6ec180tAe57hZ6kS+SYLKwb4gGzYaCxc22vMtYksXHtUeamo1NMLzI2ZfUoX";

            //公钥加密，私钥解密，从文件加载
            byte[] cipherText = RSACrypt(Encoding.UTF8.GetBytes(text),LoadPublicKeyByFile(@"C:\Users\shizuniao\Desktop\rpuk.pem"), "RSA/ECB/NoPadding",true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            
            byte[] plainText = RSACrypt(cipherText, LoadPrivateKeyByFile(@"C:\Users\shizuniao\Desktop\pri.pem"), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));

            //私钥加密，公钥解密，从文件加载
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPrivateKeyByFile(@"C:\Users\shizuniao\Desktop\pri.pem"), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPublicKeyByFile(@"C:\Users\shizuniao\Desktop\rpuk.pem"), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(plainText));
/*
            //公钥加密，私钥解密，从字串加载
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPublicKeyByString(publicStr), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPrivateKeyByString(privateStr), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(cipherText));

            //私钥加密，公钥解密，从字串加载
            cipherText = RSACrypt(Encoding.UTF8.GetBytes(text), LoadPrivateKeyByString(privateStr), "RSA/ECB/NoPadding", true);
            Console.WriteLine(Convert.ToBase64String(cipherText));
            plainText = RSACrypt(cipherText, LoadPublicKeyByString(publicStr), "RSA/ECB/NoPadding", false);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(cipherText));
*/
#endif
        }

        //从文件中加载公钥，文件格式目前只支持.pem
        public static AsymmetricKeyParameter LoadPublicKeyByFile(string fPath)
        {
            RsaKeyParameters pubKeySpec;
            using (var sr = new StreamReader(fPath))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubKeySpec = (RsaKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter pubKey = pubKeySpec;

            return pubKey;
        }

        //从文件中加载私钥，文件格式目前只支持.pem，私钥格式必须为PKCS #8
        public static AsymmetricKeyParameter LoadPrivateKeyByFile(string fPath)
        {
            RsaPrivateCrtKeyParameters priKeySpec;
            using (var sr = new StreamReader(fPath))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                priKeySpec = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter priKey = priKeySpec;

            return priKey;
        }

        
        public static AsymmetricKeyParameter LoadPublicKeyByString(string publicKeyStr)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] x509key;
            byte[] seq = new byte[15];
            int x509size;

            x509key = Convert.FromBase64String(publicKeyStr);
            x509size = x509key.Length;

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream mem = new MemoryStream(x509key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    RsaKeyParameters pubKeySpec = new RsaKeyParameters(false, new BigInteger(1,modulus), new BigInteger(1,exponent));
                    AsymmetricKeyParameter pubKey = pubKeySpec;
                    return pubKey;
                }

            }
        }

        //从字串中获取私钥，私钥格式必须为PKCS #1
        public static AsymmetricKeyParameter LoadPrivateKeyByString(string privateKeyStr)
        {
            var privateKeyBits = System.Convert.FromBase64String(privateKeyStr);

            //var RSA = new RSACryptoServiceProvider();
            var RSAparams = new RSAParameters();

            using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)
                    binr.ReadByte();
                else if (twobytes == 0x8230)
                    binr.ReadInt16();
                else
                    throw new Exception("Unexpected value read binr.ReadUInt16()");

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)
                    throw new Exception("Unexpected version");

                bt = binr.ReadByte();
                if (bt != 0x00)
                    throw new Exception("Unexpected value read binr.ReadByte()");

                RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
            }
            Console.WriteLine(RSAparams.Modulus.Length);
            RsaPrivateCrtKeyParameters priKeySpec = new RsaPrivateCrtKeyParameters(new BigInteger(1,RSAparams.Modulus), new BigInteger(1,RSAparams.Exponent), new BigInteger(1,RSAparams.D),
                new BigInteger(1,RSAparams.P), new BigInteger(1,RSAparams.Q), new BigInteger(1,RSAparams.DP), new BigInteger(1,RSAparams.DQ), new BigInteger(1,RSAparams.InverseQ));

            AsymmetricKeyParameter priKey = priKeySpec;

            return priKey;
        }
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte();
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
        /*支持私钥和公钥加密，支持私钥和公钥解密，支持分段加密
         * plaintextData：明文或密文
         * key: 传入公钥或私钥
         * algorithm: 采用的算法，如RSA、RSA/ECB/NoPadding等
         * crypt: true表示加密，false表示解密
        */
        public static byte[] RSACrypt(byte[] plaintextData, AsymmetricKeyParameter key, string algorithm, bool crypt)
        {
            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher(algorithm);
            cipher.Init(crypt, key);

            int maxBlock = 0;
            if (crypt)
                maxBlock = MAX_ENCRYPT_BLOCK;
            else
                maxBlock = MAX_DECRYPT_BLOCK;

            if (plaintextData.Length <= maxBlock)
            {
                return cipher.DoFinal(plaintextData);
            }
            else
            {
                using (MemoryStream PlaiStream = new MemoryStream(plaintextData))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[maxBlock];
                    int BlockSize = PlaiStream.Read(Buffer, 0, maxBlock);

                    while (BlockSize > 0)
                    {
                        Byte[] ToCrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToCrypt, 0, BlockSize);


                        Byte[] Cryptograph = cipher.DoFinal(ToCrypt);


                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);

                        BlockSize = PlaiStream.Read(Buffer, 0, maxBlock);
                    }
                    return CrypStream.ToArray();
                }
            }
        }

    }
}
