using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using System.IO;
using NSoup;
using NSoup.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Threading;
using NSoup.Select;
using Org.BouncyCastle.Math;

namespace Json
{
    class Program
    {
        static int LogCount = 100;
        static int WritedCount = 0;
        static int FailedCount = 0;

        static  int MAX_ENCRYPT_BLOCK = 117;

        static  int MAX_DECRYPT_BLOCK = 128;

        //static string ALGORITHM = "RSA";

        static void Main(string[] args)
        {
            /*
            string rsaPubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4ibrnwu+zsL5V0vmnwunr/bGB374VaXmIOUD/weA7/tLcrsGW2RLv+OKpMsPSqaFknrpDrco1QEJsqZ/VJ3dH2JmIW90lIMenqUWna1jMskXtkSRK6fPs30noNtz3/x+4DE0MrByArGPhyF1Rl69xO0GvPNoOURUx7eQrUM+9vwIDAQAB";
            string rsaPriKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALiJuufC77OwvlXS+afC6ev9sYHfvhVpeYg5QP/B4Dv+0tyuwZbZEu/44qkyw9KpoWSeukOtyjVAQmypn9Und0fYmYhb3SUgx6epRadrWMyyRe2RJErp8+zfSeg23Pf/H7gMTQysHICsY+HIXVGXr3E7Qa882g5RFTHt5CtQz72/AgMBAAECgYA0XAfnKH1gq75llZX2jqxWpEXQRs6lPqcYCr6xkq3v9+6WZRNSnMbtxd1yCpBbXnwHk63f9BiSoWf3cu2Byk/iXAos602yXzu0C7XXuqTb7JOf8XapCPl0YhKVbiw6GEiaWahLrTkoe0dXl1RmzL63WxUuUq/c9VF1E0ggUFEA+QJBAOuNJZryOJ1+TASa46gLWejOdopLJDkJTAExCQrj6E1DQq11Do9Mc9OPQ2UdHMkooIWQZ87wKa8RrL20aBRnNtUCQQDIjt8M7mzZ4X6sxwXIjbEa1jCCnsyTjugh/0WPtPAUEPwzyPRNnpbCnOCZMMkJGUTMCv5wEpDtGBG2iY641NRDAkA6q9mmEpdPg1nj+8Cg5tLqTiLwp27KVip8UX5zG/mM5SgClJmfz+c51wFueiXlZR02p5Vz0hZP6RMh3YHfMyZRAkEAtzHBzlcO+KpAAmQ9BSdgCcpyPy38YiCcK0m4aX71+O5W4JqDhU8CGLwhb+yfBX+eVt8H8KkU1m0w6NKXmn9VbwJAb1QnQhrE/klm6PEd1jPtANppE98LC2jJfHPhd9rH1xsPIaVN3hiodqf1coXc/JIZxV7MAcxQg6IlxqpHHV/wKg==";

            //RSACryptoService rsaEn = new RSACryptoService(rsaPriKey);
            RSACryptoService rsaDe = new RSACryptoService(null, rsaPubKey);
            string plainText = "just test";
            // string enText = rsaEn.Encrypt(plainText);
            string enText = "AjIG+OcPXc6XNhuiWPwRelFwMbBxJLupmqJR0nz2w0j37hoGbTJ6pGhH9xkgJtddjiPwzsA4X97HaW/5vqDdjZbmplQ8C81/mhEydrwcSDwDYwNzOegBGjerA4q6jJnQ7ZGXi2+ho0h9Yc5dHmWVb7qPIS7fl9QEPV31RcQBh9o=";
            string deText = rsaDe.PubDecrypt(enText);

            Console.WriteLine(enText);
            Console.WriteLine(deText);
            */


            /*
            string enstr = priEN("just test");
            Console.WriteLine(enstr);
            string destr = pukDE(enstr);
            Console.WriteLine(destr);*/
            //string cipherText = "KEMNssFAXDQFZO5Wza7fEy+EMi0bG4lG12/L4UwbMZiLWN1rjxxoe5K43wXDfPFyfR+ti0MzflOI9IoGEHYcU7riJNRq4S1k7vF0D5N9MQ54ZshgBdIlg7S0RNIagNr/olWkrJWH2+t4Fj5ap/ozGSe9VE+mMRHP1y078JN/GHch7/kkQexj0iC43ophTv9dcDHuGx8eKtOVi82YprWo2L9X5vSfR+XVzZl4vxrCFtfXcJw+ewzAFHKhm624LEtlJ26ufXdWcQXdD0os8YhTT3R7ErcVC4f0wAuVeHLhnLIe10G2lEpHE5JL6dGrQEtnbGXC5WhTf+TtCQqZLWlG8Q==";
            //RSACrypt("test");

            RSACryptoService.TestRSA();

        }

        






        static void RSACrypt(string input)
        {
            RsaKeyParameters pubKeySpec;


            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\rpuk.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubKeySpec = (RsaKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter pubKey = pubKeySpec;


            RsaPrivateCrtKeyParameters priKeySpec;
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\pri.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                priKeySpec = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter priKey = priKeySpec;
            
            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/NoPadding");

            cipher.Init(true, pubKey);
            byte[] byteArr = cipher.DoFinal(Encoding.UTF8.GetBytes(input));
            string output = Convert.ToBase64String(byteArr);
            Console.WriteLine(output);

            cipher.Init(false, priKey);
             byteArr = cipher.DoFinal(byteArr);
            output = System.Text.Encoding.UTF8.GetString(byteArr);
              Console.WriteLine(output);


            /*
            Byte[] PlaintextData = Convert.FromBase64String(input);
            int MaxBlockSize = MAX_DECRYPT_BLOCK;    //加密块最大长度限制

            if (PlaintextData.Length <= MaxBlockSize)
            {

                output = System.Text.Encoding.UTF8.GetString(cipher.DoFinal(PlaintextData));
                Console.WriteLine(output);
            }
            else
            {
                using (MemoryStream PlaiStream = new MemoryStream(PlaintextData))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);

                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);


                        Byte[] Cryptograph = cipher.DoFinal(ToEncrypt);


                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);

                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }
                    String str = System.Text.Encoding.UTF8.GetString(CrypStream.ToArray());
                    Console.WriteLine(str);



                }
            }*/
        }


       static ReaderWriterLockSlim LogWriteLock = new ReaderWriterLockSlim();
        static void test()
        {
            try {
                LogWriteLock.EnterWriteLock();
                WriteLog();
            }
            finally
            {
                //退出写入模式，释放资源占用
                //注意：一次请求对应一次释放
                //      若释放次数大于请求次数将会触发异常[写入锁定未经保持即被释放]
                //      若请求处理完成后未释放将会触发异常[此模式不下允许以递归方式获取写入锁定]
                LogWriteLock.ExitWriteLock();
            }
        }
        static void WriteLog()
        {
            try
            {
                //LogWriteLock.EnterWriteLock();
                var logFilePath = "log.txt";
                var now = DateTime.Now;
                var logContent = string.Format("Tid: {0}{1} {2}.{3}\r\n", Thread.CurrentThread.ManagedThreadId.ToString().PadRight(4), now.ToLongDateString(), now.ToLongTimeString(), now.Millisecond.ToString());
                File.AppendAllText(logFilePath, logContent);
                WritedCount++;
            }
            catch (Exception ex)
            {
                FailedCount++;
                Console.WriteLine(ex.Message);
            }
            
        }
        public void test1()
        {
            for (int i = 1; i < 7; i++)
                Console.WriteLine("test1 第{0}次",i);
        }
        public void test2()
        {
            
            for (int i = 1; i < 100; i++);

            Console.WriteLine("test2 第次");
        }
        public void test3()
        {
            
            for (int i = 1; i < 7; i++)
                Console.WriteLine("test3 第{0}次", i);
        }
        public static string CusRandom(int n)
        {
            Random ran = new Random(30);
            string value = "";
            for (int i = 0; i < n; ++i)
            {
                value += ran.Next(10);
            }
            return value;
        }

        //base64
        public static void Encode()
        {
            byte[] by = {48,129,159,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,129,141,0,48,129,137,2,129,129,0,159,69,55,92,60,129,245,210,4,253,127,125,107,66,226,8,156,188,30,237,249,118,118,209,9,247,120,19,154,49,61,115,97,254,144,181,68,53,104,4,10,34,85,67,155,40,157,3,95,193,58,12,41,211,180,111,115,165,127,138,96,4,167,139,78,26,218,207,242,247,157,130,88,149,186,163,28,45,227,78,53,39,101,205,37,186,233,169,92,107,40,199,173,190,62,228,134,6,87,219,243,50,78,234,24,177,224,101,127,190,28,144,84,42,70,245,166,42,128,78,243,201,52,89,97,127,91,201,2,3,1,0,1};
            string str = Convert.ToBase64String(by);
            Console.WriteLine(str);

        }
        public static void Decode()
        {
            string str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfRTdcPIH10gT9f31rQuIInLwe7fl2dtEJ93gTmjE9c2H+kLVENWgECiJVQ5sonQNfwToMKdO0b3Olf4pgBKeLThraz/L3nYJYlbqjHC3jTjUnZc0luumpXGsox62+PuSGBlfb8zJO6hix4GV/vhyQVCpG9aYqgE7zyTRZYX9byQIDAQAB";
            byte[] by = Convert.FromBase64String(str);
            str = "";
            for (int i = 0; i < by.Length; ++i)
            {
                str = str + "," + by[i];
            }
            Console.WriteLine(str);

        }

        //公钥加密，私钥解密
        public static string pukEN(string str)
        {
            // 加载公钥
            RsaKeyParameters pubkey;
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\rpuk.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubkey = (RsaKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter pukey = pubkey;
            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            cipher.Init(true, pubkey);

            // 加密message
            var message = Encoding.UTF8.GetBytes(str);
            var output = Encrypt(message, cipher);
            Console.WriteLine(Convert.ToBase64String(output));
            return Convert.ToBase64String(output);

        }
        public static string priDE(string str)
        {
            // 加载公钥
            RsaPrivateCrtKeyParameters prikey;
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\pri.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                prikey = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter prkey = prikey;
            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            cipher.Init(false, prkey);

            // 加密message
           /* var message = Encoding.UTF8.GetBytes("just test");
            var output = Encrypt(message, cipher);
            Console.WriteLine(Convert.ToBase64String(output));*/

            //解密
            var text = Encoding.UTF8.GetBytes(str);
             var deByte = Encrypt(text, cipher);
             Console.WriteLine(System.Text.Encoding.UTF8.GetString(deByte));
            return System.Text.Encoding.UTF8.GetString(deByte);
        }


        //公钥解密，私钥加密
        public static string pukDE(string str)
        {
            // 加载公钥
            RsaKeyParameters pubkey;
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\rpuk.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubkey = (RsaKeyParameters)pemReader.ReadObject();
            }

            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            cipher.Init(false, pubkey);

            // 加密message
           /*  var message = Encoding.UTF8.GetBytes(str);
            var output = Encrypt(message, cipher);
            Console.WriteLine(Convert.ToBase64String(output));
            return Convert.ToBase64String(output);*/
            //解密
            var text = Encoding.UTF8.GetBytes(str);
             var deByte = Encrypt(text, cipher);
             Console.WriteLine(System.Text.Encoding.Default.GetString(deByte));
            return System.Text.Encoding.Default.GetString(deByte);

        }
        public static string priEN(string str)
        {
            // 加载公钥
            RsaKeyParameters pubkey;
            
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\pri.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubkey = (RsaKeyParameters)pemReader.ReadObject();
            }
            AsymmetricKeyParameter pukey = pubkey;
            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            cipher.Init(true, pukey);

            // 加密message
             var message = Encoding.UTF8.GetBytes(str);
             var output = Encrypt(message, cipher);
             Console.WriteLine(Convert.ToBase64String(output));
             return Convert.ToBase64String(output);

            //解密
            /*var text = Encoding.UTF8.GetBytes(str);
            var deByte = Encrypt(text, cipher);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(deByte));
            return System.Text.Encoding.UTF8.GetString(deByte);*/
        }
        public static void pk()
        {
            // 加载公钥
            RsaKeyParameters pubkey;
            using (var sr = new StreamReader(@"C:\Users\shizuniao\Desktop\rpuk.pem"))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                pubkey = (RsaKeyParameters)pemReader.ReadObject();
            }

            // 初始化cipher
            var cipher = (BufferedAsymmetricBlockCipher)CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

            cipher.Init(true, pubkey);

            // 加密message
            var message = Encoding.UTF8.GetBytes("just test");
            var output = Encrypt(message, cipher);
            Console.WriteLine(Convert.ToBase64String(output));

            //解密
           /* var text = Encoding.UTF8.GetBytes("AjIG+OcPXc6XNhuiWPwRelFwMbBxJLupmqJR0nz2w0j37hoGbTJ6pGhH9xkgJtddjiPwzsA4X97HaW/5vqDdjZbmplQ8C81/mhEydrwcSDwDYwNzOegBGjerA4q6jJnQ7ZGXi2+ho0h9Yc5dHmWVb7qPIS7fl9QEPV31RcQBh9o=");
            var deByte = Encrypt(text, cipher);
            Console.WriteLine(System.Text.Encoding.Default.GetString(deByte));*/

        }
        // 利用CryptoStream进行加密
        public static byte[] Encrypt(byte[] message, BufferedAsymmetricBlockCipher cipher)
        {
            using (var buffer = new MemoryStream())
            {
                using (var transform = new BufferedCipherTransform(cipher))
                using (var stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
                using (var messageStream = new MemoryStream(message))
                    messageStream.CopyTo(stream);
                return buffer.ToArray();
            }
        }
        // 利用CryptoStream进行解密
        public static byte[] Decrypt(byte[] message, BufferedAsymmetricBlockCipher cipher)
        {
            using (var buffer = new MemoryStream())
            {
                using (var transform = new BufferedCipherTransform(cipher))
                using (var stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
                using (var messageStream = new MemoryStream(message))
                    messageStream.CopyTo(stream);
                return buffer.ToArray();
            }
        }

        public static string RandomMac()
        {
            char[] arr = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
            Random ran = new Random();

            string mac = "";
            for (int i = 0; i < 12; ++i)
            {
                Random mRan = new Random(ran.Next() * i);
                int n = mRan.Next(arr.Length - 1);
                Console.WriteLine(arr[n]);
                if (i % 2 == 0 && i != 0)
                    mac = mac + ":" + arr[n];
                else
                    mac = mac + arr[n];
            }
            Console.WriteLine(mac);
            return mac;
        }
        public static void CaDate(int Year,int Month)
        {
            string date = "";
            for (int i = 0; i < 6; ++i)
            {
                if (1 <= (Month - i) && (Month - i) <= 9)
                    date = Year.ToString() + "0" + (Month - i).ToString();
                else if (10 <= (Month - i) && (Month - i) <= 12)
                    date = Year.ToString() + (Month - i).ToString();
                else if (-2 <= (Month - i) && (Month - i) <= 0)
                    date = (Year - 1).ToString() + (Month - i + 12).ToString();
                else
                    date = (Year - 1).ToString() + "0" + (Month - i + 12).ToString();
                Console.WriteLine(date);
            }

        }
        public static void testAH()
        {
            string rsp = File.ReadAllText(@"C:\Users\shizuniao\Desktop\ah.txt");
            Dictionary<string, object> ParserInfo = new Dictionary<string, object>();
            JObject obj = JObject.Parse(rsp);
                 JArray ar = JArray.Parse(obj["result"].ToString());
                 if(ar.Count != 0)
                { 
                 JObject cobj = JObject.Parse(ar[0].ToString());
                 
                 ParserInfo["Opposite"] = cobj["otherParty"];
                 ParserInfo["Place"] = cobj["callPlace"];
                 ParserInfo["Call_begin"] = cobj["startDate"];
                 ParserInfo["Call_used"] = cobj["duration"];
                 ParserInfo["InitType"] = cobj["fee1"];
                 ParserInfo["Start_mode"] = cobj["trafficWay"];
                 ParserInfo["Charge_mode"] = cobj["callClass"];
            }
            else
            {
                Console.WriteLine("无记录");
            }
            Console.WriteLine(JsonConvert.SerializeObject(ParserInfo));
        }
        public static string StringToHexString(string s, Encoding encode)
        {
            byte[] b = encode.GetBytes(s);//按照指定编码将string编程字节数组
            string result = string.Empty;
            for (int i = 0; i < b.Length; i++)//逐字节变为16进制字符，以%隔开
            {
                Console.WriteLine(b[i]);
                result += "%" + Convert.ToString(b[i], 16);
            }
            Console.WriteLine(result);
            return result;
        }
        public static string CurTimeMillis()
        {
            long timeMills = (System.DateTime.UtcNow.Ticks - new DateTime(1970, 1, 1, 0, 0, 0).Ticks) / 10000;
            return timeMills.ToString();
        }
        public static void varParam(int i,params string[]extend)
        {
            Console.WriteLine("start");
            switch (i)
            {
                case 1:
                    Console.WriteLine(extend[0]);
                    break;
                case 2:
                    Console.WriteLine(extend[0]);
                    Console.WriteLine(extend[1]);
                    break;
            }
        }

        /*
          public void testDes()
        {

            //string param = "souKVM9C3tOm78xNOdA+AhKiUVL0WXSCQ4Z/fejfONb88TgJkYfyYrePE45vB23kdsX2+xmRwH944QwrpJEcEUEEC7XzLLjQdLdbzWlOck6tZ7hTtw7eyMMfz/kV51L/fnAb29NeNvi/GNva+q4O+0TdQtfsQpgqR758ZCuss6zedlqwPWgrNPHt0k2g0Q+1oP0Icy2/EGp/L82oimpRPWFLpFwf56u9UMeEAtA5MgKuvoo9zM87mqsohKqNERkaV1uZSPo5EgRkXLH4vip6aSlpdbQEo+pN+4LrsKwAvdhfs5H29tWbaDEYUHfb9NQTbjnyx2o4hdd+gal7RrPaLUv72NACytaqQFiR8xJZUBkvmvAEdq8DwLQvbJ3s+bVflgUo2IPUzd8H0xEU/IC+S+6VD3wiDqxfGdS7NF6ESZ+h8Bnn/CzRxi7K82HHBBSRITGiOcIl0OkfWBlk/hDiWRlCrrQPJZ83SslzRo5hrEwgemiUtc1HjPxyLxNFQxfQ3odYfjQDLWDwB5xtMu+aXx8VgIr+CUM6DZQuRvauUKBxEjsbbDZ7UOp60oTNCsptTPLDjT/GU8GrrohWkCJXwQswVuyOtLLPdhcGbjdSYKJc3JtjZxaYC459Q6Uw3RefXJy1EvpQD6Y=";
            string param = "souKVM9C3tOm78xNOdA+AhKiUVL0WXSCQ4Z/fejfONbL8j1a/6pzZxDzXVbqWNsOQXfTZOt2WVi1KxOyEAgFNSVxVl7C7bH2kXQ0FGM0Ys6tZ7hTtw7eyMMfz/kV51L/fnAb29NeNvi/GNva+q4O+0TdQtfsQpgqR758ZCuss6zedlqwPWgrNPHt0k2g0Q+1VZz1twculmTbYE9f4Ls4Cln1SEvTJgnfUMeEAtA5MgKuvoo9zM87mqsohKqNERkalRFXWqdBNffu3038uhvMK93S/wENub6ifd9MAX9OWk8zOMbXIU2PCjEYUHfb9NQTbjnyx2o4hdd+gal7RrPaLUv72NACytaqQFiR8xJZUBkvmvAEdq8DwLQvbJ3s+bVflgUo2IPUzd8H0xEU/IC+S+6VD3wiDqxfGdS7NF6ESZ+h8Bnn/CzRxi7K82HHBBSRITGiOcIl0OmPLCPQ6c65OaCPXemnagBsSslzRo5hrEwgemiUtc1HjPxyLxNFQxfQ3odYfjQDLWDwB5xtMu+aXx8VgIr+CUM6DZQuRvauUKBxEjsbbDZ7UOp60oTNCsptTPLDjT/GU8GrrohWkCJXwTYXvmi50+gO2yRivFc4GdQPN5EsTw2p7/vaZc5TzyDjni97IZ5P0Wo=";
            Console.WriteLine("原文：" + param);
            byte[] de = Utils.DesDecrypt(Convert.FromBase64String(param),Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(key),CipherMode.ECB,PaddingMode.PKCS7);
            string destr = System.Text.Encoding.UTF8.GetString(de);
            Console.WriteLine("解密："+destr);
            
            //string desstr = "auth=yes&appKey=11100&cstamp=1499411315819&sign=25923694388616E5C7607EF621DC0826&internet=wifi&sys_version=4.4.4&screen=0鑴?0&model=MI 5&imsi=460044766322333&imei=868395657423780&number=&deviceid=3F13F17A38FF351CD8F1381D010912AD&jsonParam=[{\"dynamicURI\":\"/smsPwdLogin\",\"dynamicParameter\":{\"method\":\"pwdLogin\",\"m\":\"uNe5VwAi89xYrvNfGl5F1A==\",\"p\":\"68716868696F36\",\"i\":\"\",\"c\":\"0\",\"deviceCode\":\"@5\",\"s\":\"1\"},\"dynamicDataNodeName\":\"pwdLogin_node\"}]&md5sign=8DD4334E834170C359DC546B1F019BF0";
           // for (int i = 0; i < 100; ++i)
            {
                string temp = Convert.ToBase64String(Utils.DesEncrypt(Encoding.UTF8.GetBytes(destr), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(key), CipherMode.ECB, PaddingMode.PKCS7));
                Console.WriteLine("加密：" + temp);
                if (!temp.Equals(param))
                    MessageBox.Show(temp);
            }
        }
        public void testMd5()
        {
            //test MD5
            string md5str1 = "11100android!@#3F13F17A38FF351CD8F1381D010912AD[{\"dynamicURI\":\"/smsPwdLogin\",\"dynamicParameter\":{\"method\":\"pwdLogin\",\"m\":\"uNe5VwAi89xYrvNfGl5F1A==\",\"p\":\"68716868696F36\",\"i\":\"\",\"c\":\"0\",\"deviceCode\":\"@5\",\"s\":\"1\"},\"dynamicDataNodeName\":\"pwdLogin_node\"}]";
            string md5str2 = "11100android!@#6965D7360A976C24E6C0492E00504901[{\"dynamicURI\":\"/smsPwdLogin\",\"dynamicParameter\":{\"method\":\"pwdLogin\",\"m\":\"uNe5VwAi89xYrvNfGl5F1A==\",\"p\":\"687268686A7037\",\"i\":\"\",\"c\":\"0\",\"deviceCode\":\"@5\",\"s\":\"1\"},\"dynamicDataNodeName\":\"pwdLogin_node\"}]";

            // for (int i = 0; i < 200; ++i)
            {
                Console.WriteLine(Utils.Md5Str(md5str1));
                Console.WriteLine(Utils.Md5Str(md5str2));
            }
        }
         */
    }
}
