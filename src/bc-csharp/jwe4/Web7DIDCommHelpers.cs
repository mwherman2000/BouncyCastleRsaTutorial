using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Web7.DIDComm
{
    public static class W7Util
    {
        // https://stackoverflow.com/questions/11743160/how-do-i-encode-and-decode-a-base64-string
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        // https://stackoverflow.com/questions/11743160/how-do-i-encode-and-decode-a-base64-string
        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public static string Base64EncodeBytes(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes);
        }

        public static byte[] Base64DecodeBytes(string byteString)
        {
            return System.Convert.FromBase64String(byteString);
        }

        public static long UNIX_time(DateTime t)
        {
            return (long)(t.Subtract(DateTime.UnixEpoch)).TotalSeconds;
        }

        public static RSA ConvertJWKToRSASecurityKey(JsonWebKey jsonWebKey)
        {
            // https://www.scottbrady91.com/c-sharp/rsa-key-loading-dotnet
            var rsaParameters = new RSAParameters
            {
                // PUBLIC KEY PARAMETERS
                // n parameter - public modulus
                Modulus = Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                // e parameter - public exponent
                Exponent = Base64UrlEncoder.DecodeBytes(jsonWebKey.E),

                // PRIVATE KEY PARAMETERS (optional)
                // d parameter - the private exponent value for the RSA key 
                D = Base64UrlEncoder.DecodeBytes(jsonWebKey.D),
                // dp parameter - CRT exponent of the first factor
                DP = Base64UrlEncoder.DecodeBytes(jsonWebKey.DP),
                // dq parameter - CRT exponent of the second factor
                DQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.DQ),
                // p parameter - first prime factor
                P = Base64UrlEncoder.DecodeBytes(jsonWebKey.P),
                // q parameter - second prime factor
                Q = Base64UrlEncoder.DecodeBytes(jsonWebKey.Q),
                // qi parameter - CRT coefficient of the second factor
                InverseQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.QI)
            };

            return RSA.Create(rsaParameters);
        }

        public static ECDsa ConvertJWKToEDSASecurityKey(JsonWebKey jsonWebKey)
        {
            // https://www.scottbrady91.com/c-sharp/ecdsa-key-loading
            var curve = jsonWebKey.Crv switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException()
            };

            var ecParameters = new ECParameters()
            {
                // crv parameter - public modulus
                Curve = curve,
                // d parameter - the private exponent value for the EC key 
                D = Base64UrlEncoder.DecodeBytes(jsonWebKey.D),
                // q parameter - second prime factor
                Q = new ECPoint()
                {
                    X = Base64UrlEncoder.DecodeBytes(jsonWebKey.X),
                    Y = Base64UrlEncoder.DecodeBytes(jsonWebKey.Y)
                }
            };

            return ECDsa.Create(ecParameters);
        }
    }

    public class W7DIDCommAttachmentData
    {
        public string jws { get; set; }
        public string hash { get; set; }
        public string links { get; set; }
        public string base64 { get; set; }
        public string json { get; set; }

        public W7DIDCommAttachmentData(string jws, string hash, string links, string base64, string json)
        {
            this.jws = jws;
            this.hash = hash;
            this.links = links;
            this.base64 = base64;
            this.json = json;
        }
    }

    public class W7DIDCommAttachment
    {
        public string id { get; set; }
        public string description { get; set; }
        public string filename { get; set; }
        public string media_type { get; set; }
        public string format { get; set; }
        public long lastmod_time { get; set; }
        public W7DIDCommAttachmentData data { get; set; }
        public long byte_count { get; set; }

        public W7DIDCommAttachment(string id, string description, string filename, string media_type, string format, long lastmod_time, W7DIDCommAttachmentData data, long byte_count)
        {
            this.id = id;
            this.description = description;
            this.filename = filename;
            this.media_type = media_type;
            this.format = format;
            this.lastmod_time = lastmod_time;
            this.data = data;
            this.byte_count = byte_count;
        }
    }

    public class W7DIDCommMessage
    {
        public string id { get; set; } // required
        public string type { get; set; } // required
        public List<string> to { get; set; }
        public string from { get; set; }
        public string thid { get; set; }
        public string pthid { get; set; }
        public long created_time { get; set; }
        public long expires_time { get; set; }
        public string body { get; set; }
        public List<W7DIDCommAttachment> attachments { get; set; }

        public W7DIDCommMessage()
        {
            this.to = new List<string>();
            this.attachments = new List<W7DIDCommAttachment>();
        }

        public W7DIDCommMessage(string id, string type, string from, List<string> to, string thid, string pthid, long created_time, long expires_time, string body)
        {
            this.id = id;
            this.type = type;
            this.to = to;
            this.from = from;
            this.thid = thid;
            this.pthid = pthid;
            this.created_time = created_time;
            this.expires_time = expires_time;
            this.body = body;
            this.attachments = new List<W7DIDCommAttachment>(); 
        }
    }

    public class W7DIDCommMessageJWE
    {
        private string senderID;
        private string token;

        public string SenderID { get => senderID; set => senderID = value; }
        public string Token { get => token; set => token = value; }

        public W7DIDCommMessageJWE(string senderID, string token)
        {
            this.senderID = senderID;
            this.token = token;
        }
    }

    public static class W7RSACrypo
    {
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=net-7.0
        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=net-7.0
        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }
        }
    }
}
