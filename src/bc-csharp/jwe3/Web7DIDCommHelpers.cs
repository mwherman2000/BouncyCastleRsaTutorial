using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
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
    }

    public class W7DIDCommAttachmentData
    {
        public string jws;
        public string hash;
        public string links;
        public string base64;
        public string json;
    }

    public class W7DIDCommAttachment
    {
        public string ID;
        public string description;
        public string filename;
        public string media_type;
        public string format;
        public long lastmod_time;
        public W7DIDCommAttachmentData data;
        public long byte_count;
    }

    public class W7DIDCommMessage
    {
        public string ID; // required
        public string type; // required
        public List<string> to;
        public string from;
        public string thid;
        public string pthid;
        public long created_time;
        public long expires_time;
        public string body;
        public List<W7DIDCommAttachment> attachments;

        public W7DIDCommMessage()
        {
            this.to = new List<string>();
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

}
