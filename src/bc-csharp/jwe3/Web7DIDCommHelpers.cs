using Microsoft.IdentityModel.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Reflection;
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
        public string ID { get; set; }
        public string description { get; set; }
        public string filename { get; set; }
        public string media_type { get; set; }
        public string format { get; set; }
        public long lastmod_time { get; set; }
        public W7DIDCommAttachmentData data { get; set; }
        public long byte_count { get; set; }

        public W7DIDCommAttachment(string ID, string description, string filename, string media_type, string format, long lastmod_time, W7DIDCommAttachmentData data, long byte_count)
        {
            this.ID = ID;
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
        public string ID { get; set; } // required
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

        public W7DIDCommMessage(string ID, string type, string from, List<string> to, string thid, string pthid, long created_time, long expires_time, string body)
        {
            this.ID = ID;
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

}
