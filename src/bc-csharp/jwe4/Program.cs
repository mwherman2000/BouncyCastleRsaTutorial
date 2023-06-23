using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using Web7.DIDComm;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.VisualBasic;
using System.Net.Mail;
using System.Reflection;

namespace bc_csharp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            const string DID_KEYID_ENCRYPT = "did:web7:keyid:encrypt:";
            const string DID_KEYID_SIGN = "did:web7:keyid:sign:";

            const string DID_SUBJECT = "did:web7:subject:";
            const string DID_PERSON = DID_SUBJECT + "person:";
            const string DID_ALICE = DID_PERSON + "1234";
            const string DID_BOB = DID_PERSON + "4567";

            const string DID_DIDCOMM = "did:web7:didcomm:";
            const string DID_MESSAGEID = DID_DIDCOMM + "messageid:";
            const string DID_ATTACHMENTID = DID_DIDCOMM + "attachmentid:";
            const string DID_THID = DID_DIDCOMM + "thid:";

            const string MESSAGE_TYPE = "https://example.org/example/1.0/hello";

            string plaintext = "{ \"message\": \"Hello world!\" }";
            byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);

            // 0. Create a Web 7.0 (unencrypted) DIDComm Message (with Attachment)
            DateTime now = DateTime.Now;
            W7DIDCommMessage msg = new W7DIDCommMessage(
                DID_MESSAGEID + Guid.NewGuid().ToString(),
                MESSAGE_TYPE,
                DID_ALICE,
                new List<string>() { DID_BOB },
                DID_THID + Guid.NewGuid().ToString(),
                "",
                W7Util.UNIX_time(now),
                W7Util.UNIX_time(now.AddDays(30)),
                W7Util.Base64Encode(plaintext)
            );
            string text64 = W7Util.Base64Encode("Foo bar!");
            W7DIDCommAttachmentData d = new W7DIDCommAttachmentData("", "", "", text64, "");
            W7DIDCommAttachment a = new W7DIDCommAttachment(
                DID_ATTACHMENTID + Guid.NewGuid().ToString(),
                "Attachment abc",
                "abc.txt",
                "text/plain",
                "",
                W7Util.UNIX_time(now),
                d,
                0
            );
            msg.attachments.Add( a );

            string msgJson = JsonSerializer.Serialize<W7DIDCommMessage>(msg);
            Console.WriteLine(msgJson);

            // JWE using Microsoft: https://www.scottbrady91.com/c-sharp/json-web-encryption-jwe-in-dotnet-core
            int bytesRead;

            // 1. Create ECDsa signing keys (Alice)
            var Alice_signingKid = DID_KEYID_SIGN + Guid.NewGuid().ToString(); // "29b4adf8bcc941dc8ce40a6d0227b6d3";
            Console.WriteLine("Alice kid: " + Alice_signingKid);
            ECDsa Alice_signingKeyPrivate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECDsa Alice_signingKeyPublic = ECDsa.Create(Alice_signingKeyPrivate.ExportParameters(false));
            ECDsaSecurityKey Alice_privateSigningKey = new ECDsaSecurityKey(Alice_signingKeyPrivate) { KeyId = Alice_signingKid };
            ECDsaSecurityKey Alice_publicSigningKey = new ECDsaSecurityKey(Alice_signingKeyPublic) { KeyId = Alice_signingKid };

            // 2. Signing an arbitrary string (or byte array)
            var hash = SHA256.HashData(plaintextbytes);
            var hashsig = Alice_signingKeyPrivate.SignHash(hash);
            bool hashv1 = Alice_signingKeyPrivate.VerifyHash(hash, hashsig);
            bool hashv2 = Alice_signingKeyPublic.VerifyHash(hash, hashsig);

            byte[] sig = Alice_signingKeyPrivate.SignData(plaintextbytes, HashAlgorithmName.SHA256);
            bool v1 = Alice_signingKeyPrivate.VerifyData(plaintextbytes, sig, HashAlgorithmName.SHA256);
            bool v2 = Alice_signingKeyPublic.VerifyData(plaintextbytes, sig, HashAlgorithmName.SHA256);

            // 3. Serialize signing EDsaSecurityKey as JsonWebKey
            byte[] Alice_signingPrivateKeyExported = Alice_signingKeyPrivate.ExportECPrivateKey(); // Exports public and private keys
            ECDsa Alice_signingKey2 = ECDsa.Create();
            Alice_signingKey2.ImportECPrivateKey(Alice_signingPrivateKeyExported, out bytesRead); // Imports public and private keys
            ECDsaSecurityKey Alice_privateSigningKey2 = new ECDsaSecurityKey(Alice_signingKey2) { KeyId = Alice_signingKid };
            ECDsaSecurityKey Alice_publicSigningKey2 = new ECDsaSecurityKey(ECDsa.Create(Alice_signingKey2.ExportParameters(false))) { KeyId = Alice_signingKid };

            JsonWebKey Alice_signingKeyPWK2 = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(Alice_publicSigningKey2);
            ECDsaSecurityKey Alice_signingKey3 = new ECDsaSecurityKey(Alice_signingKeyPrivate);
            JsonWebKey Alice_signingKeyPWK3 = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(Alice_signingKey3);
            string Alice_signingKeyJson3 = JsonSerializer.Serialize(Alice_signingKeyPWK3);
            Console.WriteLine(Alice_signingKeyJson3);

            // 4. Desearilize signing JsonWebKey as EDsaSecurityKey
            // https://www.scottbrady91.com/c-sharp/ecdsa-key-loading
            ECDsa Alice_signingKey4 = W7Util.ConvertJWKToEDSASecurityKey(Alice_signingKeyPWK3);
            ECDsaSecurityKey Alice_privateSigningKey4 = new ECDsaSecurityKey(Alice_signingKey4) { KeyId = Alice_signingKid };
            ECDsaSecurityKey Alice_publicSigningKey4 = new ECDsaSecurityKey(ECDsa.Create(Alice_signingKey4.ExportParameters(false))) { KeyId = Alice_signingKid };

            // 5. Create RSA encryption keys (Bob)
            var Bob_encryptionKid = DID_KEYID_ENCRYPT + Guid.NewGuid().ToString(); // "8524e3e6674e494f85c5c775dcd602c5";
            Console.WriteLine("Bob kid: " + Bob_encryptionKid);
            RSA Bob_encryptionKeyPrivate = RSA.Create(3072);
            RSA Bob_encryptionKeyPublic = RSA.Create(Bob_encryptionKeyPrivate.ExportParameters(false));
            RsaSecurityKey Bob_privateEncryptionKey = new RsaSecurityKey(Bob_encryptionKeyPrivate) { KeyId = Bob_encryptionKid };
            RsaSecurityKey Bob_publicEncryptionKey = new RsaSecurityKey(Bob_encryptionKeyPublic) { KeyId = Bob_encryptionKid };

            // 6. Serialize encryption RSASecurityKey as a JsonWebKey
            byte[] Bob_encryptionPrivateKeyExported =  Bob_encryptionKeyPrivate.ExportRSAPrivateKey(); // Exports public and private keys
            var Bob_encryptionPrivateKey2 = RSA.Create();
            Bob_encryptionPrivateKey2.ImportRSAPrivateKey(Bob_encryptionPrivateKeyExported, out bytesRead); // Imports public and private keys
            RsaSecurityKey Bob_privateEncryptionKey2 = new RsaSecurityKey(Bob_encryptionPrivateKey2) { KeyId = Bob_encryptionKid };
            RsaSecurityKey Bob_publicEncryptionKey2 = new RsaSecurityKey(Bob_encryptionPrivateKey2.ExportParameters(false)) { KeyId = Bob_encryptionKid };

            JsonWebKey Bob_encryptionPublicKeyPWK2 = JsonWebKeyConverter.ConvertFromRSASecurityKey(Bob_publicEncryptionKey2);
            RsaSecurityKey Bob_encryptionKey3 = new RsaSecurityKey(Bob_encryptionKeyPrivate);
            JsonWebKey Bob_encryptionKeyPWK3 = JsonWebKeyConverter.ConvertFromRSASecurityKey(Bob_encryptionKey3);
            string Bob_encryptionKeyJson3 = JsonSerializer.Serialize(Bob_encryptionKeyPWK3);
            Console.WriteLine(Bob_encryptionKeyJson3);

            // 7a. Encrypt an arbitrary string (byte array) using public RSA key
            byte[] bytesEncrypted = W7RSACrypo.RSAEncrypt(plaintextbytes, Bob_encryptionKeyPrivate.ExportParameters(false), false);

            // 7b. Decrypt an encrypted string (byte array) using private RSA key
            byte[] bytesDecrypted = W7RSACrypo.RSADecrypt(bytesEncrypted, Bob_encryptionKeyPrivate.ExportParameters(true), false);
            string textDecrypted = Encoding.UTF8.GetString(bytesDecrypted);
            Console.WriteLine(textDecrypted);

            // 8. Deserialize encryption JsonWebKey into an RSASecurityKey
            // https://stackoverflow.com/questions/64217089/what-is-the-correct-way-to-transform-jwk-to-rsa-key-value-pair
            RSA Bob_encryptionKey4 = W7Util.ConvertJWKToRSASecurityKey(Bob_encryptionKeyPWK3);
            RsaSecurityKey Bob_privateEncryptionKey4 = new RsaSecurityKey(Bob_encryptionKey4) { KeyId = Bob_encryptionKid };
            RsaSecurityKey Bob_publicEncryptionKey4 = new RsaSecurityKey(Bob_encryptionKey4.ExportParameters(false)) { KeyId = Bob_encryptionKid };

            // 9. Create (encode) authcrypted JWE token for DIDComm Message (with Attachment)
            var handler = new JsonWebTokenHandler();

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = DID_ALICE,
                Audience = DID_BOB,
                Claims = new Dictionary<string, object> { { "body", msgJson } },

                // private key for signing
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(Alice_signingKeyPrivate) { KeyId = Alice_signingKid }, // Alice_privateSigningKey, 
                SecurityAlgorithms.EcdsaSha256),

                // public key for encryption
                EncryptingCredentials = new EncryptingCredentials(new RsaSecurityKey(Bob_encryptionKeyPublic) { KeyId = Bob_encryptionKid }, // Bob_publicEncryptionKey, 
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            });

            // 10. Add Web 7.0 DIDComm JWE header
            W7DIDCommMessageJWE em = new W7DIDCommMessageJWE(DID_ALICE, token);
            string[] tokenparts = em.Token.Split('.');
            // https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.base64urlencoder?view=msal-web-dotnet-latest
            string spart = Base64UrlEncoder.Decode(tokenparts[0]);
            Console.WriteLine("0:JOSE Header: " + spart);
            int index = 0;
            foreach (string part in tokenparts)
            {
                Console.WriteLine(index.ToString() + ": " + part);
                index++;
            }

            // 11. Validate (decode) authcrypted JWE token for DIDComm Message (with Attachment)
            TokenValidationResult result = handler.ValidateToken(
                em.Token,
                new TokenValidationParameters
                {
                    ValidIssuer = em.SenderID,
                    ValidAudience = DID_BOB,

                    // Alice's public key to verify signature
                    IssuerSigningKey = Alice_publicSigningKey4, // Alice_publicSigningKey2,

                    // Bob's private key for decryption
                    TokenDecryptionKey = Bob_privateEncryptionKey4 // Bob_privateEncryptionKey2
                });

            Console.WriteLine("SenderID: " + em.SenderID);
            if (result.IsValid)
            {
                Console.WriteLine("Issuer (iss): " + result.Claims["iss"].ToString());
                Console.WriteLine("Audience (aud): " + result.Claims["aud"].ToString());
            }
            else
            {
                Console.WriteLine("Invalid JWE Message");
            }

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }
    }
}