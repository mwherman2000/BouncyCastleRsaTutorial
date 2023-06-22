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

namespace bc_csharp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            const string ALICE_DID = "did:person:1234";
            const string BOB_DID = "did:person:4567";

            string plaintext = "{ \"message\": \"Hello world!\" }";
            byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);

            DateTime now = DateTime.Now;
            W7DIDCommMessage msg = new W7DIDCommMessage(
                Guid.NewGuid().ToString(),
                "https://example.org/example/1.0/hello",
                ALICE_DID,
                new List<string>() { BOB_DID },
                Guid.NewGuid().ToString(),
                "",
                W7Util.UNIX_time(now),
                W7Util.UNIX_time(now.AddDays(30)),
                W7Util.Base64Encode(plaintext)
            );
            string text64 = W7Util.Base64Encode("Foo bar!");
            W7DIDCommAttachmentData d = new W7DIDCommAttachmentData("", "", "", text64, "");
            W7DIDCommAttachment a = new W7DIDCommAttachment(
                Guid.NewGuid().ToString(),
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
            var Alice_signingKid = Guid.NewGuid().ToString(); // "29b4adf8bcc941dc8ce40a6d0227b6d3";
            Console.WriteLine("Alice kid: " + Alice_signingKid);
            ECDsa Alice_signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation
            var Alice_privateSigningKey = new ECDsaSecurityKey(Alice_signingKey) { KeyId = Alice_signingKid };
            var Alice_publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(Alice_signingKey.ExportParameters(false))) { KeyId = Alice_signingKid };

            byte[] Alice_signingPrivateKeyExported = Alice_signingKey.ExportECPrivateKey(); // Exports public and private keys
            ECDsa Alice_signingKey2 = ECDsa.Create();
            Alice_signingKey2.ImportECPrivateKey(Alice_signingPrivateKeyExported, out bytesRead); // Imports public and private keys
            var Alice_privateSigningKey2 = new ECDsaSecurityKey(Alice_signingKey2) { KeyId = Alice_signingKid };
            var Alice_publicSigningKey2 = new ECDsaSecurityKey(ECDsa.Create(Alice_signingKey2.ExportParameters(false))) { KeyId = Alice_signingKid };

            var Bob_encryptionKid = Guid.NewGuid().ToString(); // "8524e3e6674e494f85c5c775dcd602c5";
            Console.WriteLine("Bob kid: " + Bob_encryptionKid);
            var Bob_encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
            var Bob_privateEncryptionKey = new RsaSecurityKey(Bob_encryptionKey) { KeyId = Bob_encryptionKid };
            var Bob_publicEncryptionKey = new RsaSecurityKey(Bob_encryptionKey.ExportParameters(false)) { KeyId = Bob_encryptionKid };

            byte[] Bob_encryptionPrivateKeyExported =  Bob_encryptionKey.ExportRSAPrivateKey(); // Exports public and private keys
            var Bob_encryptionKey2 = RSA.Create();
            Bob_encryptionKey2.ImportRSAPrivateKey(Bob_encryptionPrivateKeyExported, out bytesRead); // Imports public and private keys
            var Bob_privateEncryptionKey2 = new RsaSecurityKey(Bob_encryptionKey2) { KeyId = Bob_encryptionKid };
            var Bob_publicEncryptionKey2 = new RsaSecurityKey(Bob_encryptionKey2.ExportParameters(false)) { KeyId = Bob_encryptionKid };

            var handler = new JsonWebTokenHandler();

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = ALICE_DID,
                Audience = BOB_DID,
                Claims = new Dictionary<string, object> { { "body", msgJson } },

                // private key for signing
                SigningCredentials = new SigningCredentials(Alice_privateSigningKey, SecurityAlgorithms.EcdsaSha256),

                // public key for encryption
                EncryptingCredentials = new EncryptingCredentials(
                    Bob_publicEncryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            });

            string[] tokenparts = token.Split('.');
            int index = 0;
            foreach (string part in tokenparts)
            {
                Console.WriteLine(index.ToString() + ": " + part);
                if (index == 0)
                {
                    // https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.base64urlencoder?view=msal-web-dotnet-latest
                    string spart = Base64UrlEncoder.Decode(part);
                    Console.WriteLine(index.ToString() + ": " + spart);
                }
                index++;
            }


            W7DIDCommMessageJWE em = new W7DIDCommMessageJWE(ALICE_DID, token);

            TokenValidationResult result = handler.ValidateToken(
                em.Token,
                new TokenValidationParameters
                {
                    ValidIssuer = em.SenderID,
                    ValidAudience = BOB_DID,

                    // Alice's public key to verify signature
                    IssuerSigningKey = Alice_publicSigningKey2,

                    // Bob's private key for decryption
                    TokenDecryptionKey = Bob_privateEncryptionKey2
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