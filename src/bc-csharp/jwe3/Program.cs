﻿using System;
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

            W7DIDCommMessage msg = new W7DIDCommMessage();
            msg.ID = Guid.NewGuid().ToString();
            msg.type = "https://example.org/example/1.0/hello";
            msg.from = ALICE_DID;
            msg.to.Add(BOB_DID);
            msg.created_time = (long)(DateTime.Now.Subtract(DateTime.UnixEpoch)).TotalSeconds;
            msg.expires_time = msg.created_time + 30 /* days*/ * 24 * 60 * 60;
            msg.body = W7Util.Base64Encode(plaintext);

            // JWE using Microsoft: https://www.scottbrady91.com/c-sharp/json-web-encryption-jwe-in-dotnet-core
            var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation
            var Alice_signingKid = Guid.NewGuid().ToString(); // "29b4adf8bcc941dc8ce40a6d0227b6d3";
            var Alice_privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = Alice_signingKid };
            var Alice_publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = Alice_signingKid };

            var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
            var Bob_encryptionKid = Guid.NewGuid().ToString(); // "8524e3e6674e494f85c5c775dcd602c5";
            var Bob_privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = Bob_encryptionKid };
            var Bob_publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = Bob_encryptionKid };

            var handler = new JsonWebTokenHandler();

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = ALICE_DID,
                Audience = BOB_DID,
                Claims = new Dictionary<string, object> { { "body", plaintext } },

                // private key for signing
                SigningCredentials = new SigningCredentials(Alice_privateSigningKey, SecurityAlgorithms.EcdsaSha256),

                // public key for encryption
                EncryptingCredentials = new EncryptingCredentials(
                    Bob_publicEncryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            });

            W7DIDCommMessageJWE em = new W7DIDCommMessageJWE(ALICE_DID, token);

            TokenValidationResult result = handler.ValidateToken(
                em.Token,
                new TokenValidationParameters
                {
                    ValidIssuer = em.SenderID,
                    ValidAudience = BOB_DID,

                    // Alice's public key to verify signature
                    IssuerSigningKey = Alice_publicSigningKey,

                    // Bob's private key for decryption
                    TokenDecryptionKey = Bob_privateEncryptionKey
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