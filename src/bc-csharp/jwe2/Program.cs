using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Runtime.CompilerServices;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using System.Security.Claims;

namespace bc_csharp1
{
    internal class Program
    {
        const int IvSize = 1024;

        static void Main(string[] args)
        {
            string plaintext = "{ \"message\": \"Hello world!\" }";
            byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);

            // JWT creation: https://www.scottbrady91.com/c-sharp/eddsa-for-jwt-signing-in-dotnet-core
            // private/public key generation
            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var issuerkeyPair = keyPairGenerator.GenerateKeyPair();

            var issuerkprivate = (Ed25519PrivateKeyParameters)issuerkeyPair.Private;
            var issuerkpublic = (Ed25519PublicKeyParameters)issuerkeyPair.Public;

            var handler = new JsonWebTokenHandler();

            // create JWT
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                Subject = new ClaimsIdentity(new[] { new Claim("body", plaintext), new Claim("weather", "sunny") }),

                // using JOSE algorithm "EdDSA"
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(issuerkprivate), ExtendedSecurityAlgorithms.EdDsa)
            });

            // validate JWT
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new EdDsaSecurityKey(issuerkpublic)
            });

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }
    }
}