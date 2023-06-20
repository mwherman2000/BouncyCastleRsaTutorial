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

namespace bc_csharp1
{
    internal class Program
    {
        const int IvSize = 1024;

        static void Main(string[] args)
        {
            string plaintext = "Hello world!";
            byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);

            // 1. Generate Key Pair using Ed25519: https://www.youtube.com/watch?v=oicefquvEsY
            SecureRandom random = new SecureRandom();
            Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
            kpg.Init(new KeyGenerationParameters(random, IvSize));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            // https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
            //AsymmetricKeyParameter kprivate = kp.Private;
            //AsymmetricKeyParameter kpublic = kp.Public;
            Ed25519PrivateKeyParameters kprivate = (Ed25519PrivateKeyParameters)kp.Private;
            Ed25519PublicKeyParameters kpublic = (Ed25519PublicKeyParameters)kp.Public;

            StringWriter stringWriter = new StringWriter();
            PemWriter pw = new PemWriter(stringWriter);
            pw.WriteObject(kprivate);
            pw.Writer.Flush();
            string sprivate = stringWriter.ToString();
            Console.WriteLine(sprivate);

            stringWriter = new StringWriter();
            pw = new PemWriter(stringWriter);
            pw.WriteObject(kpublic);
            pw.Writer.Flush();
            string spublic = stringWriter.ToString();
            Console.WriteLine(spublic);

            // 2. Serialize keys to byte arrays: https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
            byte[] bprivate = kprivate.GetEncoded();
            byte[] bpublic = kpublic.GetEncoded();

            // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
            sprivate = BitConverter.ToString(bprivate).Replace("-", "");
            spublic = BitConverter.ToString(bpublic).Replace("-", "");
            Console.WriteLine(sprivate);
            Console.WriteLine(spublic);

            // 3a. Sign with Private Key: https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
            Ed25519Signer signer = new Ed25519Signer();
            signer.Init(true, kprivate);
            signer.BlockUpdate(plaintextbytes, 0, plaintextbytes.Length);
            byte[] signatureprivate = signer.GenerateSignature();

            // 3b. Verify with Public Key: https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.Init(false, kpublic);
            verifier.BlockUpdate(plaintextbytes, 0, plaintextbytes.Length);
            bool verify = verifier.VerifySignature(signatureprivate);

            // 4a. Encrypt with Public key
            // Not possible with ED25519 - signatures only

            // 4b. Decrypt with Private key
            // Not possible with ED25519 - signatures only

            // 5. Deserialize keys: https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }
    }
}
