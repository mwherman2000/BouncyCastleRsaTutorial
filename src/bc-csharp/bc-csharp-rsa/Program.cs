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

namespace bc_csharp1
{
    internal class Program
    {
        const int IvSize = 1024;

        static void Main(string[] args)
        {
            string plaintext = "Hello world!";
            byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);

            // 1. Generate Key Pair using Rsa: https://www.youtube.com/watch?v=oicefquvEsY
            SecureRandom random = new SecureRandom();
            RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new KeyGenerationParameters(random, IvSize));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            // 2: PEM Serialize Keys: https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
            //AsymmetricKeyParameter kprivate = kp.Private;
            //AsymmetricKeyParameter kpublic = kp.Public;
            RsaKeyParameters kprivate = (RsaKeyParameters)kp.Private;
            RsaKeyParameters kpublic = (RsaKeyParameters)kp.Public;

            StringWriter stringWriter = new StringWriter();
            PemWriter pw = new PemWriter(stringWriter);
            pw.WriteObject(kprivate);
            pw.Writer.Flush();
            string skprivate = stringWriter.ToString();
            Console.WriteLine(skprivate);

            stringWriter = new StringWriter();
            pw = new PemWriter(stringWriter);
            pw.WriteObject(kpublic);
            pw.Writer.Flush();
            string skpublic = stringWriter.ToString();
            Console.WriteLine(skpublic);

            // 3a. Sign with Private Key: https://artofcode.wordpress.com/2017/05/26/rsa-signatures-in-java-with-bouncy-castle/
            RsaDigestSigner signer = new RsaDigestSigner(new Sha512Digest());
            signer.Init(true, kprivate);
            signer.BlockUpdate(plaintextbytes, 0, plaintextbytes.Length);
            byte[] signatureprivate = signer.GenerateSignature();

            // 3b. Verify with Public Key: https://artofcode.wordpress.com/2017/05/26/rsa-signatures-in-java-with-bouncy-castle/
            RsaDigestSigner verifier = new RsaDigestSigner(new Sha512Digest());
            verifier.Init(false, kpublic);
            verifier.BlockUpdate(plaintextbytes, 0, plaintextbytes.Length);
            bool verify = verifier.VerifySignature(signatureprivate);
            Console.WriteLine(verify.ToString());

            // 4a. Encrypt with Public key: https://www.youtube.com/watch?v=oicefquvEsY
            IAsymmetricBlockCipher ecipher = new OaepEncoding(new RsaEngine());
            ecipher.Init(true, kpublic);
            byte[] eciphertextbytes = ecipher.ProcessBlock(plaintextbytes, 0, plaintextbytes.Length);
            string sciphertext = BitConverter.ToString(eciphertextbytes).Replace("-", "");
            Console.WriteLine(sciphertext);

            // 4b. Decrypt with Private key: https://www.youtube.com/watch?v=oicefquvEsY
            IAsymmetricBlockCipher dcipher = new OaepEncoding(new RsaEngine());
            dcipher.Init(false, kprivate);
            byte[] dciphertextbytes = dcipher.ProcessBlock(eciphertextbytes, 0, eciphertextbytes.Length);
            string stext = Encoding.UTF8.GetString(dciphertextbytes);
            Console.WriteLine(stext);

            // 5a. Serialize keys: https://www.rahulsingla.com/blog/2011/04/serializingdeserializing-rsa-publicprivate-keys-generated-using-bouncy-castle-library/
            PrivateKeyInfo kprivateinfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kprivate);
            byte[] kprivatebytes = kprivateinfo.ToAsn1Object().GetDerEncoded();
            string kprivatebytes64 = Convert.ToBase64String(kprivatebytes);
            Console.WriteLine(kprivatebytes64);

            SubjectPublicKeyInfo kpublicinfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kpublic);
            byte[] kpublicbytes = kpublicinfo.ToAsn1Object().GetDerEncoded();
            string kpublicbytes64 = Convert.ToBase64String(kpublicbytes);
            Console.WriteLine(kpublicbytes64);

            // 5b. Deserialize keys: https://www.rahulsingla.com/blog/2011/04/serializingdeserializing-rsa-publicprivate-keys-generated-using-bouncy-castle-library/
            RsaPrivateCrtKeyParameters kprivate2 = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(kprivatebytes64));
            RsaKeyParameters kpublic2 = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(kpublicbytes64));

            stringWriter = new StringWriter();
            pw = new PemWriter(stringWriter);
            pw.WriteObject(kprivate2);
            pw.Writer.Flush();
            string skprivate2 = stringWriter.ToString();
            Console.WriteLine(skprivate2);
            Console.WriteLine((skprivate == skprivate2).ToString());

            stringWriter = new StringWriter();
            pw = new PemWriter(stringWriter);
            pw.WriteObject(kpublic2);
            pw.Writer.Flush();
            string skpublic2 = stringWriter.ToString();
            Console.WriteLine(skpublic2);
            Console.WriteLine((skpublic == skpublic2).ToString());

            // 5c. Serialize/deserialize to JSON: https://kashifsoofi.github.io/cryptography/rsa-encryption-in-csharp-using-bouncycastle/

            // 99. Miscellaneous: https://tekshinobi.com/reading-rsa-key-pair-from-pem-files-in-net-with-c-using-bouncy-castle/

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }
    }
}
