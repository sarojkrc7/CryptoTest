using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Core
{
    /// <summary>
    /// The rsa crypto utils.
    /// </summary>
    public static class RsaCryptoUtils
    {
        /// <summary>
        /// Encryption algorithm: RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING
        /// </summary>
        public const string AlgorithmRsaNoneOaepWithSha256AndMgf1Padding = "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING";

        /// <summary>
        /// Signing algorithm: SHA-256withRSA
        /// </summary>
        public const string AlgorithmSHA256withRSA = "SHA-256withRSA";

        /// <summary>
        /// Generates the r s a key pair.
        /// </summary>
        /// <param name="keyLengthInBits">The key length in bits.</param>
        /// <returns>An AsymmetricCipherKeyPair.</returns>
        public static AsymmetricCipherKeyPair GenerateRSAKeyPair(int keyLengthInBits = 2048)
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), keyLengthInBits)); // key length in bits

            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// Generates the r s a key pair der.
        /// </summary>
        /// <param name="keyLengthInBits">The key length in bits.</param>
        /// <returns>A (string base64PublicKey, string base64PrivateKey) .</returns>
        public static (string base64PublicKey, string base64PrivateKey) GenerateRSAKeyPairDer(int keyLengthInBits = 2048)
        {
            var (publicKeyBytes, privateKeyBytes) = GenerateRSAKeyPairDerBytes(keyLengthInBits);

            var publicKey = Convert.ToBase64String(publicKeyBytes);
            var privateKey = Convert.ToBase64String(privateKeyBytes);

            return (publicKey, privateKey);
        }

        /// <summary>
        /// Generates the r s a key pair der bytes.
        /// </summary>
        /// <param name="keyLengthInBits">The key length in bits.</param>
        /// <returns>A (byte[] publicKey, byte[] privateKey) .</returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateRSAKeyPairDerBytes(int keyLengthInBits = 2048)
        {
            var keyPair = GenerateRSAKeyPair(keyLengthInBits);

            var rsaPublicKey = (RsaKeyParameters)keyPair.Public;
            var rsaPrivateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaPublicKey);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaPrivateKey);

            var publicKeyBytes = publicKeyInfo.ToAsn1Object().GetEncoded();
            var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();

            return (publicKeyBytes, privateKeyBytes);
        }

        /// <summary>
        /// Generates the r s a key pair pem.
        /// </summary>
        /// <param name="keyLengthInBits">The key length in bits.</param>
        /// <returns>A (string publicKey, string privateKey) .</returns>
        public static (string publicKey, string privateKey) GenerateRSAGenericKeyPairPem(int keyLengthInBits = 2048)
        {
            var keyPair = GenerateRSAKeyPair(keyLengthInBits);

            var publicKeyPem = GenerateGenericPublicKeyPem(keyPair.Public);
            var privateKeyPem = GenerateGenericPrivateKeyPem(keyPair.Private);

            return (publicKeyPem, privateKeyPem);
        }

        /// <summary>
        /// Generates the r s a key pair pem.
        /// </summary>
        /// <param name="keyLengthInBits">The key length in bits.</param>
        /// <returns>A (string publicKey, string privateKey) .</returns>
        public static (string publicKey, string privateKey) GenerateRSAKeyPairPem(int keyLengthInBits = 2048)
        {
            var generator = (RsaKeyPairGenerator)GeneratorUtilities.GetKeyPairGenerator("RSA");
            generator.Init(new KeyGenerationParameters(new SecureRandom(), keyLengthInBits));
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            using TextWriter textWriter = new StringWriter();
            var pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keyPair.Public);
            pemWriter.Writer.Flush();
            string pemPublicKey = textWriter.ToString();

            using TextWriter textWriter2 = new StringWriter();
            var pemWriter2 = new PemWriter(textWriter2);
            pemWriter2.WriteObject(keyPair.Private);
            pemWriter2.Writer.Flush();
            string pemPrivateKey = textWriter2.ToString();

            return (pemPublicKey, pemPrivateKey);
        }

        /// <summary>
        /// Imports the private key pem.
        /// </summary>
        /// <param name="pem">The pem.</param>
        /// <returns>A RsaPrivateCrtKeyParameters.</returns>
        public static RsaPrivateCrtKeyParameters ImportPrivateKeyPem(string pem)
        {
            var pemReader = new PemReader(new StringReader(pem));
            var pemObject = pemReader.ReadObject();

            if (pemObject is RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters)
                return rsaPrivateCrtKeyParameters;
            else if (pemObject is AsymmetricCipherKeyPair asymKeyPair)
                return (RsaPrivateCrtKeyParameters)asymKeyPair.Private;
            else
                throw new ArgumentException("Invalid PEM format. It should contain a private key.");
        }

        /// <summary>
        /// Imports the public key pem.
        /// </summary>
        /// <param name="pem">The pem.</param>
        /// <returns>A RsaKeyParameters.</returns>
        public static RsaKeyParameters ImportPublicKeyPem(string pem)
        {
            var publicKeyReader = new PemReader(new StringReader(pem));
            var publicKeyObject = publicKeyReader.ReadObject();
            var rsaPublicKey = (RsaKeyParameters)publicKeyObject;

            return rsaPublicKey;
        }

        /// <summary>
        /// Imports DER-encoded base64 private key
        /// </summary>
        /// <param name="base64Der">DER-encoded base64 private key</param>
        /// <returns></returns>
        public static RsaPrivateCrtKeyParameters ImportPrivateKeyDer(string base64Der)
        {
            var privateKeyBytes = Convert.FromBase64String(base64Der);

            var privateKeyStructure = (Asn1Sequence)Asn1Object.FromByteArray(privateKeyBytes);
            var privateKeyInfo = PrivateKeyInfo.GetInstance(privateKeyStructure);

            var rsaPrivateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);

            return rsaPrivateKey;
        }

        /// <summary>
        /// Imports DER-encoded base64 public key
        /// </summary>
        /// <param name="base64Der">DER-encoded base64 public key</param>
        /// <returns></returns>
        public static RsaKeyParameters ImportPublicKeyDer(string base64Der)
        {
            var publicKeyBytes = Convert.FromBase64String(base64Der);

            var publicKeyStructure = (Asn1Sequence)Asn1Object.FromByteArray(publicKeyBytes);
            var publicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyStructure);

            var rsaPublicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);

            return rsaPublicKey;
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="publicKey">The public key.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <returns>An array of byte.</returns>
        public static byte[] EncryptData(
            byte[] data,
            RsaKeyParameters publicKey,
            string encryptionAlgorithm = AlgorithmRsaNoneOaepWithSha256AndMgf1Padding)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionAlgorithm);
            cipher.Init(true, publicKey);

            return ApplyCipher(data, cipher);
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        /// <param name="cipheredData">The ciphered data.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="decryptionAlgorithm">The decryption algorithm.</param>
        /// <returns>An array of byte.</returns>
        public static byte[] DecryptData(
            byte[] cipheredData,
            RsaPrivateCrtKeyParameters privateKey,
            string decryptionAlgorithm = AlgorithmRsaNoneOaepWithSha256AndMgf1Padding)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(decryptionAlgorithm);
            cipher.Init(false, privateKey);

            return ApplyCipher(cipheredData, cipher);
        }

        /// <summary>
        /// Generates the signature.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="signingAlgorithm">The signing algorithm.</param>
        /// <returns>An array of byte.</returns>
        public static byte[] GenerateSignature(
            byte[] data,
            RsaKeyParameters privateKey,
            string signingAlgorithm = AlgorithmSHA256withRSA)
        {
            ISigner signer = SignerUtilities.GetSigner(signingAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="publicKey">The public key.</param>
        /// <param name="signingAlgorithm">The signing algorithm.</param>
        /// <returns>A bool.</returns>
        public static bool VerifySignature(
            byte[] data,
            byte[] signature,
            RsaKeyParameters publicKey,
            string signingAlgorithm = AlgorithmSHA256withRSA)
        {
            ISigner signer = SignerUtilities.GetSigner(signingAlgorithm);
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(signature);
        }

        /// <summary>
        /// Return PEM public key string
        /// </summary>
        /// <param name="publicKeyBase64Der"></param>
        /// <returns></returns>
        public static string ConvertToPemFromPublicKeyDer(string publicKeyBase64Der)
        {
            var derPublicKeyBytes = Convert.FromBase64String(publicKeyBase64Der);
            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(derPublicKeyBytes);

            // Convert the RSA public key to PEM format
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);

            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();

            var publicKeyPemString = stringWriter.ToString();
            stringWriter.Flush();

            return publicKeyPemString;
        }

        /// <summary>
        /// Return PEM private key string
        /// </summary>
        /// <param name="privateKeyBase64Der"></param>
        /// <returns></returns>
        public static string ConvertToPemFromPrivateKeyDer(string privateKeyBase64Der)
        {
            byte[] derPrivateKeyBytes = Convert.FromBase64String(privateKeyBase64Der);
            RsaKeyParameters privateKeyParameters = (RsaKeyParameters)PrivateKeyFactory.CreateKey(derPrivateKeyBytes);

            // Convert the RSA Key Parameter to a PEM string
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);

            pemWriter.WriteObject(privateKeyParameters);
            pemWriter.Writer.Flush();

            var privateKeyPemString = stringWriter.ToString();
            stringWriter.Flush();

            return privateKeyPemString;
        }

        /// <summary>
        /// Converts the to der from private key pem.
        /// </summary>
        /// <param name="privateKeyParam">The private key param.</param>
        /// <returns>A string.</returns>
        public static string ConvertToDerFromPrivateKeyPem(RsaPrivateCrtKeyParameters privateKeyParam)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();

            return Convert.ToBase64String(privateKeyBytes);
        }

        /// <summary>
        /// Converts the to der from public key pem.
        /// </summary>
        /// <param name="publicKeyParam">The public key param.</param>
        /// <returns>A string.</returns>
        public static string ConvertToDerFromPublicKeyPem(RsaKeyParameters publicKeyParam)
        {
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKeyParam);
            var publicKeyBytes = publicKeyInfo.ToAsn1Object().GetEncoded();

            return Convert.ToBase64String(publicKeyBytes);
        }

        /// <summary>
        /// Generates the public key pem.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>A string.</returns>
        public static string GenerateGenericPublicKeyPem(AsymmetricKeyParameter publicKey)
        {
            var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();

            // Get the PEM-formatted public key string
            return stringWriter.ToString();
        }

        /// <summary>
        /// Generates the private key pem.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>A string.</returns>
        public static string GenerateGenericPrivateKeyPem(AsymmetricKeyParameter privateKey)
        {
            var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            var pkcs8Generator = new Pkcs8Generator(privateKey, null)
            {
                Password = null
            };

            pemWriter.WriteObject(pkcs8Generator.Generate());
            pemWriter.Writer.Flush();

            // Get the PEM-formatted private key string
            return stringWriter.ToString();
        }

        /// <summary>
        /// Applies the cipher.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="cipher">The cipher.</param>
        /// <returns>An array of byte.</returns>
        private static byte[] ApplyCipher(byte[] data, IBufferedCipher cipher)
        {
            using var inputStream = new MemoryStream(data);
            var outputBytes = new List<byte>();

            var blockSize = cipher.GetBlockSize();
            var buffer = new byte[blockSize];

            int index;
            while ((index = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                var cipherBlock = cipher.DoFinal(buffer, 0, index);
                outputBytes.AddRange(cipherBlock);
            }

            return outputBytes.ToArray();
        }

    }
}
