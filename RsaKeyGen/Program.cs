using Core;

/* Generic RSA Key Pair */
var outputDir = @$"C:\RsaKeyFiles\Generic\{DateTime.Now:yyyyMMdd}\";

if (!Directory.Exists(outputDir))
    Directory.CreateDirectory(outputDir);

var (publicKey, privateKey) = RsaCryptoUtils.GenerateRSAGenericKeyPairPem();

var keyFileNamePartial = $@"{outputDir}{DateTimeOffset.Now.ToUnixTimeSeconds()}";

var privateKeyPemPath = $"{keyFileNamePartial}_private.pem";
var publicKeyPemPath = $"{keyFileNamePartial}_public.pem";

File.WriteAllText(privateKeyPemPath, privateKey);
File.WriteAllText(publicKeyPemPath, publicKey);

Console.WriteLine("Public and Private Generic Rsa key pair generated in following location:");
Console.WriteLine();
Console.WriteLine(outputDir);
Console.WriteLine();

Console.WriteLine("*******************************************");
Console.WriteLine();
Console.WriteLine("PublicKey:\n" + publicKey);
Console.WriteLine();

Console.WriteLine("*******************************************");
Console.WriteLine();
Console.WriteLine("PrivateKey:\n" + privateKey);
Console.WriteLine();


/* RSA Key Pair */
Console.WriteLine("---------------------------------------------------");
Console.WriteLine("---------------------------------------------------");
Console.WriteLine();

var outputDirRsa = @$"C:\RsaKeyFiles\Rsa\{DateTime.Now:yyyyMMdd}\";

if (!Directory.Exists(outputDirRsa))
    Directory.CreateDirectory(outputDirRsa);

var (publicKeyRsa, privateKeyRsa) = RsaCryptoUtils.GenerateRSAKeyPairPem();

var keyFileNamePartialRsa = $@"{outputDirRsa}{DateTimeOffset.Now.ToUnixTimeSeconds()}";

var privateRsaKeyPemPath = $"{keyFileNamePartialRsa}_private.pem";
var publicRsaKeyPemPath = $"{keyFileNamePartialRsa}_public.pem";

File.WriteAllText(privateRsaKeyPemPath, privateKeyRsa);
File.WriteAllText(publicRsaKeyPemPath, publicKeyRsa);

Console.WriteLine("Public and Private Rsa key pair generated in following location:");
Console.WriteLine();
Console.WriteLine(outputDirRsa);
Console.WriteLine();

Console.WriteLine("*******************************************");
Console.WriteLine();
Console.WriteLine("PublicKey:\n" + publicKeyRsa);
Console.WriteLine();

Console.WriteLine("*******************************************");
Console.WriteLine();
Console.WriteLine("PrivateKey:\n" + privateKeyRsa);
Console.WriteLine();