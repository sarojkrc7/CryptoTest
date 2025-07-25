using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Core
{
    public static class MypayCrypto
    {
        /////////////MYPAY CRYPTO GRAPHY///////////
        ///

        public static string EncryptString(string inputString)
        {
            MemoryStream memStream = null;
            try
            {
                byte[] key = {

            };
                byte[] IV = {
                12,
                21,
                43,
                17,
                57,
                35,
                67,
                27
            };
                string encryptKey = "aHV2ty4z";
                key = Encoding.UTF8.GetBytes(encryptKey);
                byte[] byteInput = Encoding.UTF8.GetBytes(inputString);
                DESCryptoServiceProvider provider = new();
                memStream = new MemoryStream();
                ICryptoTransform transform = provider.CreateEncryptor(key, IV);
                CryptoStream cryptoStream = new(memStream, transform, CryptoStreamMode.Write);
                cryptoStream.Write(byteInput, 0, byteInput.Length);
                cryptoStream.FlushFinalBlock();

            }
            catch (Exception)
            {
            }

            return Convert.ToBase64String(memStream.ToArray());
        }

        public static string DecryptString(string inputString)
        {
            MemoryStream memStream = null;
            try
            {
                byte[] key = {

            };
                byte[] IV = {
                12,
                21,
                43,
                17,
                57,
                35,
                67,
                27
            };
                string encryptKey = "aHV2ty4z";

                key = Encoding.UTF8.GetBytes(encryptKey);
                byte[] byteInput = new byte[inputString.Length];
                byteInput = Convert.FromBase64String(inputString);
                DESCryptoServiceProvider provider = new();
                memStream = new MemoryStream();
                ICryptoTransform transform = provider.CreateDecryptor(key, IV);
                CryptoStream cryptoStream = new(memStream, transform, CryptoStreamMode.Write);
                cryptoStream.Write(byteInput, 0, byteInput.Length);
                cryptoStream.FlushFinalBlock();

            }
            catch (Exception)
            {
                return "";
            }

            Encoding encoding1 = Encoding.UTF8;
            return encoding1.GetString(memStream.ToArray());
        }
        public static string Encryption(string plainText)
        {
            string key = "ZZ9489Slw8OslwoS";
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                aes.Mode = CipherMode.ECB;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new())
                {
                    using (CryptoStream cryptoStream = new(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array, 0, array.Length);
        }
        public static string Decryption(string cipherText)
        {
            try
            {
                string key = "ZZ9489Slw8OslwoS";
                byte[] iv = new byte[16];
                byte[] buffer = Convert.FromBase64String(cipherText);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(key);
                    aes.IV = iv;
                    aes.Mode = CipherMode.ECB;
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new(buffer))
                    {
                        using (CryptoStream cryptoStream = new(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new(cryptoStream))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                return "error";
            }
        }

        //public static string GenerateHashFromText(string plainText)
        //{
        //    // Generate a salt and hash the password
        //    string hashedText = BCrypt.Net.BCrypt.HashPassword(plainText);
        //    return hashedText;
        //}

        //public static string GenerateHashFromText(string plainText)
        //{
        //    // Generate a salt and hash the password
        //    string hashedText = BCrypt.Net.BCrypt.HashPassword(plainText);
        //    return hashedText;
        //}



        //public static bool VerifyTextAgainstHash(string plainText, string hash)
        //{
        //    // Verify the text against the stored hash
        //    return BCrypt.Net.BCrypt.Verify(plainText, hash);
        //}

        public static string base64Encode(string sData)
        {
            try
            {
                byte[] encData_byte = new byte[(sData.Length)];
                encData_byte = System.Text.Encoding.UTF8.GetBytes(sData);
                string encodedData = Convert.ToBase64String(encData_byte);
                return encodedData;
            }
            catch (Exception)
            {
                return "";
            }
        }
        public static string base64Decode(string sData)
        {
            System.Text.UTF8Encoding encoder = new();
            System.Text.Decoder utf8Decode = encoder.GetDecoder();
            try
            {
                byte[] todecode_byte = Convert.FromBase64String(sData);
                int charCount = utf8Decode.GetCharCount(todecode_byte, 0, todecode_byte.Length);
                char[] decoded_char = new char[(charCount)];
                utf8Decode.GetChars(todecode_byte, 0, todecode_byte.Length, decoded_char, 0);
                string result = new(decoded_char);
                return result;
            }
            catch (Exception)
            {
                return "";
            }
        }
        public static string EncryptionFromKey(string plainText, string key)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                aes.Mode = CipherMode.ECB;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new())
                {
                    using (CryptoStream cryptoStream = new(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array, 0, array.Length);
        }
        public static string DecryptionFromKey(string cipherText, string key)
        {
            try
            {
                byte[] iv = new byte[16];
                byte[] buffer = Convert.FromBase64String(cipherText);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(key);
                    aes.IV = iv;
                    aes.Mode = CipherMode.ECB;
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new(buffer))
                    {
                        using (CryptoStream cryptoStream = new(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new(cryptoStream))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                return "error";
            }
        }
    }
}
