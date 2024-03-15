using System.Security.Cryptography;
using System.Text;

namespace EncoderLibrary
{
    public class Encoder
    {
        private readonly string salt = "_rivc";
        private readonly string key = "1975";
        private readonly string ivSecret = "_secretVector";

        private byte[] GetIV(string ivSecret)
        {
            using MD5 md5 = MD5.Create();
            return md5.ComputeHash(Encoding.UTF8.GetBytes(ivSecret));
        }

        private byte[] GetKey(string key)
        {
            using SHA256 sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
        }

        public string GetDataEncrypt(string data)
        {
            if (string.IsNullOrEmpty(data))
                return string.Empty;

            byte[] array;

            using var aes = Aes.Create();
            aes.Key = GetKey(key);
            aes.IV = GetIV(ivSecret);

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var memoryStream = new MemoryStream();
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write($"{data}{salt}");
                }
                array = memoryStream.ToArray();
            }
            return Convert.ToBase64String(array);
        }
        public string GetDataDecrypt(string data)
        {
            if (string.IsNullOrEmpty(data))
                return null;

            try
            {
                byte[] buffer = Convert.FromBase64String(data);

                using var aes = Aes.Create();
                aes.Key = GetKey(key);
                aes.IV = GetIV(ivSecret);

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using var memoryStream = new MemoryStream(buffer);
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader(cryptoStream))
                    {
                        return streamReader.ReadToEnd().Replace(salt, string.Empty);
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
