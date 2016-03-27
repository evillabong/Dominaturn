using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Provee funciones criptográficas usando el algoritmo AES con claves de 256 bits.
    /// </summary>
    public class AesEncryptionManager
    {
        private const int MAX_IV_LENGTH = 16;
        private const int MAX_KEY_LENGTH = 32;
        private static AesManaged AesAlgorithm = new AesManaged();

        private static byte[] GenerateValidKey(byte[] KeyBytes)
        {
            byte[] ret = new byte[MAX_KEY_LENGTH];
            if (KeyBytes.Length == 0)
            {
                throw new Exception("Invalid AES key empty: " + KeyBytes.Length + " bytes.");
            }
            else
            {
                SHA256Managed crypt = new SHA256Managed();
                byte[] hash = crypt.ComputeHash(KeyBytes, 0, KeyBytes.Length);
                Array.Copy(hash, ret, MAX_KEY_LENGTH);
            }
            return ret;
        }

        /// <summary>
        /// Encripta una secuencia de bytes.
        /// </summary>
        /// <param name="PlainBytes">Bytes a encriptar.</param>
        /// <param name="Key">Bytes de llave.</param>
        /// <returns>Bytes encriptados.</returns>
        public static byte[] EncryptRaw(byte[] PlainBytes, byte[] Key)
        {
           
            AesAlgorithm.Key = GenerateValidKey(Key);
            AesAlgorithm.GenerateIV();
            var Encrypted = AesAlgorithm.CreateEncryptor().TransformFinalBlock(PlainBytes, 0, PlainBytes.Length);
            byte[] ret = new byte[Encrypted.Length + MAX_IV_LENGTH];
            Array.Copy(Encrypted, ret, Encrypted.Length);
            Array.Copy(AesAlgorithm.IV, 0, ret, ret.Length - MAX_IV_LENGTH, MAX_IV_LENGTH);
            return ret;
        }

        /// <summary>
        /// Desencripta una secuencia de bytes.
        /// </summary>
        /// <param name="CipherBytes">Bytes a desencriptar.</param>
        /// <param name="Key">Bytes de la llave.</param>
        /// <returns>Bytes desencriptados.</returns>
        public static byte[] DecryptRaw(byte[] CipherBytes, byte[] Key)
        {
            AesAlgorithm.Key = GenerateValidKey(Key);
            byte[] IV = new byte[MAX_IV_LENGTH];
            Array.Copy(CipherBytes, CipherBytes.Length - MAX_IV_LENGTH , IV,0,MAX_IV_LENGTH);
            AesAlgorithm.IV = IV;
            byte[] RealBytes = new byte[CipherBytes.Length - MAX_IV_LENGTH];
            Array.Copy(CipherBytes, RealBytes, CipherBytes.Length - MAX_IV_LENGTH);
            return AesAlgorithm.CreateDecryptor().TransformFinalBlock(RealBytes, 0, RealBytes.Length); ;
        }

        /// <summary>
        /// Encripta un texto y genera la salida en formato String Hexadecimal.
        /// </summary>
        /// <param name="Plaintext">Texto a encriptar.</param>
        /// <param name="Key">Llave.</param>
        /// <returns>Texto encriptado.</returns>
        public static String EncryptToHexString(String Plaintext, String Key)
        {
            int Length = Encoding.UTF8.GetByteCount(Key);
            byte[] PlainBytes = Encoding.UTF8.GetBytes(Plaintext);
            return HashFunctions.ByteArrayToHexString((EncryptRaw(PlainBytes, Encoding.UTF8.GetBytes(Key))));
        }

        /// <summary>
        /// Desencripta un texto en formato String Hexadecimal.
        /// </summary>
        /// <param name="CipherText">Texto a desencriptar.</param>
        /// <param name="Key">Llave.</param>
        /// <returns>Texto desencriptado.</returns>
        public static String DecryptFromHexString(String CipherText, String Key)
        {
            byte[] CiPherBytes = HashFunctions.HexStringToByteArray(CipherText);
            byte[] Encrypted = DecryptRaw(CiPherBytes, Encoding.UTF8.GetBytes(Key));
            return Encoding.UTF8.GetString(Encrypted, 0, Encrypted.Length);
        }

        /// <summary>
        /// Encripta un texto y genera la salida en formato String Base64.
        /// </summary>
        /// <param name="Plaintext">Texto a encriptar.</param>
        /// <param name="Key">Llave.</param>
        /// <param name="GetUrlSafe">El resultado será seguro para URIs/URLs.</param>
        /// <returns>Texto encriptado.</returns>
        public static String EncryptToBase64String(String Plaintext, String Key, Boolean GetUrlSafe)
        {
            byte[] PlainBytes = Encoding.UTF8.GetBytes(Plaintext);
            return HashFunctions.ByteArrayToBase64String(EncryptRaw(PlainBytes, Encoding.UTF8.GetBytes(Key)),false, GetUrlSafe);
        }

        /// <summary>
        /// Desencripta un texto en formato String Base64.
        /// </summary>
        /// <param name="CipherText">Texto a desencriptar.</param>
        /// <param name="Key">Llave.</param>
        /// <param name="IsUrlSafe">Es un String Base64 seguro para URIs/URLs.</param>
        /// <returns>Texto desencriptado.</returns>
        public static String DecryptFromBase64String(String CipherText, String Key, Boolean IsUrlSafe)
        {
            CipherText = IsUrlSafe ? HashFunctions.UrlSafeBase64StringToBase64String(CipherText) : CipherText;
            byte[] CiPherBytes = HashFunctions.Base64StringToByteArray(CipherText,false);
            byte[] Encrypted = DecryptRaw(CiPherBytes, Encoding.UTF8.GetBytes(Key));
            return Encoding.UTF8.GetString(Encrypted, 0, Encrypted.Length);
        }

    }
}