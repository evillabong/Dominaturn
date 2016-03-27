using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Contiene funciones para uso firmas hash. 
    /// </summary>
    public class HashFunctions
    {
        private const int ITERATION_NUMBER = 1000;

        private static String SaltedSHA512Base64String(byte[] Data, byte[] Salt, Boolean InsertLineBreaks)
        {
            byte[] DataWithSaltBytes = new byte[Data.Length + Salt.Length];
            Salt.CopyTo(DataWithSaltBytes, 0);
            Data.CopyTo(DataWithSaltBytes, Salt.Length);
            SHA512Managed crypt = new SHA512Managed();
            byte[] input = crypt.ComputeHash(DataWithSaltBytes);
            for (int i = 0; i < ITERATION_NUMBER; i++)
            {
                input = crypt.ComputeHash(input);
            }
            return ByteArrayToBase64String(input, InsertLineBreaks, false);
        }

        private static String SaltedSHA512HexString(byte[] Data, byte[] Salt)
        {
            byte[] DataWithSaltBytes = new byte[Data.Length + Salt.Length];
            Salt.CopyTo(DataWithSaltBytes, 0);
            Data.CopyTo(DataWithSaltBytes, Salt.Length);
            SHA512Managed crypt = new SHA512Managed();
            byte[] input = crypt.ComputeHash(DataWithSaltBytes);
            for (int i = 0; i < ITERATION_NUMBER; i++)
            {
                input = crypt.ComputeHash(input);
            }
            return ByteArrayToHexString(input);
        }

        /// <summary>
        /// Genera un hash SHA-512 custom y sal en formato String Base64 a partir de un texto plano.
        /// </summary>
        /// <param name="Data">Texto a generar el hash y sal.</param>
        /// <param name="InsertLineBreaks">Insertar saltos de línea cada 76 caracteres.</param>
        /// <returns>Hash con sal.</returns>
        public static SaltedHash SHA512WithSaltBase64String(String Data, Boolean InsertLineBreaks)
        {
            SaltedHash ret = new SaltedHash();
            byte[] Salt = new byte[8];
            RNGCryptoServiceProvider RandomGenerator = new RNGCryptoServiceProvider();
            RandomGenerator.GetNonZeroBytes(Salt);
            ret.Hash = SaltedSHA512Base64String(Encoding.UTF8.GetBytes(Data), Salt, InsertLineBreaks);
            ret.Salt = HashFunctions.ByteArrayToBase64String(Salt, InsertLineBreaks, false);
            return ret;
        }

        /// <summary>
        /// Genera un hash SHA-512 custom y sal en formato String hexadecimal a partir de un texto plano.
        /// </summary>
        /// <param name="Data">Texto a generar el hash y sal.</param>
        /// <returns>Hash con sal.</returns>
        public static SaltedHash SHA512WithSaltHexString(String Data)
        {
            SaltedHash ret = new SaltedHash();
            byte[] Salt = new byte[8];
            RNGCryptoServiceProvider RandomGenerator = new RNGCryptoServiceProvider();
            RandomGenerator.GetNonZeroBytes(Salt);

            ret.Hash = SaltedSHA512HexString(Encoding.UTF8.GetBytes(Data), Salt);
            ret.Salt = HashFunctions.ByteArrayToHexString(Salt);
            return ret;
        }

        /// <summary>
        /// Obtiene un valor que estable si el hash SHA-512 custom en formato String Base64 de un "texto plano + sal" es igual a un hash.
        /// </summary>
        /// <param name="Data">Texto plano.</param>
        /// <param name="SaltedHashString">Hash a comparar.</param>
        /// <param name="Salt">Sal.</param>
        /// <param name="InsertLineBreaks">Insertar saltos de línea cada 73 caracteres.</param>
        /// <returns>true si son iguales los hash resultantes.</returns>
        public static Boolean DataMatchesSaltedSHA512Base64String(String Data, String SaltedHashString, String Salt, Boolean InsertLineBreaks)
        {
            String hash = SaltedSHA512Base64String(Encoding.UTF8.GetBytes(Data), Base64StringToByteArray(Salt,false), InsertLineBreaks);
            //SaltedHashString = Regex.Replace(SaltedHashString, @"\r\n|\n|\n\r|\r", "");
            //hash = Regex.Replace(hash, @"\r\n|\n|\n\r|\r", "");
            return SaltedHashString.Equals(hash);
        }

        /// <summary>
        /// Obtener el hash SHA-512 Custom en formato String Base64 de un String.
        /// </summary>
        /// <param name="Data">Texto plano.</param>
        /// <param name="Salt">Sal.</param>
        /// <param name="InsertLineBreaks">Insertar saltos de línea cada 76 caracteres.</param>
        /// <returns>Hash.</returns>
        public static String StringToSaltedSHA512Base64String(String Data, String Salt, Boolean InsertLineBreaks)
        {
            return SaltedSHA512Base64String(Encoding.UTF8.GetBytes(Data), Base64StringToByteArray(Salt, false), InsertLineBreaks);
        }

        /// <summary>
        /// Obtiene un valor que estable si el hash SHA-512 custom en formato String Hexadecimal de un "texto plano + sal" es igual a un hash.
        /// </summary>
        /// <param name="Data">Texto plano.</param>
        /// <param name="SaltedHashString">Hash a comparar.</param>
        /// <param name="Salt">Sal.</param>
        /// <returns>true si son iguales los hash resultantes.</returns>
        public static Boolean DataMatchesSaltedSHA512HexString(String Data, String SaltedHashString, String Salt)
        {
            return SaltedSHA512HexString(Encoding.UTF8.GetBytes(Data), HexStringToByteArray(Salt)).Equals(SaltedHashString);
        }

        /// <summary>
        /// Obtener el hash SHA-512 Custom en formato String Hexadecimal de un String.
        /// </summary>
        /// <param name="Data">Texto plano.</param>
        /// <param name="Salt">Sal.</param>
        /// <returns>Hash.</returns>
        public static String StringToSaltedSHA512HexString(String Data, String Salt)
        {
            return SaltedSHA512HexString(Encoding.UTF8.GetBytes(Data), HexStringToByteArray(Salt));
        }

        /// <summary>
        /// Convierte un arreglo de bytes a un cadena en formato String Hexadecimal.
        /// </summary>
        /// <param name="Bytes">Arreglo de bytes.</param>
        /// <returns>Cadena en formato String Hexadecimal.</returns>
        public static String ByteArrayToHexString(byte[] Bytes)
        {
            StringBuilder ret = new StringBuilder("");
            foreach (byte Value in Bytes)
            {
                ret.Append(Value.ToString("x2"));
            }
            return ret.ToString();
        }

        /// <summary>
        /// Convierte una cadena en formato String Hexadecimal a un arreglo de bytes.
        /// </summary>
        /// <param name="HexString">Cadena en formato String Hexadecimal.</param>
        /// <returns>Array de bytes.</returns>
        public static byte[] HexStringToByteArray(String HexString)
        {
            int Pair = HexString.Length % 2;
            byte[] ret = new byte[HexString.Length / 2];
            if (Pair == 0)
            {
                for (int i = 0; i < HexString.Length / 2; i++)
                {

                    ret[i] = Convert.ToByte(HexString.Substring(i * 2, 2), 16);
                }
            }
            else
            {
                throw new Exception("Cadena con formato incorrecto.");
            }
            return ret;
        }

        /// <summary>
        /// Convierte un arreglo de bytes a un cadena en formato String Base64.
        /// </summary>
        /// <param name="Bytes">Arreglo de bytes.</param>
        /// <param name="InsertLineBreaks">Insertar saltos de línea. En base 64 cada 76 caracteres hay un salto de línea.</param>
        /// <param name="GetUrlSafe">El resultado será seguro para URIs/URLs.</param>
        /// <returns>Cadena en formato String Base64.</returns>
        public static String ByteArrayToBase64String(byte[] Bytes, Boolean InsertLineBreaks, Boolean GetUrlSafe)
        {
            var ret = InsertLineBreaks ? Convert.ToBase64String(Bytes, Base64FormattingOptions.InsertLineBreaks) : Convert.ToBase64String(Bytes);
            return GetUrlSafe ? Base64StringToUrlSafeBase64String(ret) : ret;
        }

        /// <summary>
        /// Convierte una cadena en formato String Base64 a un arreglo de bytes.
        /// </summary>
        /// <param name="Base64String">Cadena en formato String Base64.</param>
        /// <param name="IsUrlSafe">Es un String Base64 seguro para URIs/URLs.</param>
        /// <returns>Array de bytes.</returns>
        public static byte[] Base64StringToByteArray(String Base64String, Boolean IsUrlSafe)
        {
            Base64String = IsUrlSafe ? UrlSafeBase64StringToBase64String(Base64String): Base64String;
            return Convert.FromBase64String(Base64String);
        }

        /// <summary>
        /// Obtiene el hash SHA en formato String Hexadecimal.
        /// </summary>
        /// <param name="Data">Texto a aplicar hash.</param>
        /// <param name="AlgorithmName">Nombre del algoritmo a utilizar.</param>
        /// <returns>Hash.</returns>
        public static string ShaHexString(String Data, HashAlgorithmNames AlgorithmName)
        {
            if (AlgorithmName == null)
            {
                throw new Exception("Algoritmo desconocido");
            }
            if (AlgorithmName.Equals(HashAlgorithmNames.SHA512))
            {
                SHA512Managed crypt = new SHA512Managed();
                byte[] hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
                return ByteArrayToHexString(hash);
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA256))
            {
                SHA256Managed crypt = new SHA256Managed();
                byte[] hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
                return ByteArrayToHexString(hash);
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA384))
            {
                SHA384Managed crypt = new SHA384Managed();
                byte[] hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
                return ByteArrayToHexString(hash);
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA1))
            {
                SHA1Managed crypt = new SHA1Managed();
                byte[] hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
                return ByteArrayToHexString(hash);
            }
            throw new Exception("Algoritmo desconocido");
        }

        /// <summary>
        /// Obtiene el hash SHA en formato String Base64.
        /// </summary>
        /// <param name="Data">Texto a aplicar hash.</param>
        /// <param name="AlgorithmName">Nombre del algoritmo a utilizar.</param>
        /// <param name="GetUrlSafe">El resultado será seguro para URIs/URLs.</param>
        /// <returns>Hash.</returns>
        public static string ShaBase64String(String Data, HashAlgorithmNames AlgorithmName, Boolean GetUrlSafe)
        {
            byte[] hash = null;
            if (AlgorithmName == null)
            {
                throw new Exception("Algoritmo desconocido");
            }
            if (AlgorithmName.Equals(HashAlgorithmNames.SHA512))
            {
                SHA512Managed crypt = new SHA512Managed();
                hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA256))
            {
                SHA256Managed crypt = new SHA256Managed();
                hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA384))
            {
                SHA384Managed crypt = new SHA384Managed();
                hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
            }

            if (AlgorithmName.Equals(HashAlgorithmNames.SHA1))
            {
                SHA1Managed crypt = new SHA1Managed();
                hash = crypt.ComputeHash(Encoding.UTF8.GetBytes(Data), 0, Encoding.UTF8.GetByteCount(Data));
            }
            var ret = ByteArrayToBase64String(hash, false, GetUrlSafe);
            return GetUrlSafe ? Base64StringToUrlSafeBase64String(ret) : ret;
        }

        /// <summary>
        /// Convierte un String Hexadecimal en un String normal.
        /// </summary>
        /// <param name="HexString">Texto a convertir.</param>
        /// <returns>Texto convertido.</returns>
        public static String HexStringToString(String HexString)
        {
            return Encoding.UTF8.GetString(HexStringToByteArray(HexString));
        }

        /// <summary>
        /// Convierte un String normal en un String Hexadecimal.
        /// </summary>
        /// <param name="Text">Texto a convertir.</param>
        /// <returns>Texto convertido.</returns>
        public static String StringToHexString(String Text)
        {
            return ByteArrayToHexString(Encoding.UTF8.GetBytes(Text));
        }

        /// <summary>
        /// Convierte un String Base 64 en un String normal.
        /// </summary>
        /// <param name="Base64String">Texto a convertir.</param>
        /// <param name="IsUrlSafe">Es un String Base64 seguro para URIs/URLs.</param>
        /// <returns>Texto convertido.</returns>
        public static String Base64StringToString(String Base64String, Boolean IsUrlSafe)
        {
            Base64String = IsUrlSafe ? UrlSafeBase64StringToBase64String(Base64String) : Base64String;
            return Encoding.UTF8.GetString(Convert.FromBase64String(Base64String));
        }

        /// <summary>
        /// Convierte un String normal en un String Base64.
        /// </summary>
        /// <param name="Text">Texto a convertir.</param>
        /// <param name="InsertLineBreaks">Insertar saltos de línea cada 76 caracteres.</param>
        /// <param name="GetUrlSafe">El resultado será seguro para URIs/URLs.</param>
        /// <returns>Texto convertido.</returns>
        public static String StringToBase64String(String Text, Boolean InsertLineBreaks, Boolean GetUrlSafe)
        {
            var ret = InsertLineBreaks ? Convert.ToBase64String(Encoding.UTF8.GetBytes(Text), Base64FormattingOptions.InsertLineBreaks) : Convert.ToBase64String(Encoding.UTF8.GetBytes(Text));
            return GetUrlSafe ? Base64StringToUrlSafeBase64String(ret) : ret;
        }

        /// <summary>
        /// Regresar un arreglo de bytes a String.
        /// </summary>
        /// <param name="Bytes">Arreglo de bytes.</param>
        /// <returns>String.</returns>
        public static String ByteArrayToString(byte[] Bytes)
        {
            return Encoding.UTF8.GetString(Bytes);
        }

        /// <summary>
        /// Convierte un String a su representación en bytes utilizando la codificación UTF-8.
        /// </summary>
        /// <param name="Source">Cadena a ser convertida.</param>
        /// <returns>Arreglo de bytes.</returns>
        public static byte[] StringToByteArray(String Source)
        {
            return Encoding.UTF8.GetBytes(Source);
        }

        /// <summary>
        /// Convierte un String Base64 en un String Base64 seguro para utilizar en URIs/URLs.
        /// </summary>
        /// <param name="Base64String">String Base64.</param>
        /// <returns>String Base64 seguro para utilizar en URIs/URLs.</returns>
        public static String Base64StringToUrlSafeBase64String(String Base64String)
        {
            return Base64String.Replace("+", "-").Replace("/", "_").Replace("=", ",");
        }

        /// <summary>
        /// Convierte un String Base64 seguro para URIs/URLs en un String Base64.
        /// </summary>
        /// <param name="UrlSafeBase64String">String Base64 seguro para URIs/URLs.</param>
        /// <returns>String Base64.</returns>
        public static String UrlSafeBase64StringToBase64String(String UrlSafeBase64String)
        {
            return UrlSafeBase64String.Replace("-", "+").Replace("_", "/").Replace(",", "=");
        }
    }
}