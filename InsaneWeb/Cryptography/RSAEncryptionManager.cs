using DevDefined.OAuth.KeyInterop;
using MonoRailsOAuth.Core.KeyInterop;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Contiene funciones para creación de claves, encriptación y desencriptación usando el algoritmo RSA.
    /// </summary>
    public class RSAEncryptionManager
    {
        /// <summary>
        /// Crea el par de claves RSA en formato XML.
        /// </summary>
        /// <param name="Indent">Indentar XML.</param>
        /// <param name="KeySize">Tamaño de claves. Desde 384 bits hasta 16384 bits con incrementos de 8 bits.</param>
        /// <returns>Par de claves.</returns>
        public static RSAXmlStringKeyPair CreateXmlStringKeyPair(Boolean Indent, Int32 KeySize)
        {
            using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider(KeySize))
            {
                RSAXmlStringKeyPair result = new RSAXmlStringKeyPair();
                result.PrivateXmlStringKey = Csp.ToXmlString(true);
                result.PublicXmlStringKey = Csp.ToXmlString(false);
                if (Indent)
                {
                    result.PrivateXmlStringKey = result.PrivateXmlStringKey.Replace("><", ">" + Environment.NewLine + "  <").Replace(Environment.NewLine + "  </RS", Environment.NewLine + "</RS");
                    result.PublicXmlStringKey = result.PublicXmlStringKey.Replace("><", ">" + Environment.NewLine + "  <").Replace(Environment.NewLine + "  </RS", Environment.NewLine + "</RS");
                }
                return result;
            }
        }

        /// <summary>
        /// Crea el par de claves RSA en formato String Base64.
        /// </summary>
        /// <param name="KeySize">Tamaño de claves. Desde 384 bits hasta 16384 bits con incrementos de 8 bits.</param>
        /// <returns>Par de claves.</returns>
        public static RSAStringKeyPair CreateStringKeyPair(Int32 KeySize)
        {
            using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider(KeySize))
            {
                RSAStringKeyPair result = new RSAStringKeyPair();
                AsnKeyBuilder.AsnMessage PublicKey = AsnKeyBuilder.PublicKeyToX509(Csp.ExportParameters(false));
                AsnKeyBuilder.AsnMessage PrivateKey = AsnKeyBuilder.PrivateKeyToPKCS8(Csp.ExportParameters(true));
                result.PrivateStringKey = HashFunctions.ByteArrayToBase64String(PrivateKey.GetBytes(), false, false);
                result.PublicStringKey = HashFunctions.ByteArrayToBase64String(PublicKey.GetBytes(), false, false);
                return result;
            }
        }

        /// <summary>
        /// Encripta un texto plano usando la clave pública RSA. Nota: Si el formato es XML se puede utilizar la clave privada también para encriptar.
        /// </summary>
        /// <param name="PlainText">Texto plano.</param>
        /// <param name="PublicKey">Clave pública en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <param name="GetUrlSafe">El resultado será seguro para URIs/URLs.</param>
        /// <returns>Texto encriptado y codificado en formato Base64 String.</returns>
        public static String EncryptToBase64String(String PlainText, String PublicKey, Boolean KeyAsXml, Boolean GetUrlSafe)
        {
            var ret = Convert.ToBase64String(EncryptRaw(Encoding.UTF8.GetBytes(PlainText), PublicKey, KeyAsXml));
            return GetUrlSafe ? HashFunctions.Base64StringToUrlSafeBase64String(ret) : ret;
        }

        /// <summary>
        /// Encripta un texto plano usando la clave pública RSA. Nota: Si el formato es XML se puede utilizar la clave privada también para encriptar.
        /// </summary>
        /// <param name="PlainText">Texto plano.</param>
        /// <param name="PublicKey">Clave pública en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <returns>Texto encriptado y codificado en formato String Hexadecimal.</returns>
        public static String EncryptToHexString(String PlainText, String PublicKey, Boolean KeyAsXml)
        {
            return HashFunctions.ByteArrayToHexString(EncryptRaw(Encoding.UTF8.GetBytes(PlainText), PublicKey, KeyAsXml));
        }

        /// <summary>
        /// Desencripta un texto encriptado en formato String Base64 usando la clave privada RSA.
        /// </summary>
        /// <param name="EncryptedText">Texto encriptado en formato String Base64.</param>
        /// <param name="PrivateKey">Clave privada en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <param name="IsUrlSafe">Es un String Base64 seguro para URIs/URLs.</param>
        /// <returns>Texto original.</returns>
        public static String DecryptFromBase64String(String EncryptedText, String PrivateKey, Boolean KeyAsXml, Boolean IsUrlSafe)
        {
            EncryptedText = IsUrlSafe ? HashFunctions.UrlSafeBase64StringToBase64String(EncryptedText) : EncryptedText;
            var ret = DecryptRaw(Convert.FromBase64String(EncryptedText), PrivateKey, KeyAsXml);
            return Encoding.UTF8.GetString(ret);
        }

        /// <summary>
        /// Desencripta un texto encriptado en formato String Hexadecimal usando la clave privada RSA.
        /// </summary>
        /// <param name="EncryptedText">Texto encriptado en formato String Hexadecimal.</param>
        /// <param name="PrivateKey">Clave privada en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <returns>Texto original.</returns>
        public static String DecryptFromHexString(String EncryptedText, String PrivateKey, Boolean KeyAsXml)
        {
            var ret = DecryptRaw(HashFunctions.HexStringToByteArray(EncryptedText), PrivateKey, KeyAsXml);
            return Encoding.UTF8.GetString(ret, 0, ret.Length);
        }

        /// <summary>
        /// Encripta un arreglo de bytes usando la clave pública RSA. Si el formato es XML se puede utilizar la clave privada también para encriptar.
        /// </summary>
        /// <param name="PlainBytes">Texto plano transformado en bytes.</param>
        /// <param name="PublicKey">Clave pública en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <returns>Array de bytes.</returns>
        public static byte[] EncryptRaw(byte[] PlainBytes, String PublicKey, Boolean KeyAsXml)
        {
            if (KeyAsXml)
            {
                using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider())
                {
                    Csp.FromXmlString(PublicKey);
                    return Csp.Encrypt(PlainBytes, false);
                }
            }
            else
            {
                using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider())
                {
                    Csp.ImportParameters(new AsnKeyParser(HashFunctions.Base64StringToByteArray(PublicKey,false)).ParseRSAPublicKey());
                    return Csp.Encrypt(PlainBytes, false);
                }
            }
        }

        /// <summary>
        /// Desencripta un arreglo de bytes usando la clave privada RSA.
        /// </summary>
        /// <param name="EncryptedBytes">Bytes resultado de la encryptación.</param>
        /// <param name="PrivateKey">Clave privada en formato XML o String Base64.</param>
        /// <param name="KeyAsXml">Clave está en formato XML caso contrario está en formato Base64 String.</param>
        /// <returns>Bytes planos originales.</returns>
        public static byte[] DecryptRaw(byte[] EncryptedBytes, String PrivateKey, Boolean KeyAsXml)
        {
            if (KeyAsXml)
            {
                using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider())
                {
                    Csp.FromXmlString(PrivateKey);
                    return Csp.Decrypt(EncryptedBytes, false);
                }
            }
            else
            {
                using (RSACryptoServiceProvider Csp = new RSACryptoServiceProvider())
                {
                    Csp.ImportParameters(new AsnKeyParser(HashFunctions.Base64StringToByteArray(PrivateKey,false)).ParseRSAPrivateKey());
                    return Csp.Decrypt(EncryptedBytes, false);
                }
            }
        }

    }
}



//Para más servicios de encriptación de .NET Framework visitar http://msdn.microsoft.com/en-us/library/92f9ye3s(v=vs.110).aspx
//Para más servicios de encriptación de aplicaciones de la tienda windows visitar http://msdn.microsoft.com/en-us/library/92f9ye3s(v=vs.110).aspx
//Para tamaño correcto de claves http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacryptoserviceprovider.keysize(v=vs.110).aspx
//Recomendaciones para tamaño de claves revisar:
//http://stackoverflow.com/questions/589834/what-rsa-key-length-should-i-use-for-my-ssl-certificates
//http://pic.dhe.ibm.com/infocenter/zos/v1r13/index.jsp?topic=%2Fcom.ibm.zos.r13.icha700%2Fkeysizec.htm
//http://www.javamex.com/tutorials/cryptography/rsa_key_length.shtml