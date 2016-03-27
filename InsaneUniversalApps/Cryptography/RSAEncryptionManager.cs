using PCLCrypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Data.Xml.Dom;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace Insane.UniversalApps.Cryptography
{
    
    /// <summary>
    /// Contiene funciones para creación de claves, encriptación y desencriptación usando el algoritmo RSA.
    /// </summary>
    public class RSAEncryptionManager
    {

        private static String GeneratePrivateXmlStringKey(RSAParameters parameters, Boolean Indent)
        {
            StringBuilder sb = new StringBuilder();
            if (Indent)
            {
                sb.AppendLine("<RSAKeyValue>");
                sb.AppendLine("  <Modulus>" + Convert.ToBase64String(parameters.Modulus) + "</Modulus>");
                sb.AppendLine("  <Exponent>" + Convert.ToBase64String(parameters.Exponent) + "</Exponent>");
                sb.AppendLine("  <P>" + Convert.ToBase64String(parameters.P) + "</P>");
                sb.AppendLine("  <Q>" + Convert.ToBase64String(parameters.Q) + "</Q>");
                sb.AppendLine("  <DP>" + Convert.ToBase64String(parameters.DP) + "</DP>");
                sb.AppendLine("  <DQ>" + Convert.ToBase64String(parameters.DQ) + "</DQ>");
                sb.AppendLine("  <InverseQ>" + Convert.ToBase64String(parameters.InverseQ) + "</InverseQ>");
                sb.AppendLine("  <D>" + Convert.ToBase64String(parameters.D) + "</D>");
                sb.Append("</RSAKeyValue>");
            }
            else
            {
                sb.Append("<RSAKeyValue>");
                sb.Append("<Modulus>" + Convert.ToBase64String(parameters.Modulus) + "</Modulus>");
                sb.Append("<Exponent>" + Convert.ToBase64String(parameters.Exponent) + "</Exponent>");
                sb.Append("<P>" + Convert.ToBase64String(parameters.P) + "</P>");
                sb.Append("<Q>" + Convert.ToBase64String(parameters.Q) + "</Q>");
                sb.Append("<DP>" + Convert.ToBase64String(parameters.DP) + "</DP>");
                sb.Append("<DQ>" + Convert.ToBase64String(parameters.DQ) + "</DQ>");
                sb.Append("<InverseQ>" + Convert.ToBase64String(parameters.InverseQ) + "</InverseQ>");
                sb.Append("<D>" + Convert.ToBase64String(parameters.D) + "</D>");
                sb.Append("</RSAKeyValue>");
            }
            return sb.ToString();
        }

        private static String GeneratePublicXmlStringKey(RSAParameters parameters, Boolean Indent)
        {
            StringBuilder sb = new StringBuilder();
            if (Indent)
            {
                sb.AppendLine("<RSAKeyValue>");
                sb.AppendLine("  <Modulus>" + Convert.ToBase64String(parameters.Modulus) + "</Modulus>");
                sb.AppendLine("  <Exponent>" + Convert.ToBase64String(parameters.Exponent) + "</Exponent>");
                sb.Append("</RSAKeyValue>");
            }
            else
            {
                sb.Append("<RSAKeyValue>");
                sb.Append("<Modulus>" + Convert.ToBase64String(parameters.Modulus) + "</Modulus>");
                sb.Append("<Exponent>" + Convert.ToBase64String(parameters.Exponent) + "</Exponent>");
                sb.Append("</RSAKeyValue>");
            }
            return sb.ToString();
        }

        private static RSAParameters ReadPublicXmlStringKey(String Key)
        {
            RSAParameters ret = new RSAParameters();
            XmlDocument XmlDoc = new XmlDocument();
            XmlDoc.LoadXml(Key);
            ret.Modulus = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/Modulus").InnerText);
            ret.Exponent = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/Exponent").InnerText);
            return ret;
        }

        private static RSAParameters ReadPrivateXmlStringKey(String Key)
        {
            RSAParameters ret = new RSAParameters();
            XmlDocument XmlDoc = new XmlDocument();
            XmlDoc.LoadXml(Key);
            ret.Modulus = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/Modulus").InnerText);
            ret.Exponent = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/Exponent").InnerText);
            ret.P = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/P").InnerText);
            ret.Q = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/Q").InnerText);
            ret.DP = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/DP").InnerText);
            ret.DQ = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/DQ").InnerText);
            ret.InverseQ = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/InverseQ").InnerText);
            ret.D = Convert.FromBase64String(XmlDoc.SelectSingleNode("/RSAKeyValue/D").InnerText);
            return ret;
        }

        /// <summary>
        /// Crea el par de claves RSA en formato XML.
        /// </summary>
        /// <param name="Indent">Indentar XML.</param>
        /// <param name="KeySize">Tamaño de claves. Desde 384 bits hasta 16384 bits con incrementos de 8 bits.</param>
        /// <returns>Par de claves.</returns>
        public static RSAXmlStringKeyPair CreateXmlStringKeyPair(Boolean Indent, Int32 KeySize)
        {

            IAsymmetricKeyAlgorithmProvider Csp = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
            ICryptographicKey KeyPair = Csp.CreateKeyPair(KeySize);
            RSAParameters Parameters = KeyPair.ExportParameters(true);
            return new RSAXmlStringKeyPair { PrivateXmlStringKey = GeneratePrivateXmlStringKey(Parameters, Indent), PublicXmlStringKey = GeneratePublicXmlStringKey(Parameters, Indent) };
        }

        /// <summary>
        /// Crea el par de claves RSA en formato String Base64.
        /// </summary>
        /// <param name="KeySize">Tamaño de claves. Desde 384 bits hasta 16384 bits con incrementos de 8 bits.</param>
        /// <returns>Par de claves.</returns>
        public static RSAStringKeyPair CreateStringKeyPair(Int32 KeySize)
        {
            Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider Csp = Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(Windows.Security.Cryptography.Core.AsymmetricAlgorithmNames.RsaPkcs1);
            Windows.Security.Cryptography.Core.CryptographicKey KeyPair = Csp.CreateKeyPair(Convert.ToUInt32(KeySize));
            IBuffer Key = KeyPair.ExportPublicKey(Windows.Security.Cryptography.Core.CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
            byte[] PublicKeyArray;
            CryptographicBuffer.CopyToByteArray(Key, out PublicKeyArray);
            Key = KeyPair.Export(Windows.Security.Cryptography.Core.CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo);
            byte[] PrivateKeyArray;
            CryptographicBuffer.CopyToByteArray(Key, out PrivateKeyArray);
            return new RSAStringKeyPair { PrivateStringKey = Convert.ToBase64String(PrivateKeyArray) , PublicStringKey = Convert.ToBase64String(PublicKeyArray) };
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
            return Encoding.UTF8.GetString(ret, 0, ret.Length);
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
            if(KeyAsXml)
            {
                //MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.AesCmac);
                //AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.DsaSha1.ToString());
                
                
                IAsymmetricKeyAlgorithmProvider Csp = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
                ICryptographicKey Key = Csp.ImportParameters(ReadPublicXmlStringKey(PublicKey));
                return WinRTCrypto.CryptographicEngine.Encrypt(Key, PlainBytes);
            }
            else
            {
                Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider Csp = Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(Windows.Security.Cryptography.Core.AsymmetricAlgorithmNames.RsaPkcs1);
                Windows.Security.Cryptography.Core.CryptographicKey Key = Csp.ImportPublicKey(CryptographicBuffer.CreateFromByteArray(Convert.FromBase64String(PublicKey)), Windows.Security.Cryptography.Core.CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
                IBuffer Encrypted = Windows.Security.Cryptography.Core.CryptographicEngine.Encrypt(Key, CryptographicBuffer.CreateFromByteArray(PlainBytes), null);
                byte[] ret;
                CryptographicBuffer.CopyToByteArray(Encrypted, out ret);
                return ret;
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
            if(KeyAsXml)
            {
                WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
                IAsymmetricKeyAlgorithmProvider Csp = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
                ICryptographicKey Key = Csp.ImportParameters(ReadPrivateXmlStringKey(PrivateKey));
                return WinRTCrypto.CryptographicEngine.Decrypt(Key, EncryptedBytes);
            }
            else
            {
                Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider Csp = Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(Windows.Security.Cryptography.Core.AsymmetricAlgorithmNames.RsaPkcs1);
                Windows.Security.Cryptography.Core.CryptographicKey Key = Csp.ImportKeyPair(CryptographicBuffer.CreateFromByteArray(Convert.FromBase64String(PrivateKey)), Windows.Security.Cryptography.Core.CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo);
                IBuffer Decrypted = Windows.Security.Cryptography.Core.CryptographicEngine.Decrypt(Key, CryptographicBuffer.CreateFromByteArray(EncryptedBytes), null);
                byte[] ret;
                CryptographicBuffer.CopyToByteArray(Decrypted, out ret);
                return ret;
            }           
        }

    }
}



//Para más servicios de encriptación de aplicaciones de la tienda windows visitar http://msdn.microsoft.com/en-us/library/92f9ye3s(v=vs.110).aspx
//Windows Phone 8.1 (Silverlight) vs Windows Phone 8.1 ver diferencias en la API. 
//System.Security.Cryptography ya no existe en las aplicaciones de la tienda en su lugar usar Windows.Security.Cryptography
//http://firstfloorsoftware.com/Media/DiffLists/Windows%20Phone%208.1%20(Silverlight)-vs-Windows%20Phone%208.1.html
//Recomendaciones para tamaño de claves revisar:
//http://stackoverflow.com/questions/589834/what-rsa-key-length-should-i-use-for-my-ssl-certificates
//http://pic.dhe.ibm.com/infocenter/zos/v1r13/index.jsp?topic=%2Fcom.ibm.zos.r13.icha700%2Fkeysizec.htm
//http://www.javamex.com/tutorials/cryptography/rsa_key_length.shtml