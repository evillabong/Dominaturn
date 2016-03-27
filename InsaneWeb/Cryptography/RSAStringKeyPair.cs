using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Representa los valores de clave pública y privada para el algoritmo RSA en formato String Base64. 
    /// </summary>
    public class RSAStringKeyPair
    {
        /// <summary>
        /// Contiene o debe contener la representación de una clave pública RSA en String Base64. Una clave pública usa el formato X.509.
        /// </summary>
        public String PublicStringKey { get; set; }
        /// <summary>
        /// Contiene o debe contener la representación de una clave privada RSA en String Base64. Una clave privada usa el formato PKCS#8.
        /// </summary>
        public String PrivateStringKey { get; set; }
    }
}
