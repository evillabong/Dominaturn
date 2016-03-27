using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Insane.UniversalApps.Cryptography
{
    /// <summary>
    /// Representa los valores de clave pública y privada para el algoritmo RSA en formato XML. 
    /// </summary>
    public class RSAXmlStringKeyPair
    {
        /// <summary>
        /// Contiene o debe contener la representación en XML de una clave pública RSA.
        /// </summary>
        public String PublicXmlStringKey { get; set; }
        /// <summary>
        /// Contiene o debe contener la representación XML de una clave privada RSA. Puede ser usada esta misma clave para encriptar y desencriptar.
        /// </summary>
        public String PrivateXmlStringKey { get; set; }
    }
}
