using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Enumeración de tipo seguro que contiene los nombres de las algoritmos hash SHA.
    /// </summary>
    public class HashAlgorithmNames
    {
        /// <summary>
        /// Valor para el algoritmo SHA512.
        /// </summary>
        public static readonly HashAlgorithmNames SHA512 = new HashAlgorithmNames("Sha512");
        /// <summary>
        /// Valor para el algoritmo SHA256.
        /// </summary>
        public static readonly HashAlgorithmNames SHA256 = new HashAlgorithmNames("Sha256");
        /// <summary>
        /// Valor para el algoritmo SHA384.
        /// </summary>
        public static readonly HashAlgorithmNames SHA384 = new HashAlgorithmNames("Sha384");
        /// <summary>
        /// Valor para el algoritmo SHA1.
        /// </summary>
        public static readonly HashAlgorithmNames SHA1 = new HashAlgorithmNames("Sha1");

        private String Name;

        private HashAlgorithmNames(String Name)
        {
            this.Name = Name;
        }

        /// <summary>
        /// Devuelve la representación del objeto en String.
        /// </summary>
        /// <returns>Representación del objeto en un String.</returns>
        public override String ToString()
        {
            return Name;
        }
    }
}
