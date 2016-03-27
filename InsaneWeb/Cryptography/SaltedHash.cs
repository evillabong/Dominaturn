using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Insane.Web.Cryptography
{
    /// <summary>
    /// Representa un hash con sal.
    /// </summary>
    public class SaltedHash
    {
        /// <summary>
        /// Hash.
        /// </summary>
        public String Hash { get; set; }
        /// <summary>
        /// Sal del hash.
        /// </summary>
        public String Salt { get; set; }
    }
}
