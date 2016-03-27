//------------------------------------------------------------------------------
// <auto-generated>
//     Este código se generó a partir de una plantilla.
//
//     Los cambios manuales en este archivo pueden causar un comportamiento inesperado de la aplicación.
//     Los cambios manuales en este archivo se sobrescribirán si se regenera el código.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Dominaturn.WebService.Core.DataAccess.Model
{
    using System;
    using System.Collections.Generic;
    
    public partial class EquipoVentanilla
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EquipoVentanilla()
        {
            this.Atencion = new HashSet<Atencion>();
            this.EquipoVentanillaCategoriaTramite = new HashSet<EquipoVentanillaCategoriaTramite>();
        }
    
        public long Id { get; set; }
        public int Numero { get; set; }
        public string Descripcion { get; set; }
        public string DeviceId { get; set; }
        public string Nombre { get; set; }
        public bool Activo { get; set; }
        public byte[] Configuraciones { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Atencion> Atencion { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EquipoVentanillaCategoriaTramite> EquipoVentanillaCategoriaTramite { get; set; }
    }
}
