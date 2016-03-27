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
    
    public partial class Tramite
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Tramite()
        {
            this.Atencion = new HashSet<Atencion>();
            this.TramiteRequisito = new HashSet<TramiteRequisito>();
        }
    
        public long Id { get; set; }
        public string Descripcion { get; set; }
        public bool Activo { get; set; }
        public long IdTCategoriaTramite { get; set; }
        public decimal Precio { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Atencion> Atencion { get; set; }
        public virtual CategoriaTramite CategoriaTramite { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<TramiteRequisito> TramiteRequisito { get; set; }
    }
}
