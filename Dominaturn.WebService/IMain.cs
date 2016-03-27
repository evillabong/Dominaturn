using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace Dominaturn.WebService
{
    // NOTA: puede usar el comando "Rename" del menú "Refactorizar" para cambiar el nombre de interfaz "IMain" en el código y en el archivo de configuración a la vez.
    [ServiceContract]
    public interface IMain
    {
        [OperationContract]
        [Description("Saludar con HelloWorld.")]
        [WebInvoke(BodyStyle = WebMessageBodyStyle.Bare, UriTemplate = "HelloWorld?p1={name}", Method = "POST")]
        String HelloWorld(String name);
    }
}
