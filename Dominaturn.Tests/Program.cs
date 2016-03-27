using Dominaturn.WebService.Core.DataAccess.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dominaturn.Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(ConnectionStringsManager.GetEntityConnectionString());
            using (var dataBase = DominaturnEntities.NewInstance())
            {
                CategoriaTramite categoriaTramite = new CategoriaTramite
                {
                    Descripcion = "Inscripciones",
                    Activa = false,
                    Letra = "I"
                };
                dataBase.CategoriaTramite.Add(categoriaTramite);
                dataBase.SaveChanges();
                Console.WriteLine("Id generado: " + categoriaTramite.Id);
            }
            Console.ReadLine();
        }
    }
}
