using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace Dominaturn.WebService.Core.DataAccess.Model
{
    public partial class DominaturnEntities : DbContext
    {
        public DominaturnEntities(String EntityConnectionString)
            : base(EntityConnectionString)
        {

        }

        public static DominaturnEntities NewInstance()
        {
            return new DominaturnEntities(ConnectionStringsManager.GetEntityConnectionString());
        }
    }
}