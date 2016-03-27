using Dominaturn.WebService.Core.Constants;
using Microsoft.Win32;
using System;
using System.Data.Entity.Core.EntityClient;
using Dominaturn.Base.Misc;

namespace Dominaturn.WebService.Core.DataAccess.Model
{
    public sealed class ConnectionStringsManager
    {
        public static String GetConnectionString()
        {
            return RegeditAccessKeys.BuildInitialRegistryKey(RegistryHive.LocalMachine, RegeditConstants.REGEDIT_BASE_KEY).GetStringData(RegeditConstants.CONNECTION_STRING_VALUE_NAME);
        }

        public static String GetEntityConnectionString()
        {
            EntityConnectionStringBuilder MyEntityConnectionStringBuilder = new EntityConnectionStringBuilder();
            MyEntityConnectionStringBuilder.ProviderConnectionString = GetConnectionString();
            MyEntityConnectionStringBuilder.Provider = DataAccessConstants.ENTITY_CONNECTION_PROVIDER;
            MyEntityConnectionStringBuilder.Metadata = DataAccessConstants.ENTITY_CONNECTION_STRING_METADATA;
            return MyEntityConnectionStringBuilder.ToString();
        }




    }
}