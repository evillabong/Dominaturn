using Microsoft.Win32;
using System;

namespace Dominaturn.Base.Misc
{
    public class RegeditAccessKeys
    {
        private RegistryKey Key { get; set; }
        private RegeditAccessKeys()
        {


        }

        public static RegeditAccessKeys BuildInitialRegistryKey(RegistryHive registryHive, String baseKey)
        {
            return new RegeditAccessKeys { Key = RegistryKey.OpenBaseKey(registryHive, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32).OpenSubKey(baseKey) };
        }

        public String GetStringData(String valueName)
        {
            return Key.GetValue(valueName).ToString();
        }

        public Int32 GetRegDWordData(String valueName)
        {
            return (Int32)Key.GetValue(valueName);
        }

        public Int64 GetRegQWordData(String valueName)
        {
            return (Int64)Key.GetValue(valueName);
        }

        public void SetStringData(String valueName, String data)
        {
            Key.SetValue(valueName, data);
        }

        public void SetRegDWordData(String valueName, Int32 data)
        {
            Key.SetValue(valueName, data);
        }

        public void SetRegQWordData(String valueName, Int64 data)
        {
            Key.SetValue(valueName, data);
        }
    }
}