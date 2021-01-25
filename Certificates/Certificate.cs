using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace IdentityServer.Certificates
{
    public class Certificate
    {
        public static X509Certificate2 Get()
        {
            //return null;
            var fileName = Directory.GetCurrentDirectory() + @"\testIdentityServer.pfx";
            if (!File.Exists(fileName))
            {
                return null;
            }
            var cert = new X509Certificate2(fileName, "IdentityServer");
            return cert;
        }

        public static X509Certificate2 GetFromMachine()
        {
            try {
                X509Store storex = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                storex.Open(OpenFlags.ReadOnly);

                X509Certificate2 certificatex = storex.Certificates[0];

                storex.Close();
                return certificatex;
            }
            catch
            {
                return null;
            }
        }

        private static byte[] ReadStream(Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}
