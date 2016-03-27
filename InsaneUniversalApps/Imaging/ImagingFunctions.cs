using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Media.Imaging;

namespace Insane.UniversalApps.Imaging
{
    /// <summary>
    /// Funciones para el manejo de imágenes.
    /// </summary>
    public class ImagingFunctions
    {
        /// <summary>
        /// Convierte un arreglo de bytes a un BitmapImage.
        /// </summary>
        /// <param name="Source">Bytes origen.</param>
        /// <returns>Arreglo de bytes convertido.</returns>
        public static async Task<BitmapImage> ByteArrayToBitmapImageAsync(byte[] Source)
        {
            using (var stream = new InMemoryRandomAccessStream())
            {
                await stream.WriteAsync(Source.AsBuffer());
                var ret = new BitmapImage();
                stream.Seek(0);
                ret.SetSource(stream);
                return ret;
            }
        }
    }
}