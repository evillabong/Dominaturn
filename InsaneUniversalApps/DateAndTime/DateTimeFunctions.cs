using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Insane.UniversalApps.DateAndTime
{
    /// <summary>
    /// Funciones para manejo con fechas y horas.
    /// </summary>
    public class DateTimeFunctions
    {
        /// <summary>
        /// Obtiene la siguiente fecha que coincide con el día de la semana especificado.
        /// </summary>
        /// <param name="StartDate">Fecha de la cual se empezará a buscar el siguiente día activo.</param>
        /// <param name="Dow">Día de la semana.</param>
        /// <returns>Fecha con el siguiente día de la semana activo.</returns>
        public static DateTime GetNextActiveDayOfWeek(DateTime StartDate, DayOfWeek Dow)
        {
            int daysToAdd = ((int)Dow - (int)StartDate.DayOfWeek + 7) % 7;
            return StartDate.AddDays(daysToAdd);
        }
    }
}
