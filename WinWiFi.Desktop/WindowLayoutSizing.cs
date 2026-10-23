using System;

namespace WinWiFi;

/// <summary>Calculates the managed desktop shell size from Windows' usable work area.</summary>
internal static class WindowLayoutSizing
{
    internal const double WorkAreaFraction = 0.90;

    internal static (double Width, double Height) FromWorkArea(double width, double height)
    {
        if (width <= 0 || height <= 0)
            throw new ArgumentOutOfRangeException(nameof(width), "The Windows work area must have positive dimensions.");

        return (Math.Floor(width * WorkAreaFraction), Math.Floor(height * WorkAreaFraction));
    }
}
