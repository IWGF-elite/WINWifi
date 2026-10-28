using System.Net;
using System.Net.Sockets;

namespace WinWiFi.Services
{
    /// <summary>
    /// Picks a loopback port for the desktop's bridge when the preferred one is
    /// held by another local process (for example a CLI bridge left running).
    /// </summary>
    internal static class BridgePortSelector
    {
        public static bool IsPortAvailable(int port)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
                listener.Stop();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Returns the first free port at or after <paramref name="preferredPort"/>, or null.</summary>
        public static int? FindAvailablePort(int preferredPort, int attempts = 10)
        {
            for (int port = preferredPort; port < preferredPort + attempts; port++)
            {
                if (IsPortAvailable(port)) return port;
            }
            return null;
        }
    }
}
