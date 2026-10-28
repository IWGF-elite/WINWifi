using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace WinWiFi.Services
{
    /// <summary>
    /// Keeps WinWiFi to a single desktop instance: the first launch owns a named
    /// mutex; any later launch signals a named event so the first window comes
    /// to the foreground, then exits without showing anything.
    /// </summary>
    public sealed class SingleInstanceGuard : IDisposable
    {
        public const string DefaultMutexName = @"Local\WinWiFi.Desktop.SingleInstance";
        public const string DefaultActivateEventName = @"Local\WinWiFi.Desktop.Activate";

        private const int AsfwAny = -1;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool AllowSetForegroundWindow(int dwProcessId);

        private readonly Mutex _mutex;
        private readonly EventWaitHandle _activateEvent;
        private RegisteredWaitHandle? _registration;
        private Action? _onActivate;

        private SingleInstanceGuard(Mutex mutex, EventWaitHandle activateEvent)
        {
            _mutex = mutex;
            _activateEvent = activateEvent;
        }

        public static SingleInstanceGuard? TryAcquire(
            string mutexName = DefaultMutexName,
            string activateEventName = DefaultActivateEventName)
        {
            var mutex = new Mutex(initiallyOwned: true, mutexName, out bool createdNew);
            if (!createdNew)
            {
                mutex.Dispose();
                return null;
            }
            // Created eagerly by the first instance so a later launch can signal
            // it even before StartActivationListener is registered.
            var activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, activateEventName);
            return new SingleInstanceGuard(mutex, activateEvent);
        }

        /// <summary>Called by a second launch to bring the existing window forward.</summary>
        public static void ActivateExistingInstance(string activateEventName = DefaultActivateEventName)
        {
            if (!OperatingSystem.IsWindows()) return;
            try
            {
                // The launching process usually holds foreground rights (Explorer
                // started it from a click). Hand them to the already-running
                // instance, otherwise Windows refuses its SetForegroundWindow.
                AllowSetForegroundWindow(AsfwAny);
                using var evt = EventWaitHandle.OpenExisting(activateEventName);
                evt.Set();
            }
            catch (Exception ex)
            {
                // No first instance listening (it may still be starting up); nothing to activate.
                Trace.TraceInformation($"Second launch could not signal activation: {ex.Message}");
            }
        }

        public void StartActivationListener(Action onActivate)
        {
            if (_registration is not null) return;
            _onActivate = onActivate;
            _registration = ThreadPool.RegisterWaitForSingleObject(
                _activateEvent,
                (_, _) => _onActivate?.Invoke(),
                null,
                Timeout.Infinite,
                executeOnlyOnce: false);
        }

        public void StopActivationListener()
        {
            _registration?.Unregister(null);
            _registration = null;
        }

        public void Dispose()
        {
            StopActivationListener();
            try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }
            _activateEvent.Dispose();
            _mutex.Dispose();
        }
    }
}
