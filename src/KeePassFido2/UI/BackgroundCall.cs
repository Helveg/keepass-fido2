using System;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows.Forms;

namespace KeePassFido2.UI
{
    /// <summary>
    /// Runs a blocking Windows Hello or WebAuthn call off the UI thread while keeping KeePass's
    /// windows painted. The prompts belong to a separate Windows process that parents itself to
    /// our window, which must keep pumping messages meanwhile.
    /// </summary>
    internal static class BackgroundCall
    {
        public static T Run<T>(Func<T> call)
        {
            T result = default(T);
            ExceptionDispatchInfo error = null;
            using (var done = new ManualResetEvent(false))
            {
                var thread = new Thread(() =>
                {
                    try
                    {
                        result = call();
                    }
                    catch (Exception ex)
                    {
                        error = ExceptionDispatchInfo.Capture(ex);
                    }
                    finally
                    {
                        done.Set();
                    }
                }) { IsBackground = true, Name = "KeePassFido2 prompt" };
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();

                while (!done.WaitOne(15))
                    Application.DoEvents();
            }

            error?.Throw();
            return result;
        }

        public static void Run(Action call) => Run<object>(() =>
        {
            call();
            return null;
        });
    }
}
