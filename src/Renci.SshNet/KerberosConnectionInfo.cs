using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.ObjectModel;

namespace Renci.SshNet
{
    /// <summary>
    /// 
    /// </summary>
    public class KerberosConnectionInfo : ConnectionInfo, IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="username"></param>
        public KerberosConnectionInfo(string host, string username)
            : this(host, ConnectionInfo.DefaultPort, username, ProxyTypes.None, string.Empty, 0, string.Empty, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <param name="username"></param>
        public KerberosConnectionInfo(string host, int port, string username)
            : this(host, port, username, ProxyTypes.None, string.Empty, 0, string.Empty, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        public KerberosConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort)
            : this(host, port, username, proxyType, proxyHost, proxyPort, string.Empty, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        /// <param name="proxyUsername"></param>
        public KerberosConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername)
            : this(host, port, username, proxyType, proxyHost, proxyPort, proxyUsername, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        public KerberosConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort)
            : this(host, ConnectionInfo.DefaultPort, username, proxyType, proxyHost, proxyPort, string.Empty, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        /// <param name="proxyUsername"></param>
        public KerberosConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername)
            : this(host, ConnectionInfo.DefaultPort, username, proxyType, proxyHost, proxyPort, proxyUsername, string.Empty)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        /// <param name="proxyUsername"></param>
        /// <param name="proxyPassword"></param>
        public KerberosConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, string proxyPassword)
            : this(host, ConnectionInfo.DefaultPort, username, proxyType, proxyHost, proxyPort, proxyUsername, proxyPassword)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <param name="username"></param>
        /// <param name="proxyType"></param>
        /// <param name="proxyHost"></param>
        /// <param name="proxyPort"></param>
        /// <param name="proxyUsername"></param>
        /// <param name="proxyPassword"></param>
        public KerberosConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, string proxyPassword)
            : base(host, port, username, proxyType, proxyHost, proxyPort, proxyUsername, proxyPassword, new KerberosAuthenticationMethod(username))
        {
        }

        #region IDisposable Members

        private bool _isDisposed;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called.
            if (!this._isDisposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.
                    if (this.AuthenticationMethods != null)
                    {
                        foreach (var authenticationMethods in this.AuthenticationMethods.OfType<IDisposable>())
                        {
                            authenticationMethods.Dispose();
                        }
                    }
                }

                // Note disposing has been done.
                _isDisposed = true;
            }
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="PasswordConnectionInfo"/> is reclaimed by garbage collection.
        /// </summary>
        ~KerberosConnectionInfo()
        {
            // Do not re-create Dispose clean-up code here.
            // Calling Dispose(false) is optimal in terms of
            // readability and maintainability.
            Dispose(false);
        }

        #endregion
    }
}
