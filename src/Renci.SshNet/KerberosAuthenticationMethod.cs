using Renci.SshNet.Messages;
using Renci.SshNet.Messages.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Renci.SshNet
{
    /// <summary>
    /// Provides functionality to perform Kerberos (GSS) authentication
    /// </summary>
    public class KerberosAuthenticationMethod : AuthenticationMethod, IDisposable
    {
        private AuthenticationResult _authenticationResult = AuthenticationResult.Failure;

        private EventWaitHandle _stepCompleted = new ManualResetEvent(false);

        private GssapiResponseMessage _gssapiResponse = null;
        private GssapiTokenMessage _tokenResponse = null;

        /// <summary>
        /// 
        /// </summary>
        public override string Name
        {
            get
            {
                return "gssapi-with-mic";
            }
        }

        /// <summary>
        /// Initializes new instance of <see cref="KerberosAuthenticationMethod"/> class.
        /// </summary>
        /// <param name="username"></param>
        public KerberosAuthenticationMethod(string username)
            : base(username)
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="session"></param>
        /// <returns></returns>
        public override AuthenticationResult Authenticate(Session session)
        {
            session.UserAuthenticationSuccessReceived += Session_UserAuthenticationSuccessReceived;
            session.UserAuthenticationFailureReceived += Session_UserAuthenticationFailureReceived;
            session.GssapiResponseReceived += Session_GssapiResponseReceived;
            session.GssapiTokenReceived += Session_GssapiTokenReceived;

            // TODO: 1) initialize the gss lib

            // 2) get the mechanism from gss lib
            byte[] mechanism;
            if(GssApi.IndicateMech(out mechanism) != GSS_STATUS.SSH_GSS_OK)
            {
                this._authenticationResult = AuthenticationResult.Failure;
                return this._authenticationResult;
            }

            // pass in the mechanism from the gss lib to build up the message
            var message = new RequestMessageKerberos(ServiceName.Connection, this.Username, mechanism);

            // TODO: not sure if there's more to do before sending the message...
            session.RegisterMessage("SSH_MSG_USERAUTH_GSSAPI_RESPONSE");
            this._stepCompleted.Reset();
            session.SendMessage(message);
            session.WaitOnHandle(this._stepCompleted);
            session.UnRegisterMessage("SSH_MSG_USERAUTH_GSSAPI_RESPONSE");

            // Validate the response
            if(this._gssapiResponse != null && message.ValidateResponse(_gssapiResponse))
            {
                // 4) verify hostname via gsslib
                string serverName;
                if(GssApi.ImportName(session.ConnectionInfo.Host, out serverName) != GSS_STATUS.SSH_GSS_OK)
                {
                    this._authenticationResult = AuthenticationResult.Failure;
                    return this._authenticationResult;
                }

                // 5) fetch credentials from gsslib
                GssContext credentials;
                if(GssApi.AcquireCredentials(out credentials) != GSS_STATUS.SSH_GSS_OK)
                {
                    this._authenticationResult = AuthenticationResult.Failure;
                    return this._authenticationResult;
                }

                GSS_STATUS status = GSS_STATUS.SSH_GSS_OK;
                byte[] receiveToken = null;
                byte[] sendToken = null;

                do
                {
                    // 6a) Initialize the security context (gsslib)
                    status = GssApi.InitializeSecurityContext(ref credentials,
                                                              serverName,
                                                              false,        // TODO: this is a setting in PuTTY
                                                              receiveToken,
                                                              out sendToken);

                    if(status != GSS_STATUS.SSH_GSS_OK &&
                       status != GSS_STATUS.SSG_GSS_S_CONTINUE_NEEDED)
                    {
                        this._authenticationResult = AuthenticationResult.Failure;
                        return this._authenticationResult;
                    }

                    // 6b) exchange token with server
                    if(sendToken != null && sendToken.Length > 0)
                    {
                        var tokenMsg = new GssapiTokenMessage(sendToken);
                        session.RegisterMessage("SSH_MSG_USERAUTH_GSSAPI_TOKEN");
                        this._stepCompleted.Reset();
                        session.SendMessage(tokenMsg);
                        session.WaitOnHandle(this._stepCompleted);
                        session.UnRegisterMessage("SSH_MSG_USERAUTH_GSSAPI_TOKEN");

                        if (_tokenResponse != null)
                        {
                            // TODO: get contents of the response token message. They will be used for the next initialize security context call
                            receiveToken = _tokenResponse.ReceiveToken;
                        }
                        else
                        {
                            this._authenticationResult = AuthenticationResult.Failure;
                            return this._authenticationResult;
                        }
                    }
                }
                while (status == GSS_STATUS.SSG_GSS_S_CONTINUE_NEEDED);

                DummyGssApiMicMessage dummyMsg = new DummyGssApiMicMessage(session.SessionId, this.Username);
                var gssBuf = dummyMsg.GetBytes();

                byte[] hashMic;
                if(GssApi.GetMic(ref credentials, gssBuf.Skip(1).ToArray(), out hashMic) == GSS_STATUS.SSH_GSS_OK)
                {
                    // TODO: get the MIC from gsslib and send the MIC message
                    var micMsg = new GssapiMicMessage(hashMic);
                    this._stepCompleted.Reset();
                    session.SendMessage(micMsg);
                    session.WaitOnHandle(this._stepCompleted);
                    // TODO: not sure if we should wait for a response?
                }
                else
                {
                    this._authenticationResult = AuthenticationResult.Failure;
                }
            }
            else
            {
                // TODO: log error for GSSAPI auth refused
                this._authenticationResult = AuthenticationResult.Failure;
            }

            return this._authenticationResult;
        }

        private void Session_GssapiTokenReceived(object sender, MessageEventArgs<GssapiTokenMessage> e)
        {
            _gssapiResponse = null;
            _tokenResponse = e.Message;
            this._stepCompleted.Set();
        }

        private void Session_GssapiResponseReceived(object sender, MessageEventArgs<GssapiResponseMessage> e)
        {
            _gssapiResponse = e.Message;
            this._stepCompleted.Set();
        }

        private void Session_UserAuthenticationSuccessReceived(object sender, MessageEventArgs<SuccessMessage> e)
        {
            this._authenticationResult = AuthenticationResult.Success;

            this._stepCompleted.Set();
        }

        private void Session_UserAuthenticationFailureReceived(object sender, MessageEventArgs<FailureMessage> e)
        {
            if (e.Message.PartialSuccess)
                this._authenticationResult = AuthenticationResult.PartialSuccess;
            else
                this._authenticationResult = AuthenticationResult.Failure;

            //  Copy allowed authentication methods
            this.AllowedAuthentications = e.Message.AllowedAuthentications;

            this._stepCompleted.Set();
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            
        }
    }
}
