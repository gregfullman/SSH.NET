using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    [Message("SSH_MSG_USERAUTH_GSSAPI_TOKEN", 61)]
    public class GssapiTokenMessage : Message
    {
        private readonly byte[] _sendToken;

        /// <summary>
        /// 
        /// </summary>
        public byte[] ReceiveToken { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        public GssapiTokenMessage()
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sendToken"></param>
        public GssapiTokenMessage(byte[] sendToken)
        {
            _sendToken = sendToken;
        }

        /// <summary>
        /// 
        /// </summary>
        protected override int BufferCapacity
        {
            get
            {
                return base.BufferCapacity + 4 + _sendToken.Length;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void LoadData()
        {
            ReceiveToken = this.ReadBinary();
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void SaveData()
        {
            this.WriteBinaryString(_sendToken);
        }

        internal override void Process(Session session)
        {
            session.OnGssapiTokenReceived(this);
        }
    }
}
