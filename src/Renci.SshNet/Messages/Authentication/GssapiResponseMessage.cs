using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    [Message("SSH_MSG_USERAUTH_GSSAPI_RESPONSE", 60)]
    public class GssapiResponseMessage : Message
    {
        /// <summary>
        /// 
        /// </summary>
        public byte[] ReceivedToken { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        protected override void LoadData()
        {
            ReceivedToken = this.ReadBytes();
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void SaveData()
        {
            // Nothing to save, this is only a response message (I think)
        }

        internal override void Process(Session session)
        {
            session.OnGssapiResponseReceived(this);
        }
    }
}
