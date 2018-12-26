using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    [Message("DummyGssApiMicMessage", 0)]
    public class DummyGssApiMicMessage : Message
    {
        private readonly byte[] _sessionId;
        private readonly string _username;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sessionId"></param>
        /// <param name="username"></param>
        public DummyGssApiMicMessage(byte[] sessionId, string username)
        {
            _sessionId = sessionId;
            _username = username;
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void LoadData()
        {
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void SaveData()
        {
            WriteBinaryString(_sessionId);
            Write((byte)50);
            Write(_username);
            Write("ssh-connection");
            Write("gssapi-with-mic");
        }

        internal override void Process(Session session)
        {
            throw new NotImplementedException();
        }
    }
}
