using System;

namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    [Message("SSH_MSG_USERAUTH_GSSAPI_MIC", 66)]
    public class GssapiMicMessage : Message
    {
        private readonly byte[] _micData;

        /// <summary>
        /// 
        /// </summary>
        public GssapiMicMessage() { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="micData"></param>
        public GssapiMicMessage(byte[] micData)
        {
            _micData = micData;
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void LoadData()
        {
            // No response (supposedly) so nothing to do here
        }

        /// <summary>
        /// 
        /// </summary>
        protected override int BufferCapacity
        {
            get
            {
                return base.BufferCapacity + 4 + _micData.Length;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void SaveData()
        {
            this.WriteBinaryString(_micData);
        }

        internal override void Process(Session session)
        {
            // TODO: not sure if this would ever get hit
            throw new NotImplementedException();
        }
    }
}
