using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class RequestMessageKerberos : RequestMessage
    {
        private const byte SSH_GSS_OIDTYPE = 0x06;

        private readonly byte[] _mechanism;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="serviceName"></param>
        /// <param name="username"></param>
        /// <param name="mechanism"></param>
        public RequestMessageKerberos(ServiceName serviceName, string username, byte[] mechanism)
            : base(serviceName, username, "gssapi-with-mic")
        {
            _mechanism = mechanism;
        }

        /// <summary>
        /// 
        /// </summary>
        protected override int BufferCapacity
        {
            get
            {
                var capacity = base.BufferCapacity;
                capacity += 4;  // number of mechanisms
                capacity += 4 + 1;  // length of OID + 2, plus the GSS_OIDTYPE byte length
                capacity += 1; // length of OID
                capacity += _mechanism.Length;  // length of mechanisms array
                return capacity;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void SaveData()
        {
            // This handles step 2 of the document

            // Do the standard pieces of the message
            base.SaveData();

            // add number of GSSAPI mechanisms
            this.Write((uint)1);

            // add length of OID + 2
            this.Write((uint)_mechanism.Length + 2);
            this.Write((byte)SSH_GSS_OIDTYPE);

            // add length of OID
            this.Write((byte)_mechanism.Length);

            // add the mechanism info
            this.Write(_mechanism);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="responseMessage"></param>
        /// <returns></returns>
        public bool ValidateResponse(GssapiResponseMessage responseMessage)
        {
            return responseMessage.ReceivedToken.Length != _mechanism.Length + 2 ||
                   responseMessage.ReceivedToken[0] != SSH_GSS_OIDTYPE ||
                   responseMessage.ReceivedToken[1] != _mechanism.Length ||
                   !responseMessage.ReceivedToken.Skip(2).SequenceEqual(_mechanism);
        }
    }
}
