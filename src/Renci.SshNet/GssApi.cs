using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Renci.SshNet
{
    /// <summary>
    /// 
    /// </summary>
    public enum GSS_STATUS
    {
        /// <summary>
        /// 
        /// </summary>
        SSH_GSS_OK = 0,

        /// <summary>
        /// 
        /// </summary>
        SSG_GSS_S_CONTINUE_NEEDED,

        /// <summary>
        /// 
        /// </summary>
        SSH_GSS_NO_MEM,

        /// <summary>
        /// 
        /// </summary>
        SSH_GSS_BAD_HOST_NAME,

        /// <summary>
        /// 
        /// </summary>
        SSH_GSS_FAILURE
    }

    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        /// <summary>
        /// 
        /// </summary>
        public uint LowPart;

        /// <summary>
        /// 
        /// </summary>
        public int HighPart;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dummy"></param>
        public SECURITY_INTEGER(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };

    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        /// <summary>
        /// 
        /// </summary>
        public IntPtr LowPart;

        /// <summary>
        /// 
        /// </summary>
        public IntPtr HighPart;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dummy"></param>
        public SECURITY_HANDLE(int dummy)
        {
            LowPart = HighPart = IntPtr.Zero;
        }
    };

    /// <summary>
    /// 
    /// </summary>
    public class GssContext
    {
        /// <summary>
        /// 
        /// </summary>
        public UInt64 maj_stat;

        /// <summary>
        /// 
        /// </summary>
        public UInt64 min_stat;

        /// <summary>
        /// 
        /// </summary>
        public SECURITY_HANDLE cred_handle;

        /// <summary>
        /// 
        /// </summary>
        /*CtxtHandle*/
        public SECURITY_HANDLE context;

        /// <summary>
        /// 
        /// </summary>
        /*PCtxtHandle*/
        public SECURITY_HANDLE context_handle;

        /// <summary>
        /// 
        /// </summary>
        public SECURITY_INTEGER expiry;
    }

    /// <summary>
    /// 
    /// </summary>
    public enum SecBufferType
    {
        /// <summary>
        /// 
        /// </summary>
        SECBUFFER_VERSION = 0,

        /// <summary>
        /// 
        /// </summary>
        SECBUFFER_EMPTY = 0,

        /// <summary>
        /// 
        /// </summary>
        SECBUFFER_DATA = 1,

        /// <summary>
        /// 
        /// </summary>
        SECBUFFER_TOKEN = 2
    }

    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer : IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        public int cbBuffer;

        /// <summary>
        /// 
        /// </summary>
        public int BufferType;

        /// <summary>
        /// 
        /// </summary>
        public IntPtr pvBuffer;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bufferSize"></param>
        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secBufferBytes"></param>
        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secBufferBytes"></param>
        /// <param name="bufferType"></param>
        public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public struct MultipleSecBufferHelper
    {
        /// <summary>
        /// 
        /// </summary>
        public byte[] Buffer;

        /// <summary>
        /// 
        /// </summary>
        public SecBufferType BufferType;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="bufferType"></param>
        public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
        {
            if (buffer == null || buffer.Length == 0)
            {
                throw new ArgumentException("buffer cannot be null or 0 length");
            }

            Buffer = buffer;
            BufferType = bufferType;
        }
    };

    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc : IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        public int ulVersion;

        /// <summary>
        /// 
        /// </summary>
        public int cBuffers;

        /// <summary>
        /// 
        /// </summary>
        public IntPtr pBuffers; //Point to SecBuffer

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bufferSize"></param>
        public SecBufferDesc(int bufferSize)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secBufferBytes"></param>
        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secBufferBytesArray"></param>
        public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
        {
            if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
            {
                throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
            }

            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = secBufferBytesArray.Length;

            //Allocate memory for SecBuffer Array....
#pragma warning disable CS0618 // Type or member is obsolete
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);
#pragma warning restore CS0618 // Type or member is obsolete

            for (int Index = 0; Index < secBufferBytesArray.Length; Index++)
            {
                //Super hack: Now allocate memory for the individual SecBuffers
                //and just copy the bit values to the SecBuffer array!!!
                SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                //We will write out bits in the following order:
                //int cbBuffer;
                //int BufferType;
                //pvBuffer;
                //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                //are disposed...
#pragma warning disable CS0618 // Type or member is obsolete
                int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete
                Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.BufferType);
                Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.BufferType), ThisSecBuffer.pvBuffer);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
#pragma warning disable CS0618 // Type or member is obsolete
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                        //SecBuffer and release it...
#pragma warning disable CS0618 // Type or member is obsolete
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete
#pragma warning disable CS0618 // Type or member is obsolete
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
#pragma warning restore CS0618 // Type or member is obsolete
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //What we need to do here calculate the total number of bytes we need to copy...
#pragma warning disable CS0618 // Type or member is obsolete
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Now iterate over the individual buffers and put them together into a
                    //byte array...
#pragma warning disable CS0618 // Type or member is obsolete
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
#pragma warning restore CS0618 // Type or member is obsolete
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
#pragma warning disable CS0618 // Type or member is obsolete
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
#pragma warning restore CS0618 // Type or member is obsolete
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }

        /*public SecBuffer GetSecBuffer()
        {
            if(pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            return((SecBuffer)Marshal.PtrToStructure(pBuffers,typeof(SecBuffer)));
        }*/
    }

    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        /// <summary>
        /// 
        /// </summary>
        public uint cbMaxToken;

        /// <summary>
        /// 
        /// </summary>
        public uint cbMaxSignature;

        /// <summary>
        /// 
        /// </summary>
        public uint cbBlockSize;

        /// <summary>
        /// 
        /// </summary>
        public uint cbSecurityTrailer;
    };

    /// <summary>
    /// 
    /// </summary>
    public static class GssApi
    {
        /// <summary>
        /// 
        /// </summary>
        public const int TOKEN_QUERY = 0x00008;

        /// <summary>
        /// 
        /// </summary>
        public const int SEC_E_OK = 0;

        /// <summary>
        /// 
        /// </summary>
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;
        private const int SECPKG_CRED_OUTBOUND = 2;
        private const int SECURITY_NATIVE_DREP = 0x10;
        private const int SECPKG_CRED_INBOUND = 1;
        private const int MAX_TOKEN_SIZE = 12288;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_DELEGATE = 0x00000001;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_MUTUAL_AUTH = 0x00000002;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_REPLAY_DETECT = 0x00000004;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_CONFIDENTIALITY = 0x00000010;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_USE_SESSION_KEY = 0x00000020;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_PROMPT_FOR_CREDS = 0x00000040;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_ALLOCATE_MEMORY = 0x00000100;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_USE_DCE_STYLE = 0x00000200;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_DATAGRAM = 0x00000400;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_CONNECTION = 0x00000800;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_CALL_LEVEL = 0x00001000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_EXTENDED_ERROR = 0x00004000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_STREAM = 0x00008000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_INTEGRITY = 0x00010000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_IDENTIFY = 0x00020000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_NULL_SESSION = 0x00040000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_RESERVED1 = 0x00100000;

        /// <summary>
        /// 
        /// </summary>
        public const int ISC_REQ_FRAGMENT_TO_FIT = 0x00200000;

        /// <summary>
        /// 
        /// </summary>
        public const int SECPKG_ATTR_SIZES = 0;

        [DllImport("secur32.dll", SetLastError = true)]
        static extern int AcquireCredentialsHandle(
                string pszPrincipal, //SEC_CHAR*
                string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
                int fCredentialUse,
                IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID, //PLUID
                IntPtr pAuthData,//PVOID
                int pGetKeyFn, //SEC_GET_KEY_FN
                IntPtr pvGetKeyArgument, //PVOID
                ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
                ref SECURITY_INTEGER ptsExpiry); //PTimeStamp //TimeStamp ref

        [DllImport("secur32.dll", SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,//PCredHandle
            ref SECURITY_HANDLE phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        [DllImport("secur32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential,//PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        /// <summary>
        /// 
        /// </summary>
        /// <param name="phContext"></param>
        /// <param name="fQOP"></param>
        /// <param name="pMessage"></param>
        /// <param name="MessageSeqNo"></param>
        /// <returns></returns>
        [DllImport("secur32.Dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int MakeSignature(ref SECURITY_HANDLE phContext,          // Context to use
                                                uint fQOP,         // Quality of Protection
                                                ref SecBufferDesc pMessage,        // Message to sign
                                                uint MessageSeqNo);      // Message Sequence Num.

        /// <summary>
        /// 
        /// </summary>
        /// <param name="phContext"></param>
        /// <param name="ulAttribute"></param>
        /// <param name="pContextAttributes"></param>
        /// <returns></returns>
        [DllImport("secur32.Dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int QueryContextAttributes(ref SECURITY_HANDLE phContext,
                                                        uint ulAttribute,
                                                        out SecPkgContext_Sizes pContextAttributes);

        private static byte[] _gss_mech_krb5 = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

        /// <summary>
        /// 
        /// </summary>
        /// <param name="gss_mech"></param>
        /// <returns></returns>
        public static GSS_STATUS IndicateMech(out byte[] gss_mech)
        {
            gss_mech = _gss_mech_krb5;
            return GSS_STATUS.SSH_GSS_OK;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="host"></param>
        /// <param name="serverName"></param>
        /// <returns></returns>
        public static GSS_STATUS ImportName(string host, out string serverName)
        {
            serverName = null;

            if (host == null)
                return GSS_STATUS.SSH_GSS_FAILURE;

            serverName = string.Format("host/{0}", host);
            return GSS_STATUS.SSH_GSS_OK;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        public static GSS_STATUS AcquireCredentials(out GssContext credentials)
        {
            credentials = new GssContext
            {
                maj_stat = SEC_E_OK,
                min_stat = SEC_E_OK
            };

            credentials.maj_stat = (ulong)
                AcquireCredentialsHandle(null,
                                         "Kerberos",
                                         SECPKG_CRED_OUTBOUND,
                                         IntPtr.Zero,
                                         IntPtr.Zero,
                                         0,
                                         IntPtr.Zero,
                                         ref credentials.cred_handle,
                                         ref credentials.expiry);
            return GSS_STATUS.SSH_GSS_OK;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="credentials"></param>
        /// <param name="serverName"></param>
        /// <param name="toDelegate"></param>
        /// <param name="receiveToken"></param>
        /// <param name="sendToken"></param>
        /// <returns></returns>
        public static GSS_STATUS InitializeSecurityContext(ref GssContext credentials,
                                                           string serverName,
                                                           bool toDelegate,
                                                           byte[] receiveToken,     // server token
                                                           out byte[] sendToken)    // client token
        {
            sendToken = null;
            SECURITY_INTEGER ClientLifeTime = new SECURITY_INTEGER(0);
            SecBufferDesc _sendToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            int flags = ISC_REQ_MUTUAL_AUTH |
                        ISC_REQ_REPLAY_DETECT |
                        ISC_REQ_CONFIDENTIALITY |
                        ISC_REQ_ALLOCATE_MEMORY;

            if (toDelegate)
                flags |= ISC_REQ_DELEGATE;

            try
            {
                uint ContextAttributes = 0;

                if(receiveToken == null)
                {
                    credentials.maj_stat = (ulong)
                        InitializeSecurityContext(ref credentials.cred_handle,
                                                  IntPtr.Zero,
                                                  serverName,
                                                  flags,
                                                  0,
                                                  SECURITY_NATIVE_DREP,
                                                  IntPtr.Zero,
                                                  0,
                                                  out credentials.context,
                                                  out _sendToken,
                                                  out ContextAttributes,
                                                  out credentials.expiry);
                }
                else
                {
                    SecBufferDesc _receiveToken = new SecBufferDesc(receiveToken);

                    credentials.maj_stat = (ulong)
                        InitializeSecurityContext(ref credentials.cred_handle,
                                                  ref credentials.context,
                                                  serverName,
                                                  flags,
                                                  0,
                                                  SECURITY_NATIVE_DREP,
                                                  ref _receiveToken,
                                                  0,
                                                  out credentials.context,
                                                  out _sendToken,
                                                  out ContextAttributes,
                                                  out credentials.expiry);
                }

                sendToken = _sendToken.GetSecBufferByteArray();

                if (credentials.maj_stat == SEC_E_OK)
                    return GSS_STATUS.SSH_GSS_OK;
                if (credentials.maj_stat == SEC_I_CONTINUE_NEEDED)
                    return GSS_STATUS.SSG_GSS_S_CONTINUE_NEEDED;

                return GSS_STATUS.SSH_GSS_FAILURE;
            }
            finally
            {
                _sendToken.Dispose();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="credentials"></param>
        /// <param name="message"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static GSS_STATUS GetMic(ref GssContext credentials,
                                        byte[] message,
                                        out byte[] hash)
        {
            hash = null;
            SecPkgContext_Sizes contextSizes;
            SecBuffer[] inputSecurityToken = new SecBuffer[2];

            credentials.maj_stat = (ulong)
                QueryContextAttributes(ref credentials.context,
                                       SECPKG_ATTR_SIZES,
                                       out contextSizes);

            if(credentials.maj_stat != SEC_E_OK ||
               contextSizes.cbMaxSignature == 0)
            {
                return (GSS_STATUS)credentials.maj_stat;
            }

            MultipleSecBufferHelper[] thisSecHelper = new MultipleSecBufferHelper[2];
            thisSecHelper[0] = new MultipleSecBufferHelper(message, SecBufferType.SECBUFFER_DATA);
            thisSecHelper[1] = new MultipleSecBufferHelper(new byte[contextSizes.cbMaxSignature], SecBufferType.SECBUFFER_TOKEN);

            SecBufferDesc descBuffer = new SecBufferDesc(thisSecHelper);

            try
            {
                if (MakeSignature(ref credentials.context,
                                 0,
                                 ref descBuffer,
                                 0) == SEC_E_OK)
                {
                    var tempHash = descBuffer.GetSecBufferByteArray();

                    // need to get the last set of bytes, corresponding with the SECBUFFER_TOKEN
                    int startAt = tempHash.Length - (int)contextSizes.cbMaxSignature;
                    hash = tempHash.Skip(startAt).ToArray();
                }
            }
            finally
            {
                descBuffer.Dispose();
            }

            return (GSS_STATUS)credentials.maj_stat;
        }
    }
}
