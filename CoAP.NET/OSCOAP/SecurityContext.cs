using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
// using System.Runtime.Remoting.Messaging;
using System.Text;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Stack;
using PeterO.Cbor;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.OSCOAP
{
    /// <summary>
    /// Security context information for use with the OSCOAP structures.
    /// This structure supports doing both unicast and multicast transmission and
    /// reception of messages.
    /// </summary>
    public class SecurityContext
    {

        private static int _contextNumber;
        protected byte[] _MasterSecret;
        protected byte[] _Salt;

        public CBORObject CountersignParams { get; set; }
        public CBORObject CountersignKeyParams { get; set; }
        public int SignatureSize { get; } = 64;

        /// <summary>
        /// What is the global unique context number for this context.
        /// </summary>
        public int ContextNo { get; private set; }

        /// <summary>
        /// Return the sender information object
        /// </summary>
        public ISenderEntityContext Sender { get; protected set; } = new EntityContext();

        /// <summary>
        /// Return the single recipient object
        /// </summary>
        public IRecipientEntityContext Recipient { get; private set; }

        /// <summary>
        /// Group ID for multi-cast.
        /// </summary>
        public byte[] GroupId { get; set; }

        /// <summary>
        /// What encryption algorithm is being used?
        /// </summary>
        public CBORObject Algorithm { get; set; }

        public CBORObject SigningAlgorithm { get; set; }

        /// <summary>
        /// Location for a user to place significant information.
        /// For contexts that are created by the system this will be a list of
        /// COSE Web Tokens for authorization
        /// </summary>
        public object UserData { get; set; }

        /// <summary>
        /// Mark this context as being replaced with a new context
        /// </summary>
        public SecurityContext ReplaceWithSecurityContext { get; set; }

#if false
        /// <summary>
        /// Set of block exchanges associated with this 
        /// </summary>
        public ConcurrentDictionary<Exchange.KeyUri, OscoapLayer.BlockHolder> OngoingExchanges { get; } = new ConcurrentDictionary<Exchange.KeyUri, OscoapLayer.BlockHolder>();
#endif

        /// <summary>
        /// Gets or sets the status of the blockwise transfer of the request,
        /// or null in case of a normal transfer,
        /// </summary>
        public BlockwiseStatus RequestBlockStatus { get; set; }

        /// <summary>
        /// The response we are currently trying to blockwise transfer
        /// </summary>
        public Response OpenResponse { get; set; }


        /// <summary>
        /// Gets or sets the status of the blockwise transfer of the response,
        /// or null in case of a normal transfer,
        /// </summary>
        public BlockwiseStatus ResponseBlockStatus { get; set; }

        /// <summary>
        /// All of the respone sessions that are open for this security context.
        /// </summary>
        public Dictionary<Exchange.KeyID, SecureBlockwiseData> AllResponseSessions => new Dictionary<Exchange.KeyID, SecureBlockwiseData>();

        /// <summary>
        /// Set an object in the attribute map based on it's key.
        /// If a previous object existed, return it.
        ///
        /// M00BUG - This should be cleaned up.
        /// </summary>
        /// <param name="key">Key to use to save the object</param>
        /// <param name="value">value to save</param>
        /// <returns>old object if one exists.</returns>
        public object Set(object key, object value)
        {
            object old = null;
            _attributes.AddOrUpdate(key, value, (k, v) => {
                old = v;
                return value;
            });
            return old;
        }
        public object Remove(object key)
        {
            object obj;
            _attributes.TryRemove(key, out obj);
            return obj;
        }
        private readonly ConcurrentDictionary<object, object> _attributes = new ConcurrentDictionary<object, object>();

        /// <summary>
        /// Create a new empty security context
        /// </summary>
        public SecurityContext() { }

        /// <summary>
        /// Clone a security context - needed because key info needs to be copied.
        /// </summary>
        /// <param name="old">context to clone</param>
        public SecurityContext(SecurityContext old)
        {
            ContextNo = old.ContextNo;
            GroupId = old.GroupId;
            Sender = new EntityContext( (EntityContext) old.Sender);
            if (old.Recipient != null) Recipient = new EntityContext((EntityContext) old.Recipient);
        }

        public void ReplaceSender(byte[] senderId, OneKey signKey)
        {
            if (!signKey.HasAlgorithm(SigningAlgorithm)) {
                throw new ArgumentException("signature algorithm not correct");
            }

            EntityContext x = DeriveEntityContext(_MasterSecret, GroupId, senderId, _Salt, Algorithm);
            x.SigningKey = signKey;

            Sender = x;
        }


#region  Key Derivation Functions

        /// <summary>
        /// Given the input security context information, derive a new security context
        /// and return it
        /// </summary>
        /// <param name="rawData"></param>
        /// <param name="isServer">Flop the names when doing the derivtion</param>
        public static SecurityContext DeriveContext(CBORObject rawData, bool isServer)
        {
            return DeriveContext(rawData, isServer, null, null);
        }

        /// <summary>
        /// Given the input security context information, derive a new security context
        /// and return it
        /// </summary>
        /// <param name="rawData"></param>
        /// <param name="isServer">Flop the names when doing the derivtion</param>
        public static SecurityContext DeriveContext(CBORObject rawData, bool isServer, byte[] nonce1, byte[] nonce2)
        {
            byte[] groupId = null;
            byte[] senderId = rawData[isServer ? 3 : 2].GetByteString();
            byte[] receiverId = rawData[isServer ? 2 : 3].GetByteString();
            byte[] salt = new byte[0];
            CBORObject algAEAD = AlgorithmValues.AES_CCM_16_64_128;
            CBORObject algKDF = null;

            if (rawData.ContainsKey(7)) {
                groupId = rawData[7].GetByteString();
            }

            if (rawData.ContainsKey(4)) {
                algKDF = rawData[4];
            }

            if (rawData.ContainsKey(5)) {
                algAEAD = rawData[5];
            }

            if (rawData.ContainsKey(6)) {
                salt = rawData[6].GetByteString();
            }

            if (nonce1 != null) {
                byte[] newSalt = new byte[salt.Length + nonce1.Length + nonce2.Length];
                Array.Copy(salt, newSalt, salt.Length);
                Array.Copy(nonce1, 0, newSalt, salt.Length, nonce1.Length);
                Array.Copy(nonce2, 0, newSalt, salt.Length + nonce1.Length, nonce2.Length);
                salt = newSalt;
            }

            return DeriveContext(rawData[1].GetByteString(), groupId, senderId, receiverId,  salt, algAEAD, algKDF);
        }

        /// <summary>
        /// Given the set of inputs, perform the cryptographic operations that are needed
        /// to build a security context for a single sender and recipient.
        /// </summary>
        /// <param name="masterSecret">pre-shared key</param>
        /// <param name="senderContext">context for the ID</param>
        /// <param name="senderId">name assigned to sender</param>
        /// <param name="recipientId">name assigned to recipient</param>
        /// <param name="masterSalt">salt value</param>
        /// <param name="algAEAD">encryption algorithm</param>
        /// <param name="algKeyAgree">key agreement algorithm</param>
        /// <returns></returns>
        public static SecurityContext DeriveContext(byte[] masterSecret, byte[] senderContext, byte[] senderId, byte[] recipientId, 
                                                    byte[] masterSalt = null, CBORObject algAEAD = null, CBORObject algKeyAgree = null)
        {
            SecurityContext ctx = new SecurityContext();
            ctx.Algorithm = algAEAD ?? AlgorithmValues.AES_CCM_16_64_128;

            ctx.Sender = DeriveEntityContext(masterSecret, senderContext, senderId, masterSalt, ctx.Algorithm, algKeyAgree);
            ctx.Recipient = DeriveEntityContext(masterSecret, senderContext, recipientId, masterSalt, ctx.Algorithm, algKeyAgree);
            ctx.GroupId = senderContext;

            //  Give a unique context number for doing comparisons

            ctx.ContextNo = _contextNumber;
            _contextNumber += 1;

            return ctx;
        }



        /// <summary>
        /// Given the set of inputs, perform the cryptographic operations that are needed
        /// to build a security context for a single sender and recipient.
        /// </summary>
        /// <param name="masterSecret">pre-shared key</param>
        /// <param name="groupId">Group/Context Identifier</param>
        /// <param name="entityId">name assigned to sender</param>
        /// <param name="masterSalt">salt value</param>
        /// <param name="algAEAD">encryption algorithm</param>
        /// <param name="algKeyDerivation">key agreement algorithm</param>
        /// <returns></returns>
        protected static EntityContext DeriveEntityContext(byte[] masterSecret, byte[] groupId, byte[] entityId, byte[] masterSalt = null, CBORObject algAEAD = null, CBORObject algKeyDerivation = null)
        {
            EntityContext ctx = new EntityContext();
            int keySize;
            int ivSize;

            if (algAEAD == null) throw new ArgumentNullException(nameof(algAEAD));
            ctx.Id = entityId ?? throw new ArgumentNullException(nameof(entityId));
            if (algKeyDerivation == null) {
                algKeyDerivation = AlgorithmValues.HKDF_HMAC_SHA_256;
            }

            if (algAEAD.Type != CBORType.Integer) throw new ArgumentException("algorithm is unknown" );
            switch ((AlgorithmValuesInt) algAEAD.AsInt32()) {
                case AlgorithmValuesInt.AES_CCM_16_64_128:
                    keySize = 128 / 8;
                    ivSize = 13;
                    break;

                case AlgorithmValuesInt.AES_GCM_128:
                    keySize = 128 / 8;
                    ivSize = 96 / 8;
                    break;                       

                default:
                    throw new ArgumentException("content encryption algorithm is unknown");
            }

            ctx.ReplayWindow = new ReplayWindow(0, 64);

            CBORObject info = CBORObject.NewArray();

            info.Add(entityId);                 // 0
            info.Add(groupId);                  // 1
            info.Add(algAEAD);            // 2
            info.Add("Key");                    // 3
            info.Add(keySize);                  // 4 in bytes

            IDigest sha256;
            IDerivationFunction hkdf;

            if (algKeyDerivation.Equals(AlgorithmValues.ECDH_SS_HKDF_256) || algKeyDerivation.Equals(AlgorithmValues.HKDF_HMAC_SHA_256)) {
                sha256 = new Sha256Digest();
                hkdf = new HkdfBytesGenerator(sha256);
            }
            else if (algKeyDerivation.Equals(AlgorithmValues.ECDH_SS_HKDF_512) || algKeyDerivation.Equals(AlgorithmValues.HKDF_HMAC_SHA_512)) {
                sha256 = new Sha512Digest();
                hkdf = new HkdfBytesGenerator(sha256);
            }
            else {
                throw new ArgumentException("Unknown key agree algorithm");
            }

            hkdf.Init(new HkdfParameters(masterSecret, masterSalt, info.EncodeToBytes()));

            ctx.Key = new byte[keySize];
            hkdf.GenerateBytes(ctx.Key, 0, ctx.Key.Length);

            info[0] = CBORObject.FromObject(new byte[0]);
            info[3] = CBORObject.FromObject("IV");
            info[4] = CBORObject.FromObject(ivSize);
            hkdf.Init(new HkdfParameters(masterSecret, masterSalt, info.EncodeToBytes()));
            ctx.BaseIV = new byte[ivSize];
            hkdf.GenerateBytes(ctx.BaseIV, 0, ctx.BaseIV.Length);

            // Modify the context 

            if (ivSize - 6 < entityId.Length) throw new CoAPException("Entity id is too long");
            ctx.BaseIV[0] ^= (byte) entityId.Length;
            int i1 = ivSize - 5 - entityId.Length /*- 1*/;
            for (int i = 0; i < entityId.Length; i++) {
                ctx.BaseIV[i1 + i] ^= entityId[i];
            }

            return ctx;
        }
#endregion

        public bool IsGroupContext { get; protected set; }

        public event EventHandler<OscoreEvent> OscoreEvents;

        public void OnEvent(OscoreEvent e)
        {
            EventHandler<OscoreEvent> eventHandler = OscoreEvents;
            eventHandler?.Invoke(this, e);
        }

        /// <inheritdoc />
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("SecurityContext: ");
            sb.Append($"Secret: {BitConverter.ToString(_MasterSecret)}\n");
            sb.Append($"Sender: {Sender}");
                sb.Append($"Recipient: {Recipient}");

            return sb.ToString();
        }

        public class KeyId
        {
            private readonly CacheKey _cacheKey;
            private readonly System.Net.EndPoint _sourceEndPoint;
            private readonly int _hashCode;
            private readonly bool _isResponse;

            public KeyId(CacheKey cacheKey, System.Net.EndPoint sourceAddress, bool isResponse)
            {
                _cacheKey = cacheKey;
                _sourceEndPoint = sourceAddress;
                _hashCode = (int) (isResponse ? 7919 : 0 +  _sourceEndPoint.GetHashCode() * 59 * _cacheKey.GetHashCode() & 0xffffffff);
                _isResponse = isResponse;
            }

            /// <inheritdoc />
            public override bool Equals(object obj)
            {
                KeyId other = obj as KeyId;
                if (other == null) {
                    return false;
                }
                if (other == this) {
                    return true;
                }

                if (other._isResponse != _isResponse) {
                    return false;
                }

                if (!other._sourceEndPoint.Equals(_sourceEndPoint)) {
                    return false;
                }

                return _cacheKey.Equals(other._cacheKey);
            }


            /// <inheritdoc />
            public override int GetHashCode()
            {
                return _hashCode;
            }

            /// <inheritdoc />
            public override string ToString()
            {
                return $"KeyId: {_sourceEndPoint} {_cacheKey}";
            }
        }

        public ConcurrentDictionary<KeyId, SecureBlockwiseData> BlockwiseDictionary { get; set; }

        #region Equality comparer for bytes

        public class ByteArrayComparer : EqualityComparer<byte[]>
        {
            public override bool Equals(byte[] first, byte[] second)
            {
                return AreEqual(first, second);
            }

            public static bool AreEqual(byte[] first, byte[] second)
            {
                if (first == null || second == null) {
                    // null == null returns true.
                    // non-null == null returns false.
                    return first == second;
                }
                if (ReferenceEquals(first, second)) {
                    return true;
                }
                if (first.Length != second.Length) {
                    return false;
                }
                // Linq extension method is based on IEnumerable, must evaluate every item.
                return first.SequenceEqual(second);
            }
            public override int GetHashCode(byte[] obj)
            {
                if (obj == null) {
                    throw new ArgumentNullException(nameof(obj));
                }
                // quick and dirty, instantly identifies obviously different
                // arrays as being different
                return obj.Length;
            }
        }
#endregion

    }
}
