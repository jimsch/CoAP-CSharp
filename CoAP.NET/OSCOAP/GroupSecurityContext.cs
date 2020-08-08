using Com.AugustCellars.COSE;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Com.AugustCellars.CoAP.OSCOAP
{
    public class GroupSecurityContext : SecurityContext
    {

        /// <summary>
        /// Get the set of all recipients for group.
        /// </summary>
        public Dictionary<byte[], IRecipientEntityContext> Recipients { get; private set; }

        protected GroupSecurityContext()
        { }

        public GroupSecurityContext(GroupSecurityContext old) : base(old)
        {
            if (old.Recipients != null) {
                Recipients = new Dictionary<byte[], IRecipientEntityContext>(new ByteArrayComparer());
                foreach (var item in old.Recipients) {
                    Recipients[item.Key] = new EntityContext(new EntityContext((EntityContext) item.Value));
                }
                IsGroupContext = true;
            }
        }

        /// <summary>
        /// Given the set of inputs, perform the cryptographic operations that are needed
        /// to build a security context for a single sender and recipient.
        /// </summary>
        /// <param name="masterSecret">pre-shared key</param>
        /// <param name="groupId">identifier for the group</param>
        /// <param name="senderId">name assigned to sender</param>
        /// <param name="algSignature">What is the signature algorithm</param>
        /// <param name="algCapabilities">COSE signing algorithm capabilities</param>
        /// <param name="keyCapabilities">COSE signing key capabilities</param>
        /// <param name="senderSignKey">what is the signing key for the signer</param>
        /// <param name="recipientIds">names assigned to recipients</param>
        /// <param name="recipientSignKeys">keys for any assigned recipients</param>
        /// <param name="masterSalt">salt value</param>
        /// <param name="algAEAD">encryption algorithm</param>
        /// <param name="algKeyDerivation">key derivation algorithm</param>
        /// <returns></returns>
        public static GroupSecurityContext DeriveGroupContext(byte[] masterSecret, byte[] groupId, byte[] senderId, 
                                                         CBORObject algSignature, OneKey senderSignKey, CBORObject algCapabilities, CBORObject keyCapabilities,
                                                         byte[][] recipientIds, OneKey[] recipientSignKeys,
                                                         byte[] masterSalt = null, CBORObject algAEAD = null, CBORObject algKeyDerivation = null)
        {
            GroupSecurityContext ctx = new GroupSecurityContext()
            {
                Recipients = new Dictionary<byte[], IRecipientEntityContext>(new ByteArrayComparer()),
                _MasterSecret = masterSecret,
                _Salt = masterSalt,
                IsGroupContext = true
            };

            if ((recipientIds != null && recipientSignKeys != null) && (recipientIds.Length != recipientSignKeys.Length)) {
                throw new ArgumentException("recipientsIds and recipientSignKey must be the same length");
            }

            if (senderSignKey.ContainsName(algSignature) &&  !senderSignKey.HasAlgorithm(algSignature)) {
                throw new ArgumentException("Wrong algorithm for sender sign key");
            }

            if (algAEAD == null) {
                algAEAD = AlgorithmValues.AES_CCM_16_64_128;
                ctx.Algorithm = algAEAD;
            }

            ctx.Sender = DeriveEntityContext(masterSecret, groupId, senderId, masterSalt, algAEAD,  algKeyDerivation);
            ctx.SigningAlgorithm = algSignature;
            ctx.Sender.SigningKey = senderSignKey;

            if (recipientIds != null) {
                if (recipientSignKeys == null) throw new ArgumentException("recipientSignKeys is null when recipientIds is not null");
                ctx.Recipients = new Dictionary<byte[], IRecipientEntityContext>(new ByteArrayComparer());
                for (int i = 0; i < recipientIds.Length; i++) {
                    if (!recipientSignKeys[i].HasAlgorithm(algSignature)) {
                        throw new ArgumentException("Wrong algorithm for recipient sign key");
                    }
                    EntityContext et = DeriveEntityContext(masterSecret, groupId, recipientIds[i], masterSalt, algAEAD, algKeyDerivation);
                    et.SigningKey = recipientSignKeys[i];
                    ctx.Recipients.Add(recipientIds[i], et);
                }
            }
            else if (recipientSignKeys != null) {
                throw new ArgumentException("recipientIds is null when recipientSignKeys is not null");
            }

            ctx.GroupId = groupId;

            if (algCapabilities == null || keyCapabilities == null) {
                switch ((AlgorithmValuesInt)algSignature.AsInt32()) {
                    case AlgorithmValuesInt.ECDSA_256:
                        if (algCapabilities == null) {
                            algCapabilities = CBORObject.DecodeFromBytes(new byte[] { 0x82, 0x81, 0x2, 0x82, 2, 1 });
                        }
                        if (keyCapabilities == null) {
                            keyCapabilities = CBORObject.DecodeFromBytes(new byte[] { 0x82, 2, 1 });
                        }
                        break;

                    case AlgorithmValuesInt.EdDSA:
                        if (algCapabilities == null) {
                            algCapabilities = CBORObject.DecodeFromBytes(new byte[] {0x82, 0x81, 0x1, 0x82, 0x1, 6});
                        }
                        if (keyCapabilities == null) {
                            keyCapabilities = CBORObject.DecodeFromBytes(new byte[] {0x82, 1, 6});
                        }
                        break;

                    default:
                        throw new ArgumentException("Unrecognized Algorithm for capabilities");
                }
            }

            ctx.CountersignParams = algCapabilities;
            ctx.CountersignKeyParams = keyCapabilities;

            return ctx;
        }

        public void AddRecipient(byte[] recipientId, OneKey signKey)
        {
            if (signKey.ContainsName(SigningAlgorithm) && !signKey.HasAlgorithm(SigningAlgorithm)) {
                throw new ArgumentException("signature algorithm not correct");
            }
            EntityContext x = DeriveEntityContext(_MasterSecret, GroupId, recipientId, _Salt, Algorithm);
            x.SigningKey = signKey;

            Recipients.Add(recipientId, x);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("SecurityContext: ");
            sb.Append($"Secret: {BitConverter.ToString(_MasterSecret)}\n");
            sb.Append($"Sender: {Sender}");
                foreach (KeyValuePair<byte[], IRecipientEntityContext> entity in Recipients) {
                    sb.Append($"Entity: {entity.Value}\n");

                }

            return sb.ToString();
        }

        public PairSecurityContext DerivePairContext(byte[] recipientId)
        {
            PairSecurityContext pair = new PairSecurityContext();
            
            if (!Recipients.ContainsKey(recipientId)) {
                throw new ArgumentException("No recipient exists", nameof(recipientId));
            }
            IRecipientEntityContext recipient = Recipients[recipientId];

            AsymmetricKeyParameter senderSignKey = Sender.SigningKey.AsPrivateKey();
            AsymmetricKeyParameter recipientSignKey = Recipients[recipientId].SigningKey.AsPublicKey();

            IBasicAgreement e1 = new ECDHBasicAgreement();
            e1.Init(senderSignKey);

            BigInteger k1 = e1.CalculateAgreement(recipientSignKey);

            byte[] secret = PadBytes(k1.ToByteArrayUnsigned(), 256);

            EntityContext senderContext = DeriveEntityContext(Sender.Key, this.GroupId, Sender.Id, secret, Algorithm, COSE.AlgorithmValues.HKDF_HMAC_SHA_256);
            EntityContext recipientContext = DeriveEntityContext(recipient.Key, GroupId, recipient.Id, secret, Algorithm, AlgorithmValues.HKDF_HMAC_SHA_256);



            return pair;
        }
        private byte[] PadBytes(byte[] rgbIn, int outSize)
        {
            outSize = (outSize + 7) / 8;
            if (rgbIn.Length == outSize) return rgbIn;
            byte[] x = new byte[outSize];
            Array.Copy(rgbIn, 0, x, outSize - rgbIn.Length, rgbIn.Length);
            return x;
        }
    }
}
