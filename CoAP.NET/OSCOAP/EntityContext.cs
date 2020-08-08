using Com.AugustCellars.COSE;
using PeterO.Cbor;
using System;

namespace Com.AugustCellars.CoAP.OSCOAP
{
    public interface ISenderEntityContext
    {
        /// <summary>
        /// What is the base IV value for this context?
        /// </summary>
        byte[] BaseIV { get; set; }

        /// <summary>
        /// What is the identity of this context - matches a key identifier.
        /// </summary>
        byte[] Id { get; set; }

        /// <summary>
        /// What is the cryptographic key?
        /// </summary>
        byte[] Key { get; set; }


        /// <summary>
        /// Return the sequence number as a byte array.
        /// </summary>
        byte[] PartialIV { get; }

        /// <summary>
        /// What is the current sequence number (IV) for the context?
        /// </summary>
        long SequenceNumber { get; set; }

        /// <summary>
        /// Check to see if all of the Partial IV Sequence numbers are exhausted.
        /// </summary>
        /// <returns>true if exhausted</returns>
        bool SequenceNumberExhausted { get; }

        /// <summary>
        /// Should an IV update event be sent?
        /// </summary>
        bool SendSequenceNumberUpdate { get; }

        /// <summary>
        /// Set/get the maximum sequence number.  Limited to five bits.
        /// </summary>
        long MaxSequenceNumber { get; set; }

        /// <summary>
        /// Given a partial IV, create the actual IV to use
        /// </summary>
        /// <param name="partialIV">partial IV</param>
        /// <returns>full IV</returns>
        CBORObject GetIV(byte[] partialIV);

        /// <summary>
        /// Increment the sequence/parital IV
        /// </summary>
        void IncrementSequenceNumber();

        /// <summary>
        /// The key to use for counter signing purposes
        /// </summary>
        OneKey SigningKey { get; set; }

    }

    public interface IRecipientEntityContext
    {

        /// <summary>
        /// What is the identity of this context - matches a key identifier.
        /// </summary>
        byte[] Id { get; set; }

        /// <summary>
        /// The key to use for counter signing purposes
        /// </summary>
        OneKey SigningKey { get; set; }

        /// <summary>
        /// What is the cryptographic key?
        /// </summary>
        byte[] Key { get; set; }

        /// <summary>
        /// What is the base IV value for this context?
        /// </summary>
        byte[] BaseIV { get; set; }

        /// <summary>
        /// Given a partial IV, create the actual IV to use
        /// </summary>
        /// <param name="partialIV">partial IV</param>
        /// <returns>full IV</returns>
        CBORObject GetIV(byte[] partialIV);

        /// <summary>
        /// Get/Set the replay window checker for the context.
        /// </summary>
        ReplayWindow ReplayWindow { get; set; }
    }

    public class EntityContext : ISenderEntityContext, IRecipientEntityContext
    {
        /// <summary>
        /// Create new entity crypto context structure
        /// </summary>
        public EntityContext()
        {
        }

        /// <summary>
        /// Create new entity crypto context structure
        /// Copy constructor - needed to clone key material
        /// </summary>
        /// <param name="old">old structure</param>
        public EntityContext(EntityContext old)
        {
            BaseIV = (byte[]) old.BaseIV.Clone();
            Key = (byte[]) old.Key.Clone();
            Id = (byte[]) old.Id.Clone();
            ReplayWindow = new ReplayWindow(0, 256);
            SequenceNumber = old.SequenceNumber;
            SigningKey = old.SigningKey;
        }

        /// <summary>
        /// What is the base IV value for this context?
        /// </summary>
        public byte[] BaseIV { get; set; }

        /// <summary>
        /// What is the identity of this context - matches a key identifier.
        /// </summary>
        public byte[] Id { get; set; }

        /// <summary>
        /// What is the cryptographic key?
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// What is the current sequence number (IV) for the context?
        /// </summary>
        public long SequenceNumber { get; set; }

        /// <summary>
        /// At what frequency should the IV update event be sent?
        /// SequenceNumber % SequenceInterval == 0
        /// </summary>
        public int SequenceInterval { get; set; } = 100;

        /// <summary>
        /// Should an IV update event be sent?
        /// </summary>
        public bool SendSequenceNumberUpdate => (SequenceNumber % SequenceInterval) == 0;

        /// <summary>
        /// Return the sequence number as a byte array.
        /// </summary>
        public byte[] PartialIV
        {
            get {
                byte[] part = BitConverter.GetBytes(SequenceNumber);
                if (BitConverter.IsLittleEndian) Array.Reverse(part);
                int i;
                for (i = 0; i < part.Length - 1; i++) {
                    if (part[i] != 0) break;
                }

                Array.Copy(part, i, part, 0, part.Length - i);
                Array.Resize(ref part, part.Length - i);

                return part;
            }
        }

        /// <summary>
        /// Given a partial IV, create the actual IV to use
        /// </summary>
        /// <param name="partialIV">partial IV</param>
        /// <returns>full IV</returns>
        public CBORObject GetIV(byte[] partialIV)
        {
            byte[] iv = (byte[]) BaseIV.Clone();
            int offset = iv.Length - partialIV.Length;

            for (int i = 0; i < partialIV.Length; i++) {
                iv[i + offset] ^= partialIV[i];
            }

            return CBORObject.FromObject(iv);
        }

        /// <summary>
        /// Get/Set the replay window checker for the context.
        /// </summary>
        public ReplayWindow ReplayWindow { get; set; }

        /// <summary>
        /// Increment the sequence/parital IV
        /// </summary>
        public void IncrementSequenceNumber()
        {
            SequenceNumber += 1;
            if (SequenceNumber > MaxSequenceNumber) {
                throw new CoAPException("Oscore Partial IV exhaustion");
            }
        }

        /// <summary>
        /// Check to see if all of the Partial IV Sequence numbers are exhausted.
        /// </summary>
        /// <returns>true if exhausted</returns>
        public bool SequenceNumberExhausted => SequenceNumber >= MaxSequenceNumber;

        private long _maxSequenceNumber = 0xfffff;

        /// <summary>
        /// Set/get the maximum sequence number.  Limited to five bits.
        /// </summary>
        public long MaxSequenceNumber
        {
            get => _maxSequenceNumber;
            set {
                if (value > 0xfffff || value < 0) {
                    throw new CoAPException("value must be no more than 0xfffff");
                }

                _maxSequenceNumber = value;
            }
        }

        /// <summary>
        /// The key to use for counter signing purposes
        /// </summary>
        public OneKey SigningKey { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            string ret = $"kid= {BitConverter.ToString(Id)} key={BitConverter.ToString(Key)} IV={BitConverter.ToString(BaseIV)} PartialIV={BitConverter.ToString(PartialIV)}\n";
            if (SigningKey != null) {
                ret += $" {SigningKey.AsCBOR()}";
            }

            return ret;
        }
    }
}

