using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoAP.Test.Std10.OSCOAP
{
    [TestClass]
    public class GroupSecurityContextTest
    {

        private static readonly byte[] _Doc_Secret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static readonly byte[] _Doc_Salt = new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
        private static readonly byte[] _Doc_GroupId = new byte[] { 0xab, 0xcd };
        private static readonly byte[] _Doc_Entity1_Id = new byte[] { 0, 1 };
        private static readonly byte[] _Doc_Entity2_Id = new byte[] { 2, 1 };
        private static readonly byte[] _Doc_Entity3_Id = new byte[] { 2, 3 };

        private static readonly byte[] _Doc_SenderId = new byte[0];
        private static readonly byte[] _Doc_RecipientId = new byte[] { 1 };



        [TestMethod]
        [Ignore] //  Wait until new version comes out
        public void GroupDerive1()
        {
            OneKey signKey = new OneKey();
            signKey.Add(CoseKeyKeys.Algorithm, AlgorithmValues.EdDSA);

            GroupSecurityContext context = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Doc_Entity1_Id, 
                signKey[CoseKeyKeys.Algorithm], signKey, null, null, null, null, _Doc_Salt, null, null);

            CollectionAssert.AreEqual(context.Sender.Key, new byte[] { 0x96, 0xCF, 0x17, 0xBD, 0x0B, 0xF4, 0x26, 0x13, 0x75, 0x6E, 0xAD, 0x0A, 0x93, 0x66, 0xEE, 0xED }); 
            CollectionAssert.AreEqual(context.Sender.BaseIV, new byte[] { 0xF7, 0x47, 0x54, 0x04, 0x33, 0xCD, 0x65, 0xE9, 0x1F, 0x3B, 0x64, 0xC0, 0x98                 });
            Assert.AreEqual(context.Recipients.Count, 0);

            context.AddRecipient(_Doc_Entity2_Id, signKey);
            CollectionAssert.AreEqual(context.Recipients[_Doc_Entity2_Id].Key, new byte[] { 0x46, 0xE2, 0xD1, 0x64, 0x13, 0x57, 0x8D, 0x61, 0xC3, 0x59, 0x45, 0xD3, 0x42, 0xD0, 0x59, 0xD0 });
            CollectionAssert.AreEqual(context.Recipients[_Doc_Entity2_Id].BaseIV, new byte[] { 0xF6, 0x47, 0x54, 0x04, 0x33, 0xCD, 0x65, 0xE8, 0x1F, 0x3B, 0x64, 0xC0, 0x98 });

            context.AddRecipient(_Doc_Entity3_Id, signKey);
            CollectionAssert.AreEqual(context.Recipients[_Doc_Entity3_Id].Key, new byte[] { 0x46, 0xE2, 0xD1, 0x64, 0x13, 0x57, 0x8D, 0x61, 0xC3, 0x59, 0x45, 0xD3, 0x42, 0xD0, 0x59, 0xD0 });
            CollectionAssert.AreEqual(context.Recipients[_Doc_Entity3_Id].BaseIV, new byte[] { 0xF6, 0x47, 0x54, 0x04, 0x33, 0xCD, 0x65, 0xE8, 0x1F, 0x3B, 0x64, 0xC0, 0x98 });
            Assert.AreEqual(context.Recipients.Count, 2);
        }

        [TestMethod]
        public void Derive_C_3_1()
        {
            byte[] salt = new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
            byte[] groupId = new byte[] { 0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3 };
            OneKey signKey = new OneKey();
            signKey.Add(CoseKeyKeys.Algorithm, AlgorithmValues.EdDSA);

            GroupSecurityContext ctx = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, groupId, _Doc_SenderId,
                                                                     signKey[CoseKeyKeys.Algorithm], signKey, null, null,
                                                                     new byte[][] { _Doc_RecipientId }, new OneKey[] { signKey }, salt);

            CollectionAssert.AreEqual(ctx.Sender.Key, new byte[] { 0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88, 0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92 });
            CollectionAssert.AreEqual(ctx.Sender.BaseIV, new byte[] { 0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c, 0x0b, 0x71, 0x81, 0xb8, 0x5e });
            CollectionAssert.AreEqual(ctx.Recipients[_Doc_RecipientId].Key, new byte[] { 0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03, 0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f });
            CollectionAssert.AreEqual(ctx.Recipients[_Doc_RecipientId].BaseIV, new byte[] { 0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d, 0x0b, 0x71, 0x81, 0xb8, 0x5e });
        }

    }
}
