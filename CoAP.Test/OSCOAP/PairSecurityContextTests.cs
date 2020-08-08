using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoAP.Test.Std10.OSCOAP
{
    [TestClass]
    public class PairSecurityContextTests
    {
        private static readonly byte[] _Doc_Secret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static readonly byte[] _Doc_Salt = new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
        private static readonly byte[] _Doc_SenderId = new byte[0];
        private static readonly byte[] _Doc_RecipientId = new byte[] { 1 };

        private static readonly byte[] _Doc_GroupId = new byte[] { 0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3 };

        private static readonly byte[] _Entity1_Id = new byte[] { 0x01 };
        private static readonly string _Entity1_Key_Str = "A60102024101235820FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E622582064CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB06842158201ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC962001";
        private OneKey _Entity1_Key;

        private static readonly byte[] _Entity2_Id = new byte[] { };
        private static readonly string _Entity2_Key_Str = "A601020240235820DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C903815972258201897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F2158200EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC12001";
        private OneKey _Entity2_Key;

        private static readonly byte[] _Entity3_Id = new byte[] { 0xAA };
        private static readonly string _Entity3_Key_Str = "A601020241AA235820BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E2258205694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD215820FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD2001";
        private OneKey _Entity3_Key;

        [TestInitialize]
        public void Setup()
        {
            _Entity1_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity1_Key_Str)));
            _Entity2_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity2_Key_Str)));
            _Entity3_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity3_Key_Str)));
        }

        [TestMethod]
        public void DeriveTest()
        {
            GroupSecurityContext group = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Entity1_Id, AlgorithmValues.ECDSA_256, _Entity1_Key, null, null, null, null, _Doc_Salt);
            group.AddRecipient(_Entity3_Id, _Entity3_Key);
            group.AddRecipient(_Entity2_Id, _Entity2_Key);

            PairSecurityContext pair12 = group.DerivePairContext(_Entity2_Id);

            PairSecurityContext pair13 = group.DerivePairContext(_Entity3_Id);

            GroupSecurityContext group3 = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Entity3_Id, AlgorithmValues.ECDSA_256, _Entity3_Key, null, null, null, null, _Doc_Salt);
            group3.AddRecipient(_Entity1_Id, _Entity1_Key);
            group3.AddRecipient(_Entity2_Id, _Entity2_Key);

            PairSecurityContext pair31 = group3.DerivePairContext(_Entity1_Id);


        }
    }
}
