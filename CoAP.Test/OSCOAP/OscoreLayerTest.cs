using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using PeterO.Cbor;
using Org.BouncyCastle.Utilities.Encoders;
using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP.Codec;
using CoAP.Test.Std10.MockItems;
using Message = Com.AugustCellars.COSE.Message;

namespace CoAP.Test.Std10.OSCOAP
{
    [TestClass]
    public class OscoreLayerTest
    {
        private static readonly byte[] _Doc_Secret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static readonly byte[] _Doc_Salt = new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
        private static readonly byte[] _Doc_SenderId = new byte[0];
        private static readonly byte[] _Doc_RecipientId = new byte[] { 1 };
        private static readonly byte[] _Doc_GroupId = new byte[] { 0xa, 0xb, 0xc };

        private static readonly byte[] _Entity1_Id = new byte[] { 0xE1 };
        private static readonly string _Entity1_Key_Str = "A601020241E12001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3";
        private OneKey _Entity1_Key;

        private static readonly byte[] _Entity2_Id = new byte[] { 0xE2 };
        private static readonly string _Entity2_Key_Str = "A601020241E2200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF";
        private OneKey _Entity2_Key;

        private static readonly byte[] _Entity3_Id = new byte[] { 0xE3 };
        private static readonly string _Entity3_Key_Str = "A6010220010241E321582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB23582002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3";
        private OneKey _Entity3_Key;

        private MockMessagePump MessagePump { get; set; }
        private CoapConfig ClientConfig { get; set; }
        private CoapConfig ServerConfig { get; set; }
 
        [TestInitialize]
        public void Setup()
        {
            _Entity1_Key = new OneKey( CBORObject.DecodeFromBytes(Hex.Decode(_Entity1_Key_Str)));
            _Entity2_Key = new OneKey( CBORObject.DecodeFromBytes(Hex.Decode(_Entity2_Key_Str)));
            _Entity3_Key = new OneKey( CBORObject.DecodeFromBytes(Hex.Decode(_Entity3_Key_Str)));

            ClientConfig = new CoapConfig();
            ServerConfig = new CoapConfig();

            MessagePump = new MockMessagePump(new Type[]{typeof(OscoapLayer)}, ClientConfig, ServerConfig);
        }

        private void SetupServer()
        {
        }

        [TestMethod]
        public void LayerTest_Get()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b", 
                OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt)
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        Assert.AreEqual(Method.POST, item.Request.Method );
                        Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                        Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                        byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                        CollectionAssert.AreEqual(option, new byte[] { 0x09, 1 });
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        MessagePump.Queue.Dequeue();
                        Assert.AreEqual(Method.GET, item.Request.Method);
                        Assert.IsTrue(item.Request.HasOption(OptionType.UriPath));
                        Assert.IsFalse(item.Request.HasOption(OptionType.Oscore));

                        Response serverResponse = new Response(StatusCode.Content) {
                            PayloadString = "This is the payload"
                        };

                        item.Exchange.EndPoint.SendResponse(item.Exchange, serverResponse);
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        Assert.AreEqual(StatusCode.Changed, item.Response.StatusCode);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        MessagePump.Queue.Dequeue();
                        Assert.AreEqual(StatusCode.Content, item.Response.StatusCode);
                        break;
                }
            }
        }

        [TestMethod]
        public void LayerTest_Observe()
        {
            Request request = new Request(Method.GET)
            {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt),
                Observe = 0
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        Assert.AreEqual(Method.FETCH, item.Request.Method);
                        Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                        Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));
                        Assert.IsTrue(request.HasOption(OptionType.Observe));

                        byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                        CollectionAssert.AreEqual(option, new byte[] { 0x09, 1 });
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        MessagePump.Queue.Dequeue();
                        Assert.AreEqual(Method.GET, item.Request.Method);
                        Assert.IsTrue(item.Request.HasOption(OptionType.UriPath));
                        Assert.IsFalse(item.Request.HasOption(OptionType.Oscore));
                        Assert.IsTrue(request.HasOption(OptionType.Observe));

                        Response serverResponse = new Response(StatusCode.Content) {
                            PayloadString = "This is the payload #1",
                            Observe = 5
                        };

                        item.Exchange.EndPoint.SendResponse(item.Exchange, serverResponse);
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        Assert.AreEqual(StatusCode.Changed, item.Response.StatusCode);
                        Assert.IsTrue(item.Response.HasOption(OptionType.Oscore));
                        Assert.IsTrue(item.Response.HasOption(OptionType.Observe));
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        MessagePump.Queue.Dequeue();
                        break;
                }
            }

            CollectionAssert.AreEqual(request.OscoreContext.Sender.PartialIV, new byte[] { 1 });
        }

        [TestMethod]
        public void LayerTest_Get_GroupId()
        {
            Request request = new Request(Method.GET)
            {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, _Doc_GroupId, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt)
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, _Doc_GroupId, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        Assert.AreEqual(Method.POST, item.Request.Method);
                        Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                        Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                        byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                        CollectionAssert.AreEqual(option, new byte[] { 0x19, 1, 0x3, 0xa, 0xb, 0xc });
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        MessagePump.Queue.Dequeue();
                        break;
                }
            }
        }

        [TestMethod]
        public void LayerTest_Get_KeyId()
        {
            Request request = new Request(Method.GET)
            {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt)
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt));

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(Method.POST, item.Request.Method);
                    Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                    byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] { 0x09, 1, 1 });
                    break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        MessagePump.Queue.Dequeue();
                        break;
                }
            }
        }

        [TestMethod]
        public void LayerTest_Get_KeyId_GroupId()
        {
            Request request = new Request(Method.GET)
            {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, _Doc_GroupId, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt)
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, _Doc_GroupId, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt));

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(Method.POST, item.Request.Method);
                    Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                    byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] { 0x19, 1, 3, 0xa, 0xb, 0xc, 1 });
                    break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        MessagePump.Queue.Dequeue();
                        break;
                }
            }
        }

        [TestMethod]
        public void LayerTest_Group_Get()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Entity1_Id, AlgorithmValues.ECDSA_256, _Entity1_Key, null, null, null, null, _Doc_Salt)
            };

            IEndPoint ep = MessagePump.ServerStacks[MockMessagePump.ServerAddress].First().MyEndPoint;
            ep.SecurityContexts = new SecurityContextSet();
            ep.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));
            GroupSecurityContext group = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Entity3_Id, AlgorithmValues.ECDSA_256, _Entity3_Key, null, null, null, null, _Doc_Salt);
            group.AddRecipient(_Entity1_Id, _Entity1_Key);
            group.AddRecipient(_Entity2_Id, _Entity2_Key);
            ep.SecurityContexts.Add(group);

            MessagePump.SendRequest(request);

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();

                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(Method.POST, item.Request.Method);
                    Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                    byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xe1});
                    break;

                case MockQueueItem.QueueType.ServerSendRequest:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(item.Request.Method, Method.GET);
                    Assert.IsTrue(item.Request.HasOption(OptionType.UriPath));
                    Assert.IsFalse(item.Request.HasOption(OptionType.Oscore));
                    break;
                }
            }
        }

        [TestMethod]
        public void SendRequestEvents()
        {
            ICoapConfig config = new CoapConfig();
            OscoapLayer layer = new OscoapLayer(config);
            GroupSecurityContext oscoreContext = GroupSecurityContext.DeriveGroupContext(_Doc_Secret, _Doc_GroupId, _Entity1_Id, AlgorithmValues.ECDSA_256, _Entity1_Key, null, null, null, null, _Doc_Salt);

            OscoreEvent.EventCode eventCode = 0;

            oscoreContext.OscoreEvents += (sender, eventArgs) =>
            {
                eventCode = eventArgs.Code;

                switch (eventArgs.Code) {
                    case OscoreEvent.EventCode.PivExhaustion:
                        break;

                    case OscoreEvent.EventCode.SenderIvSave:
                        break;

                    default:
                        break;
                }
            };

            long[] sequenceNumbers = new long[]{ 0, 10, 99, 150, 199, 0xffffffffff, 0xffffffffff+1 };
            OscoreEvent.EventCode[] codes = new OscoreEvent.EventCode[] { 0, 0, OscoreEvent.EventCode.SenderIvSave, 0, OscoreEvent.EventCode.SenderIvSave, 0, OscoreEvent.EventCode.PivExhaustion };


            for (int i = 0; i < sequenceNumbers.Length; i++) {
                eventCode = 0;
                oscoreContext.Sender.SequenceNumber = sequenceNumbers[i];

                Request request = new Request(Method.GET);
                Exchange exchange = new Exchange(request, Origin.Local);

                request.UriPath = "/a/b";
                request.OscoreContext = oscoreContext;

                try {
                    bool b = layer.SendRequest(null, exchange, request);
                    Assert.IsTrue(b);
                }
                catch (CoAPException) {
                    continue;
                }

                Assert.AreEqual(codes[i], eventCode);

            }
        }
    }
}
