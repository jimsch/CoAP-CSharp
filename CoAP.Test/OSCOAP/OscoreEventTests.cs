using System;
using CoAP.Test.Std10.MockItems;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;

namespace CoAP.Test.Std10.OSCOAP
{
    [TestClass]
    public class OscoreEventTests
    {
        private static readonly byte[] docSecret = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        private static readonly byte[] docSalt = new byte[] {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
        private static readonly byte[] docSenderId = new byte[0];
        private static readonly byte[] docRecipientId = new byte[] {1};
        private static readonly byte[] docGroupId = new byte[] {0xa, 0xb, 0xc};

        private static readonly byte[] entity1Id = new byte[] {0xE1};

        private static readonly string entity1KeyStr =
            "A601020241E12001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3";

        private OneKey _entity1Key;

        private static readonly byte[] entity2Id = new byte[] {0xE2};

        private static readonly string entity2KeyStr =
            "A601020241E2200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF";

        private OneKey _entity2Key;

        private static readonly byte[] entity3Id = new byte[] {0xE3};

        private static readonly string _Entity3_Key_Str =
            "A6010220010241E321582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB23582002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3";

        private OneKey _entity3Key;

        private MockMessagePump MessagePump { get; set; }
        private CoapConfig ClientConfig { get; set; }
        private CoapConfig ServerConfig { get; set; }

        [TestInitialize]
        public void Setup()
        {
            _entity1Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(entity1KeyStr)));
            _entity2Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(entity2KeyStr)));
            _entity3Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity3_Key_Str)));

            ClientConfig = new CoapConfig();
            ServerConfig = new CoapConfig();

            MessagePump = new MockMessagePump(new Type[] {typeof(OscoapLayer)}, ClientConfig, ServerConfig);
        }

        //  Non-group message - no group ID - KID - no context
        //  Two cases - 1) don't return a key,  2) return a new key
        [TestMethod]
        public void OscoreEventNoKeyId1()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(docSecret, null, docSenderId, docRecipientId, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] keyId = null;
            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownKeyIdentifier &&
                    e.GroupIdentifier == null && e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {
                    keyId = e.KeyIdentifier;
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.IsNotNull(item.Request);
                    Assert.AreEqual(item.Request.Method, Method.POST);
                    Assert.IsFalse(item.Request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(item.Request.HasOption(OptionType.Oscore));

                    byte[] option = item.Request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x09, 1});
                    break;


                case MockQueueItem.QueueType.ClientSendResponse:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(item.Response.StatusCode, StatusCode.Unauthorized);
                    break;
                }
            }

            Assert.IsNotNull(keyId);
            CollectionAssert.AreEqual(docSenderId, keyId);
        }

        [TestMethod]
        public void OscoreEventNoKeyId2()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(docSecret, null, docSenderId, docRecipientId, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] keyId = null;
            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownKeyIdentifier &&
                    e.GroupIdentifier == null && e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {
                    keyId = e.KeyIdentifier;
                    e.SecurityContext = SecurityContext.DeriveContext(docSecret, null, docRecipientId, docSenderId, docSalt);

                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ServerSendRequest:
                    MessagePump.Queue.Dequeue();

                    var serverRequest = item.Request;
                    Assert.IsNotNull(keyId);
                    CollectionAssert.AreEqual(docSenderId, keyId);

                    Assert.IsNotNull(serverRequest);
                    Assert.AreEqual(serverRequest.Method, Method.GET);
                    Assert.IsTrue(serverRequest.HasOption(OptionType.UriPath));
                    Assert.IsFalse(serverRequest.HasOption(OptionType.Oscore));
                    break;
                }
            }
        }

        //  Non-group Message - w/ group ID - kID - no context
        //  two cases 1) don't return a key, 2) return a new key
        [TestMethod]
        public void OscoreEventNoGroupIdFail()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(docSecret, docGroupId, docSenderId, docRecipientId, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {
                    callbackKid = e.KeyIdentifier;
                    callbackGid = e.GroupIdentifier;
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x19, 1, 3, 0xa, 0xb, 0xc});
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(item.Response.StatusCode, StatusCode.Unauthorized);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(docSenderId, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        [TestMethod]
        public void OscoreEventNoGroupIdFail2()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = SecurityContext.DeriveContext(docSecret, docGroupId, docSenderId, docRecipientId, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (
                    e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {
                    callbackKid = e.KeyIdentifier;
                    callbackGid = e.GroupIdentifier;

                    e.SecurityContext = SecurityContext.DeriveContext(docSecret, docGroupId, docRecipientId, docSenderId, docSalt);
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x19, 1, 3, 0xa, 0xb, 0xc});
                    break;

                case MockQueueItem.QueueType.ServerSendRequest:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(Method.GET, item.Request.Method);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(docSenderId, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        //  Group Message - 
        //      1. Group ID is not known - fail
        //      2. Group ID is not known - return group only for server - fail on key
        //      3. Group ID is not known - return group only for server - fail on key - but return AM LOOKING state
        //      4. Group ID is not known - return group only for server - add client key
        //      5. Group ID is not known - return group + client key
        [TestMethod]
        public void OscoreEventGroupNoGroupId()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity1Id, AlgorithmValues.ECDSA_256, _entity1Key, null, null, null, null, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {
                    callbackKid = e.KeyIdentifier;
                    callbackGid = e.GroupIdentifier;
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xE1});
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(item.Response.StatusCode, StatusCode.Unauthorized);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(entity1Id, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        [TestMethod]
        public void OscoreEventGroupNoGroupId2()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity1Id, AlgorithmValues.ECDSA_256, _entity1Key, null, null, null, null, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {

                    e.SecurityContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity3Id, AlgorithmValues.ECDSA_256, _entity3Key, null, null, null, null, docSalt);
                    e.SecurityContext.OscoreEvents += (o1, e1) => {
                        if (e1.Code == OscoreEvent.EventCode.UnknownKeyIdentifier && e1.RecipientContext == null && e1.SecurityContext != null &&
                            e1.SenderContext == null) {
                            callbackGid = e1.GroupIdentifier;
                            callbackKid = e1.KeyIdentifier;
                        }
                    };
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xE1});
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(StatusCode.BadRequest, item.Response.StatusCode);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(entity1Id, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        [TestMethod]
        public void OscoreEventGroupNoGroupId3()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity1Id, AlgorithmValues.ECDSA_256, _entity1Key, null, null, null, null, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {

                    e.SecurityContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity3Id, AlgorithmValues.ECDSA_256, _entity3Key, null, null, null, null, docSalt);
                    e.SecurityContext.OscoreEvents += (o1, e1) => {
                        if (e1.Code == OscoreEvent.EventCode.UnknownKeyIdentifier && e1.RecipientContext == null && e1.SecurityContext != null &&
                            e1.SenderContext == null) {
                            callbackGid = e1.GroupIdentifier;
                            callbackKid = e1.KeyIdentifier;
                            e1.StatusCode = StatusCode.ServiceUnavailable;
                        }
                    };
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xE1});
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(StatusCode.ServiceUnavailable, item.Response.StatusCode);
                    Assert.IsTrue(item.Response.HasOption(OptionType.MaxAge));
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(entity1Id, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        [TestMethod]
        public void OscoreEventGroupNoGroupId4()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity1Id, AlgorithmValues.ECDSA_256, _entity1Key, null, null, null, null, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {

                    GroupSecurityContext g =
                        GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity3Id, AlgorithmValues.ECDSA_256, _entity3Key, null, null, null, null, docSalt);
                    e.SecurityContext = g;
                    e.SecurityContext.OscoreEvents += (o1, e1) => {
                        if (e1.Code == OscoreEvent.EventCode.UnknownKeyIdentifier && e1.RecipientContext == null && e1.SecurityContext != null &&
                            e1.SenderContext == null) {
                            callbackGid = e1.GroupIdentifier;
                            callbackKid = e1.KeyIdentifier;
                            GroupSecurityContext g1 = e1.SecurityContext as GroupSecurityContext;
                            g1.AddRecipient(entity1Id, _entity1Key);
                            e1.RecipientContext = g1.Recipients[entity1Id];
                        }
                    };
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xE1});
                    break;

                case MockQueueItem.QueueType.ServerSendRequest:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(Method.GET, item.Request.Method);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(entity1Id, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }

        [TestMethod]
        public void OscoreEventGroupNoGroupId5()
        {
            Request request = new Request(Method.GET) {
                UriPath = "/a/b",
                OscoreContext = GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity1Id, AlgorithmValues.ECDSA_256, _entity1Key, null, null, null, null, docSalt)
            };

            MessagePump.SendRequest(request);

            byte[] callbackKid = null;
            byte[] callbackGid = null;

            MockEndpoint serverEndpoint = MessagePump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.OscoreEvents += (o, e) => {
                if (e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier &&
                    e.RecipientContext == null && e.SecurityContext == null && e.SenderContext == null) {

                    GroupSecurityContext g =
                        GroupSecurityContext.DeriveGroupContext(docSecret, docGroupId, entity3Id, AlgorithmValues.ECDSA_256, _entity3Key, null, null, null, null, docSalt);
                    e.SecurityContext = g;
                    g.AddRecipient(entity1Id, _entity1Key);
                    e.RecipientContext = g.Recipients[entity1Id];

                    callbackGid = e.GroupIdentifier;
                    callbackKid = e.KeyIdentifier;
                }
            };

            while (MessagePump.Pump()) {
                MockQueueItem item = MessagePump.Queue.Peek();
                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    Assert.AreEqual(request.Method, Method.POST);
                    Assert.IsFalse(request.HasOption(OptionType.UriPath));
                    Assert.IsTrue(request.HasOption(OptionType.Oscore));

                    byte[] option = request.GetFirstOption(OptionType.Oscore).RawValue;
                    CollectionAssert.AreEqual(option, new byte[] {0x39, 1, 3, 0xa, 0xb, 0xc, 0xE1});
                    break;

                case MockQueueItem.QueueType.ServerSendRequest:
                    MessagePump.Queue.Dequeue();
                    Assert.AreEqual(Method.GET, item.Request.Method);
                    break;
                }
            }

            Assert.IsNotNull(callbackKid);
            CollectionAssert.AreEqual(entity1Id, callbackKid);
            Assert.IsNotNull(callbackGid);
            CollectionAssert.AreEqual(docGroupId, callbackGid);
        }
    }
}
