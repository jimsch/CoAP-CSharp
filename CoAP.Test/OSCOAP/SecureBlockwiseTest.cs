using System;
using System.Collections.Generic;
using System.Text;
using CoAP.Test.Std10.MockItems;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Stack;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;

namespace CoAP.Test.Std10.OSCOAP
{
    [TestClass]
    public class SecureBlockwiseTest
    {
        static readonly String SHORT_POST_REQUEST = "<Short request>";
        static string LONG_POST_REQUEST; 
        static readonly String SHORT_POST_RESPONSE = "<Short response>";
        static string LONG_POST_RESPONSE;
        static string SHORT_GET_RESPONSE = SHORT_POST_RESPONSE.ToLower();
        static string LONG_GET_RESPONSE;

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

        [TestInitialize]
        public void Setup()
        {
            int resourceSize = 1024*10;

            _Entity1_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity1_Key_Str)));
            _Entity2_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity2_Key_Str)));
            _Entity3_Key = new OneKey(CBORObject.DecodeFromBytes(Hex.Decode(_Entity3_Key_Str)));

            string blockFormat = new StringBuilder()
                .Append("/-- Post -----------------------------------------------------\\\r\n")
                .Append("|               RESOURCE BLOCK NO. {0,3} OF {1,3}                 |\r\n")
                .Append("|               [each line contains 64 bytes]                 |\r\n")
                .Append("\\-------------------------------------------------------------/\r\n")
                .ToString();

            string payload = "";
            int count = resourceSize / (64 * 4);
            for (int i = 0; i < count; i++) {
                payload += string.Format(blockFormat, i + 1, count);
            }

            LONG_POST_REQUEST = payload;
            LONG_POST_RESPONSE = payload.ToLower();
            LONG_GET_RESPONSE = LONG_POST_RESPONSE.Replace("post", " get");

        }

        //
        //  Tests to be run -- All in SecureBlockwise
        //  1. POST short, short
        //  2. POST long, short
        //  3. POST short, long
        //  4. POST long, long
        //  5. GET short
        //  6.  GET long
        //
        //  Using both SecureBlockwise and Unsecure Blockwise
        //  1. POST short, short
        //  2. POST long, short
        //  3. POST short, long
        //  4. POST long, long
        //  5. GET short
        //  6. GET long
        //
        //  Observe response
        //  Multicast
        //  Concurrent operations

        [TestMethod]
        public void Block1()
        {
            Request r = new Request(Method.POST);
            r.PayloadString = SHORT_POST_REQUEST;
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[]{typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer)});
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        clientCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        serverCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        pump.Queue.Dequeue();
                        Assert.AreEqual(SHORT_POST_REQUEST, item.Request.PayloadString);

                        Response s = new Response(StatusCode.Content);
                        s.PayloadString = SHORT_POST_RESPONSE;
                        item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        pump.Queue.Dequeue();

                        Assert.AreEqual(SHORT_POST_RESPONSE, item.Response.PayloadString);
                        break;
                }
            }

            Assert.AreEqual(1, clientCount);
            Assert.AreEqual(1, serverCount);

        }

        [TestMethod]
        public void Block2()
        {
            CoapConfig clientCoapConfig = new CoapConfig();
            CoapConfig serverCoapConfig = new CoapConfig();

            LogManager.Level = LogLevel.Debug;

            clientCoapConfig.DefaultBlockSize = 4096;
            clientCoapConfig.MaxMessageSize = 4200;
            clientCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            clientCoapConfig.OSCOAP_MaxMessageSize = 1400;

            Request r = new Request(Method.POST);
            r.PayloadString = LONG_POST_REQUEST;
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer) }, clientCoapConfig, serverCoapConfig);
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        clientCount += 1;
                        Assert.IsFalse(item.Request.HasOption(OptionType.Block1));
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        serverCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        pump.Queue.Dequeue();
                        Assert.AreEqual(LONG_POST_REQUEST, item.Request.PayloadString);

                        Response s = new Response(StatusCode.Content);
                        s.PayloadString = SHORT_POST_RESPONSE;
                        item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        pump.Queue.Dequeue();

                        Assert.AreEqual(SHORT_POST_RESPONSE, item.Response.PayloadString);
                        break;
                }
            }

            Assert.AreEqual(11, clientCount);
            Assert.AreEqual(11, serverCount);

        }

        [TestMethod]
        public void Block3()
        {
            CoapConfig clientCoapConfig = new CoapConfig();
            CoapConfig serverCoapConfig = new CoapConfig();

            clientCoapConfig.DefaultBlockSize = 4096;
            clientCoapConfig.MaxMessageSize = 4200;
            clientCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            clientCoapConfig.OSCOAP_MaxMessageSize = 1400;

            serverCoapConfig.DefaultBlockSize = 4096;
            serverCoapConfig.MaxMessageSize = 4200;
            serverCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            serverCoapConfig.OSCOAP_MaxMessageSize = 1400;

            Request r = new Request(Method.POST);
            r.PayloadString = SHORT_POST_REQUEST;
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer) }, clientCoapConfig, serverCoapConfig);
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        clientCount += 1;
                        Assert.IsFalse(item.Request.HasOption(OptionType.Block1));
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        serverCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        pump.Queue.Dequeue();
                        Assert.AreEqual(SHORT_POST_REQUEST, item.Request.PayloadString);

                        Response s = new Response(StatusCode.Content);
                        s.PayloadString = LONG_POST_RESPONSE;
                        item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        pump.Queue.Dequeue();

                        Assert.AreEqual(LONG_POST_RESPONSE, item.Response.PayloadString);
                        break;
                }
            }

            Assert.AreEqual(11, clientCount);
            Assert.AreEqual(11, serverCount);

        }

        [TestMethod]
        public void Block4()
        {
            CoapConfig clientCoapConfig = new CoapConfig();
            CoapConfig serverCoapConfig = new CoapConfig();

            LogManager.Level = LogLevel.Debug;

            clientCoapConfig.DefaultBlockSize = 4096;
            clientCoapConfig.MaxMessageSize = 4200;
            clientCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            clientCoapConfig.OSCOAP_MaxMessageSize = 1400;

            serverCoapConfig.DefaultBlockSize = 4096;
            serverCoapConfig.MaxMessageSize = 4200;
            serverCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            serverCoapConfig.OSCOAP_MaxMessageSize = 1400;

            Request r = new Request(Method.POST);
            r.PayloadString = LONG_POST_REQUEST;
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer) }, clientCoapConfig, serverCoapConfig);
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        clientCount += 1;
                        Assert.IsFalse(item.Request.HasOption(OptionType.Block1));
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        serverCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        pump.Queue.Dequeue();
                        Assert.AreEqual(LONG_POST_REQUEST, item.Request.PayloadString);

                        Response s = new Response(StatusCode.Content);
                        s.PayloadString = LONG_POST_RESPONSE;
                        item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        pump.Queue.Dequeue();

                        Assert.AreEqual(LONG_POST_RESPONSE, item.Response.PayloadString);
                        break;
                }
            }

            Assert.AreEqual(21, clientCount);
            Assert.AreEqual(21, serverCount);

        }

        [TestMethod]
        public void Block5()
        {
            Request r = new Request(Method.GET);
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer) });
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                    case MockQueueItem.QueueType.ClientSendRequestNetwork:
                        clientCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendResponseNetwork:
                        serverCount += 1;
                        break;

                    case MockQueueItem.QueueType.ServerSendRequest:
                        pump.Queue.Dequeue();
                        Assert.IsTrue(item.Request.PayloadSize == 0);

                        Response s = new Response(StatusCode.Content);
                        s.PayloadString = SHORT_GET_RESPONSE;
                        item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                        break;

                    case MockQueueItem.QueueType.ClientSendResponse:
                        pump.Queue.Dequeue();

                        Assert.AreEqual(SHORT_GET_RESPONSE, item.Response.PayloadString);
                        break;
                }
            }

            Assert.AreEqual(1, clientCount);
            Assert.AreEqual(1, serverCount);

        }

        [TestMethod]
        public void Block6()
        {
            CoapConfig clientCoapConfig = new CoapConfig();
            CoapConfig serverCoapConfig = new CoapConfig();

            LogManager.Level = LogLevel.Debug;


            clientCoapConfig.DefaultBlockSize = 4096;
            clientCoapConfig.MaxMessageSize = 4200;
            clientCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            clientCoapConfig.OSCOAP_MaxMessageSize = 1400;

            serverCoapConfig.DefaultBlockSize = 4096;
            serverCoapConfig.MaxMessageSize = 4200;
            serverCoapConfig.OSCOAP_DefaultBlockSize = 1024;
            serverCoapConfig.OSCOAP_MaxMessageSize = 1400;

            Request r = new Request(Method.GET);
            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            MockMessagePump pump = new MockMessagePump(new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer) }, clientCoapConfig, serverCoapConfig);
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            int clientCount = 0;
            int serverCount = 0;

            pump.SendRequest(r);
            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    clientCount += 1;
                    break;

                case MockQueueItem.QueueType.ServerSendResponseNetwork:
                    serverCount += 1;
                    break;

                case MockQueueItem.QueueType.ServerSendRequest:
                    pump.Queue.Dequeue();
                    Assert.IsTrue(item.Request.PayloadSize == 0);

                    Response s = new Response(StatusCode.Content);
                    s.PayloadString = LONG_GET_RESPONSE;
                    item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    pump.Queue.Dequeue();

                    Assert.AreEqual(LONG_GET_RESPONSE, item.Response.PayloadString);
                    break;
                }
            }

            Assert.AreEqual(11, clientCount);
            Assert.AreEqual(11, serverCount);

        }

    }
}
