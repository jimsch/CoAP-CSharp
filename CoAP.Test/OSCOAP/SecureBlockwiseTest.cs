using System;
using System.Collections.Generic;
using System.Text;
using CoAP.Test.Std10.MockItems;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Net;
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
        static readonly string ShortPostRequest = "<Short request>";
        static string LongPostRequest;
        static readonly String ShortPostResponse = "<Short response>";
        static string LongPostResponse;
        static string ShortGetResponse = ShortPostResponse.ToLower();
        static string LongGetResponse;

        private static readonly byte[] _Doc_Secret = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        private static readonly byte[] _Doc_Salt = new byte[] {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
        private static readonly byte[] _Doc_SenderId = new byte[0];
        private static readonly byte[] _Doc_RecipientId = new byte[] {1};
        private static readonly byte[] _Doc_GroupId = new byte[] {0xa, 0xb, 0xc};

        private static readonly byte[] _Entity1_Id = new byte[] {0xE1};

        private static readonly string _Entity1_Key_Str =
            "A601020241E12001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3";

        private OneKey _Entity1_Key;

        private static readonly byte[] _Entity2_Id = new byte[] {0xE2};

        private static readonly string _Entity2_Key_Str =
            "A601020241E2200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF";

        private OneKey _Entity2_Key;

        private static readonly byte[] _Entity3_Id = new byte[] {0xE3};

        private static readonly string _Entity3_Key_Str =
            "A6010220010241E321582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB23582002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3";

        private OneKey _Entity3_Key;

        private CoapConfig ClientConfig { get; } = new CoapConfig();
        private CoapConfig ServerConfig { get; } = new CoapConfig();


        [TestInitialize]
        public void Setup()
        {
            int resourceSize = 1024 * 10;

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

            LongPostRequest = payload;
            LongPostResponse = payload.ToLower();
            LongGetResponse = LongPostResponse.Replace("post", " get");

            ClientConfig.DefaultBlockSize = 4096;
            ClientConfig.MaxMessageSize = 4200;
            ClientConfig.OSCOAP_DefaultBlockSize = 1024;
            ClientConfig.OSCOAP_MaxMessageSize = 1400;

            ServerConfig.DefaultBlockSize = 4096;
            ServerConfig.MaxMessageSize = 4200;
            ServerConfig.OSCOAP_DefaultBlockSize = 1024;
            ServerConfig.OSCOAP_MaxMessageSize = 1400;
        }

        //
        //  Tests to be run -- All in SecureBlockwise
        //  Set of tests to be run
        //  1.  POST short-short
        //  2. POST short-long
        //  3. POST long-short
        //  4. POST long-long
        //  5. GET short
        //  6. GET long
        //  7. multicast get
        //  8. Observe gets
        //  9. Parallel gets
        //  *. Parallel posts
        //  *. random access
        //  *. pre-negotiate size
        //  *. Different sizes on each side - server bigger
        //  *. Different sizes on each side - client bigger

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
        //  Random access
        //  Restart in the middle - PUT & GET

        [TestMethod]
        public void Block1()
        {
            CommonTestCode(Method.POST, false, false, 1, 1);
        }

        [TestMethod]
        public void Block2()
        {
            CommonTestCode(Method.POST, false, true, 11, 11);
        }

        [TestMethod]
        public void Block3()
        {
            CommonTestCode(Method.POST, true, false, 11, 11);
        }

        [TestMethod]
        public void Block4()
        {
            CommonTestCode(Method.POST, true, true, 21, 21);
        }

        [TestMethod]
        public void Block5()
        {
            CommonTestCode(Method.GET, false, false, 1, 1);
        }

        [TestMethod]
        public void Block6()
        {
            CommonTestCode(Method.GET, false, true, 11, 11);
        }

        [TestMethod]
        public void BlockwiseTest8()
        {
            Observe = true;

            CommonTestCode(Method.GET, false, true, 21, 22);
        }

        [TestMethod]
        public void BlockwiseTest9()
        {
            Parallel = true;
            CommonTestCode(Method.GET, false, true, 22, 22);
        }

        private bool Observe { get; set; }
        private bool Parallel { get; set; }


        private void CommonTestCode(Method method, bool longRequest, bool longResponse, int expectedClient, int expectedServer)
        {
            string requestText = null;
            byte[] observeToken = new byte[] {0xa, 0xa, 0xa};
            int observeNum = 0;
            string[] currentResourceContent = new string[2];

            Type[] layerTypes = new Type[] { typeof(SecureBlockwiseLayer), typeof(OscoapLayer), typeof(BlockwiseLayer)};
            MockMessagePump pump = new MockMessagePump(layerTypes, ClientConfig, ServerConfig);

            Request r = new Request(method);
            if (method == Method.POST) {
                requestText = longRequest ? LongPostRequest : ShortPostRequest;
                currentResourceContent[0] = longResponse ? LongPostResponse : ShortPostResponse;
                r.PayloadString = requestText;
            }
            else {
                currentResourceContent[0] = longResponse ? LongGetResponse : ShortGetResponse;
                if (Observe) {
                    r.Observe = 1;
                    r.Token = observeToken;
                }
            }

            r.OscoreContext = SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_SenderId, _Doc_RecipientId, _Doc_Salt);

            //  Server side contexts.
            MockEndpoint serverEndpoint = pump.ServerStacks[MockMessagePump.ServerAddress][0].MyEndPoint;
            serverEndpoint.SecurityContexts = new SecurityContextSet();
            serverEndpoint.SecurityContexts.Add(SecurityContext.DeriveContext(_Doc_Secret, null, _Doc_RecipientId, _Doc_SenderId, _Doc_Salt));

            pump.SendRequest(r);

            if (Parallel) {
                Request r2 = new Request(method) {
                    UriPath = "/resource2"
                };
                currentResourceContent[1] = longResponse ? LongGetResponse.Replace("get ", "getA") : ShortGetResponse + "P";
                pump.SendRequest(r2);
            }

            int clientCount = 0;
            int serverCount = 0;
            int success = 0;
            Exchange observeExchange = null;

            while (pump.Pump()) {
                MockQueueItem item = pump.Queue.Peek();

                switch (item.ItemType) {
                //  Check conditions of the request when ready to transmit it on the wire
                case MockQueueItem.QueueType.ClientSendRequestNetwork:
                    if (Observe) {
                        if (item.Request.HasOption(OptionType.Observe)) {
                        }
                        else {
                        }
                    }

                    clientCount += 1;
                    break;

                //  Check conditions of the response when ready to transmit it on the wire
                case MockQueueItem.QueueType.ServerSendResponseNetwork:
                    if (Observe) {
                        if (item.Response.HasOption(OptionType.Observe)) {
                            CollectionAssert.AreEqual(observeToken, item.Response.Token);
                        }
                        else {
                            CollectionAssert.AreNotEqual(observeToken, item.Response.Token);
                        }
                    }

                    serverCount += 1;
                    break;

                // Server Resource is going to respond
                case MockQueueItem.QueueType.ServerSendRequest:
                    pump.Queue.Dequeue();
                    if (method == Method.POST) {
                        Assert.AreEqual(requestText, item.Request.PayloadString);
                    }
                    else {
                        Assert.AreEqual(0, item.Request.PayloadSize);
                    }

                    Response s = new Response(StatusCode.Content);
                    s.PayloadString = currentResourceContent[0];

                    if (Parallel && item.Request.UriPath == "/resource2") {
                        s.PayloadString = currentResourceContent[1];
                    }

                    if (Observe && item.Request.HasOption(OptionType.Observe)) {
                        s.Observe = 3;
                        observeExchange = item.Exchange;
                        s.Type = MessageType.NON;
                    }

                    item.Exchange.EndPoint.SendResponse(item.Exchange, s);
                    break;

                case MockQueueItem.QueueType.ClientSendResponse:
                    pump.Queue.Dequeue();

                    if (Parallel && item.Exchange.Request.UriPath == "/resource2") {
                        Assert.AreEqual(currentResourceContent[1], item.Response.PayloadString);
                        currentResourceContent[1] = currentResourceContent[0].Replace("get ", "get9");
                    }
                    else {
                        Assert.AreEqual(currentResourceContent[0], item.Response.PayloadString);
                        currentResourceContent[0] = currentResourceContent[0].Replace("get ", "get3");
                    }

                    success += 1;

                    //  For observe, send a second observe out
                    if (Observe && observeNum == 0) {
                        observeNum += 1;


                        s = new Response(StatusCode.Content) {
                            PayloadString = currentResourceContent[0],
                            Observe = 5,
                            Type = MessageType.NON
                        };

                        List<MockStack> stacks = pump.ServerStacks[MockMessagePump.ServerAddress];
                        stacks[0].MyEndPoint.SendResponse(observeExchange, s);

                    }

                    break;
                }
            }

            if (Parallel || Observe) {
                Assert.AreEqual(2, success);
            }
            else {
                Assert.AreEqual(1, success);
            }

            Assert.AreEqual(expectedClient, clientCount);
            Assert.AreEqual(expectedServer, serverCount);
        }
    }
}

