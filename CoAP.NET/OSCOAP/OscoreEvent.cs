using System;
using System.Collections.Generic;
using System.Text;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.OSCOAP
{
    public class OscoreEvent
    {
        public enum EventCode
        {
            UnknownGroupIdentifier = 1,
            UnknownKeyIdentifier = 2,
            UnknownPublicKey = 3,
            PivExhaustion = 4,
            HitZoneMoved = 5,
            SenderIvSave = 6
        }

        public EventCode Code { get; }
        public byte[] GroupIdentifier { get; }
        public byte[] KeyIdentifier { get; }
        public SecurityContext SecurityContext { get; set; }
        public IRecipientEntityContext RecipientContext { get; set; }
        public ISenderEntityContext SenderContext { get; set; }

        // If a different status code is to be returned - put it here.
        public StatusCode StatusCode { get; set; }

        public OscoreEvent(EventCode code, byte[] groupIdentifier, byte[] keyIdentifier, SecurityContext context, IRecipientEntityContext recipient)
        {
            Code = code;
            GroupIdentifier = groupIdentifier;
            KeyIdentifier = keyIdentifier;
            SecurityContext = context;
            RecipientContext = recipient;
        }

        public OscoreEvent(EventCode code, byte[] groupIdentifier, byte[] keyIdentifier, SecurityContext context, ISenderEntityContext sender)
        {
            Code = code;
            GroupIdentifier = groupIdentifier;
            KeyIdentifier = keyIdentifier;
            SecurityContext = context;
            SenderContext = sender;
        }

    }
}
