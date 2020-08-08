using System;
using System.Collections.Generic;
using System.Text;
using Com.AugustCellars.CoAP.Stack;

namespace Com.AugustCellars.CoAP.OSCOAP
{
    public class SecureBlockwiseData
    {
        /// <summary>
        /// Gets or sets the status of the blockwise transfer of the request,
        /// or null in case of a normal transfer,
        /// </summary>
        public BlockwiseStatus BlockStatus { get; set; }

        /// <summary>
        /// The response we are currently trying to blockwise transfer
        /// </summary>
        public Response OpenResponse { get; set; }


    }
}
