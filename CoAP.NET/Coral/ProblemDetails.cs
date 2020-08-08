using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Text;
using Com.AugustCellars.CoAP.Util;

namespace Com.AugustCellars.CoAP.Coral
{
    public class ProblemDetails : CoralDocument
    {
        public ProblemDetails()
        {}

        public ProblemDetails(string problemType)
        {
            AddProblemType(problemType);
        }

        public ProblemDetails(string problemType, string detail)
        {
            AddProblemType(problemType);
            AddProblemDetails(detail);
        }

        public void AddProblemDetails(string detail)
        {
            Add(new CoralLink("http://example.org/vocabulary/problem-details#detail", detail));

        }
        public void AddProblemType(string problemType)
        {
            Add(new CoralLink("http://example.org/vocabulary/problem-details#type", new Cori( problemType)));

        }

        public void AddExceptionDetails(Exception e)
        {
            Add(new CoralLink("http://example.org/vocabulary/problem-details#debug", e.ToString()));
        }
    }
}
