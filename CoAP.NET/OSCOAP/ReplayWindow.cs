using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Com.AugustCellars.CoAP.OSCOAP
{
        /// <summary>
        /// Class implementation used for doing checking if a message is being replayed at us.
        /// </summary>
        public class ReplayWindow
        {
            private BitArray _hits;
            public long BaseValue { get; private set; }

            /// <summary>
            /// create a replay window and initialize where the floating window is.
            /// </summary>
            /// <param name="baseValue">Start value to check for hits</param>
            /// <param name="arraySize">Size of the replay window</param>
            public ReplayWindow(int baseValue, int arraySize)
            {
                BaseValue = baseValue;
                _hits = new BitArray(arraySize);
            }

            /// <summary>
            /// Check if the value is in the replay window and if it has been set.
            /// </summary>
            /// <param name="index">value to check</param>
            /// <returns>true if should treat as replay</returns>
            public bool HitTest(long index)
            {

                index -= BaseValue;
                if (index < 0) return true;
                if (index >= _hits.Length) return false;
                return _hits.Get((int)index);
            }

            /// <summary>
            /// Set a value has having been seen.
            /// </summary>
            /// <param name="index">value that was seen</param>
            /// <returns>true if the zone was shifted</returns>
            public bool SetHit(long index)
            {
                bool returnValue = false;
                index -= BaseValue;
                if (index < 0) return false;
                if (index >= _hits.Length) {
                    returnValue = true;
                    if (index < _hits.Length * 3 / 2) {
                        int v = _hits.Length / 2;
                        BaseValue += v;
                        BitArray t = new BitArray(_hits.Length);
                        for (int i = 0; i < v; i++) {
                            t[i] = _hits[i + v];
                        }

                        _hits = t;
                        index -= v;
                    }
                    else {
                        BaseValue = index;
                        _hits.SetAll(false);
                        index = 0;
                    }
                }
                _hits.Set((int)index, true);
                return returnValue;
            }
        }
    }
