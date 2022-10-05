using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    internal static class ByteArrayExtensions
    {
        public static byte[] Combine(params byte[][] byteArr)
        {
            byte[] newArr = new byte[byteArr.Sum(arr => arr.Length)];

            int index = 0;
            foreach(var arr in byteArr)
            {
                Array.Copy(arr, 0, newArr, index, newArr.Length);
                index += arr.Length;
            }

            return newArr;
        }
    }
}
