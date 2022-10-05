using System;
using System.Text;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    internal static class KeySettings
    {
        public const string BITCOIN_KEY = "Bitcoin seed";
        public const int KEY_SIZE = 64;
        public const int HARDENED_DERIVATION_INDEX = 2147483647;

        public static byte[] BITCOIN_KEY_BYTES = Encoding.UTF8.GetBytes(KeySettings.BITCOIN_KEY);
        public static Range _KeyRange = 0..(KEY_SIZE / 2);
        public static Range _ChainCodeRange = (KEY_SIZE / 2)..KEY_SIZE;
    }
}
