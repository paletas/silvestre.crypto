using System.Security.Cryptography;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public class PrivateKey
    {
        private readonly byte[] _key;

        internal PrivateKey(byte[] key)
        {
            this._key = key;
        }

        public ReadOnlySpan<byte> Key => _key;
    }

    public class ExtendedPrivateKey : PrivateKey
    {
        private readonly byte[] _chainCode;

        internal ExtendedPrivateKey(byte[] key, byte[] chainCode, uint depth)
            : base(key)
        {
            this._chainCode = chainCode;
            this.Depth = depth;
        }

        internal ExtendedPrivateKey(byte[] extendedKey, uint depth) 
            : base(extendedKey[KeySettings._KeyRange])
        {
            this._chainCode = extendedKey[KeySettings._ChainCodeRange];
            this.Depth = depth;
        }

        public ReadOnlySpan<byte> ChainCode => _chainCode;

        public uint Depth { get; }

        public ExtendedPrivateKey DeriveChild(uint index, bool hardened)
        {
            ReadOnlySpan<byte> privateKey = this.Key;
            ReadOnlySpan<byte> chainCode = this.ChainCode;

            ReadOnlySpan<byte> dataKey;

            if (hardened)
            {
                index += KeySettings.HARDENED_DERIVATION_INDEX;
                dataKey = privateKey;
            }
            else
            {
                dataKey = Cryptography.ECDSA.Secp256K1Manager.GetPublicKey(privateKey.ToArray(), true);
            }

            byte[] data = new byte[dataKey.Length + sizeof(int)];
            dataKey.CopyTo(data);
            Array.Copy(BitConverter.GetBytes(index), 0, data, data.Length, sizeof(int));

            byte[] derivedExtendedKey = HMACSHA512.HashData(chainCode, data);
            return new ExtendedPrivateKey(derivedExtendedKey, this.Depth + 1);
        }
    }
}
