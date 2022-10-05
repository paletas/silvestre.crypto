using System.Security.Cryptography;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public class PublicKey
    {
        private readonly byte[] _key;

        internal PublicKey(byte[] key)
        {
            this._key = key;
        }

        internal PublicKey(PrivateKey privateKey)
        {
            this._key = Cryptography.ECDSA.Secp256K1Manager.GetPublicKey(privateKey.Key.ToArray(), true);
        }

        public ReadOnlySpan<byte> Key => _key;
    }

    public class ExtendedPublicKey : PublicKey
    {
        private readonly byte[] _chainCode;

        internal ExtendedPublicKey(ExtendedPrivateKey privateKey)
            : base(privateKey)
        {
            this._chainCode = privateKey.ChainCode.ToArray();
        }

        internal ExtendedPublicKey(byte[] key, byte[] chainCode)
            : base(key)
        {
            this._chainCode = chainCode;
        }

        internal ExtendedPublicKey(byte[] extendedKey)
            : base(extendedKey[KeySettings._KeyRange])
        {
            this._chainCode = extendedKey[KeySettings._ChainCodeRange];
        }

        public byte[] ChainCode => _chainCode;

        public ExtendedPublicKey DeriveChild(uint index)
        {
            ReadOnlySpan<byte> publicKey = this.Key;
            ReadOnlySpan<byte> chainCode = this.ChainCode;

            if (index >= KeySettings.HARDENED_DERIVATION_INDEX)
                throw new ArgumentOutOfRangeException($"index should be between 0 and {KeySettings.HARDENED_DERIVATION_INDEX}");

            byte[] data = new byte[publicKey.Length + sizeof(int)];
            publicKey.CopyTo(data);
            Array.Copy(BitConverter.GetBytes(index), 0, data, data.Length, sizeof(int));

            byte[] derivedExtendedKey = HMACSHA512.HashData(chainCode, data);
            return new ExtendedPublicKey(derivedExtendedKey);
        }
    }
}
