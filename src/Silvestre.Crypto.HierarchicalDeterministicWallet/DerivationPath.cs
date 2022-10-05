using System.Text.RegularExpressions;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public static class DerivationPath
    {
        private static readonly Regex _DerivationPathRegex = new(@"m(?<Purpose>\/([0-9]*)'?)(?<CoinType>\/([0-9]*)'?)(?<Account>\/([0-9]*)'?)(?<Change>\/([0-9]*)'?)(?<Index>\/([0-9]*)'?)", RegexOptions.Compiled);

        public static (DerivationLevel Purpose, DerivationLevel CoinType, DerivationLevel Account, DerivationLevel Change, DerivationLevel Index) Parse(string path)
        {
            Match regexMatch = _DerivationPathRegex.Match(path);
            if (regexMatch.Success == false)
                throw new ArgumentException("invalid path", nameof(path));

            DerivationLevel purpose = ParseLevel(regexMatch.Groups["Purpose"].Captures[0].Value);
            DerivationLevel coinType = ParseLevel(regexMatch.Groups["CoinType"].Captures[0].Value);
            DerivationLevel account = ParseLevel(regexMatch.Groups["Account"].Captures[0].Value);
            DerivationLevel change = ParseLevel(regexMatch.Groups["Change"].Captures[0].Value);
            DerivationLevel index = ParseLevel(regexMatch.Groups["Index"].Captures[0].Value);

            return new (purpose, coinType, account, change, index);
        }

        public static ExtendedPrivateKey DerivePrivateKey(this ExtendedPrivateKey privateKey, string path)
        {
            var (purpose, coinType, account, change, index) = Parse(path);

            if (privateKey.Depth == 0)
                privateKey = privateKey.DeriveChild(purpose.Value, purpose.Hardened);

            if (privateKey.Depth == 1)
                privateKey = privateKey.DeriveChild(coinType.Value, coinType.Hardened);

            if (privateKey.Depth == 2)
                privateKey = privateKey.DeriveChild(account.Value, account.Hardened);

            if (privateKey.Depth == 3)
                privateKey = privateKey.DeriveChild(change.Value, change.Hardened);

            if (privateKey.Depth == 4)
                privateKey = privateKey.DeriveChild(index.Value, index.Hardened);
            else
                throw new NotSupportedException();

            return privateKey;
        }

        private static DerivationLevel ParseLevel(string levelString)
        {
            bool isHardened = levelString[^1] == '\'';
            uint level = uint.Parse(isHardened ? levelString[..^1] : levelString);
            return new(level, isHardened);
        }
    }

    public record DerivationLevel(uint Value, bool Hardened);
}
