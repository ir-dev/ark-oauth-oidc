namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// One password attempt at a time for one login id.
    ///
    /// The lockout is read before the password is verified and counted after it. Between the two is
    /// a hash of tens of milliseconds, and a burst of attempts sent together all read the count as it
    /// stood before any of them: a limit of ten let two hundred through. Attempts at the same account
    /// take turns here, and each looks at the count again when its turn comes, so the limit holds
    /// for a parallel guesser as it does for a patient one. Different accounts never wait for each
    /// other.
    ///
    /// Per process: with several instances the limit is reached per instance in the same instant,
    /// and by all of them the instant after, because the count itself is in the database.
    /// </summary>
    internal static class ArkSignInQueue
    {
        private sealed class Turn
        {
            public readonly SemaphoreSlim Gate = new(1, 1);
            public int Wanted;
        }

        // Only logins with an attempt in flight are in here.
        private static readonly Dictionary<string, Turn> Turns = new(StringComparer.Ordinal);

        public static async Task<IDisposable> EnterAsync(string login)
        {
            Turn turn;
            lock (Turns)
            {
                if (!Turns.TryGetValue(login, out turn!)) Turns[login] = turn = new Turn();
                turn.Wanted++;
            }
            await turn.Gate.WaitAsync();
            return new Place(login, turn);
        }

        private sealed class Place : IDisposable
        {
            private readonly string _login;
            private Turn? _turn;

            public Place(string login, Turn turn)
            {
                _login = login;
                _turn = turn;
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _turn, null) is not { } turn) return;
                lock (Turns)
                    if (--turn.Wanted == 0) Turns.Remove(_login);
                turn.Gate.Release();
            }
        }
    }

    /// <summary>
    /// The account is locked: reached when the count passed the limit while this attempt waited its
    /// turn. The password was not looked at, so nothing is counted and nothing is learned.
    /// </summary>
    public class ArkAccountLockedException : ApplicationException
    {
        public ArkAccountLockedException(int minutes) : base($"Too many failed attempts. Try again in {minutes} minutes.")
        {
        }
    }
}
