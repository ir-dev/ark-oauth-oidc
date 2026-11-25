using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ark.Agents.TenantOnboarding.Llm
{
    /// <summary>
    /// ARK-LLM: <c>{ message, stream }</c> in, server-sent events out, from a small model on a very
    /// small server. The server does one inference at a time and reads every prompt from scratch,
    /// so the connector's first job is to be a considerate caller:
    ///
    /// * one call at a time from this process, with a pause after each;
    /// * a short prompt and a short answer, both capped, and a longer prompt refused here rather
    ///   than sent;
    /// * <c>enableTools: false</c>, always: otherwise the server adds its whole tool catalogue to
    ///   the prompt, and lets what somebody pasted into a conversation call those tools;
    /// * streamed, so that a wait is not cut off and repeated, and stopped as soon as the answer is
    ///   complete if the model goes on talking;
    /// * never retried. After a failure the server is left alone, for longer each time, and the
    ///   agent carries on without it;
    /// * a ceiling on calls per hour.
    /// </summary>
    internal sealed class ArkLlmModel : IArkAgentModel
    {
        // Per address, not per instance: two agents in one process share one small server.
        static readonly ConcurrentDictionary<string, Manners> Shared = new(StringComparer.OrdinalIgnoreCase);

        readonly ArkLlmOptions _o;
        readonly HttpClient _http;
        readonly Manners _manners;
        readonly Func<DateTime> _now;
        readonly Func<TimeSpan, CancellationToken, Task> _delay;

        public ArkLlmModel(ArkLlmOptions options, HttpClient http)
            : this(options, http, Shared.GetOrAdd(options.Url ?? "", _ => new Manners()), () => DateTime.UtcNow, Task.Delay) { }

        internal ArkLlmModel(ArkLlmOptions options, HttpClient http, Manners manners, Func<DateTime> now, Func<TimeSpan, CancellationToken, Task> delay)
        {
            _o = options;
            _http = http;
            _manners = manners;
            _now = now;
            _delay = delay;
        }

        public string Label => "ARK-LLM";

        public int? SmallPromptChars => Math.Max(1200, _o.MaxPromptChars);

        /// <summary>What the process knows about one server: whether it is busy, resting, or has been asked enough.</summary>
        internal sealed class Manners
        {
            public readonly SemaphoreSlim Turn = new(1, 1);
            public readonly Queue<DateTime> Calls = new();
            public DateTime LastFinished = DateTime.MinValue;
            public DateTime RestUntil = DateTime.MinValue;
            public int Failures;
        }

        public async Task<string> CompleteAsync(string instructions, string message, CancellationToken cancel)
        {
            var prompt = Neutralize(instructions.Length == 0 ? message : instructions + "\n\n" + message);
            if (prompt.Length > SmallPromptChars)
                throw new ArkAgentModelException($"that is more than ARK-LLM is asked to read at once ({prompt.Length:N0} characters, the limit is {SmallPromptChars:N0})");

            // Before queueing: somebody resting or over the hourly limit should not even wait.
            Refuse();
            if (!await _manners.Turn.WaitAsync(TimeSpan.FromSeconds(Math.Max(0, _o.MaxWaitSeconds)), cancel))
                throw new ArkAgentModelException("ARK-LLM is busy with somebody else's message");

            var handedOver = false;
            try
            {
                Refuse();
                var quiet = _manners.LastFinished.AddSeconds(Math.Max(0, _o.PauseSeconds)) - _now();
                if (quiet > TimeSpan.Zero) await _delay(quiet, cancel);
                lock (_manners.Calls) _manners.Calls.Enqueue(_now());

                using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                limit.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_o.TimeoutSeconds, 10, 600)));
                try
                {
                    var (text, response, reader) = await AskAsync(prompt, limit.Token);
                    _manners.Failures = 0;
                    if (response != null)
                    {
                        // The answer is here; the server is still writing its own records, and hanging
                        // up now would cancel them. It is heard out in the background, and the next
                        // call waits for that.
                        handedOver = true;
                        _ = HearOutAsync(response, reader!);
                    }
                    return text;
                }
                catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
                {
                    throw Rest(null, $"ARK-LLM did not finish within {_o.TimeoutSeconds} seconds");
                }
                catch (HttpRequestException ex)
                {
                    throw Rest(null, $"ARK-LLM could not be reached: {ex.Message}");
                }
                catch (IOException ex)
                {
                    throw Rest(null, $"the connection to ARK-LLM broke off: {ex.Message}");
                }
            }
            finally
            {
                if (!handedOver) Leave();
            }
        }

        void Leave()
        {
            _manners.LastFinished = _now();
            _manners.Turn.Release();
        }

        /// <summary>Reasons not to call at all. None of them touches the network.</summary>
        void Refuse()
        {
            var now = _now();
            if (now < _manners.RestUntil)
                throw new ArkAgentModelException($"ARK-LLM is being left alone for another {Math.Ceiling((_manners.RestUntil - now).TotalSeconds):0} seconds after a problem");
            lock (_manners.Calls)
            {
                while (_manners.Calls.Count > 0 && now - _manners.Calls.Peek() > TimeSpan.FromHours(1)) _manners.Calls.Dequeue();
                if (_manners.Calls.Count >= Math.Max(1, _o.MaxCallsPerHour))
                    throw new ArkAgentModelException($"ARK-LLM has been asked {_manners.Calls.Count} times in the last hour, which is the limit set for it");
            }
        }

        /// <summary>A problem: the server is left alone, 30 seconds the first time, twice as long each time after, ten minutes at most.</summary>
        ArkAgentModelException Rest(TimeSpan? asked, string why)
        {
            _manners.Failures++;
            var rest = TimeSpan.FromSeconds(Math.Min(600, 30 * Math.Pow(2, Math.Min(_manners.Failures, 6) - 1)));
            if (asked is { } wanted && wanted > rest) rest = wanted < TimeSpan.FromHours(1) ? wanted : TimeSpan.FromHours(1);
            _manners.RestUntil = _now() + rest;
            return new ArkAgentModelException(why);
        }

        async Task<(string Text, HttpResponseMessage? Open, StreamReader? Reader)> AskAsync(string prompt, CancellationToken cancel)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, _o.Url)
            {
                Content = AgentModelFactory.Json(new JsonObject
                {
                    ["message"] = prompt,
                    ["stream"] = true,
                    ["enableTools"] = false,
                    ["maxTokens"] = Math.Clamp(_o.MaxAnswerTokens, 16, 1024),
                    ["temperature"] = 0.1
                })
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            request.Headers.TryAddWithoutValidation(string.IsNullOrWhiteSpace(_o.ApiKeyHeader) ? "X-API-Key" : _o.ApiKeyHeader.Trim(), _o.ApiKey);

            var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancel);
            var keep = false;
            try
            {
                if (!response.IsSuccessStatusCode) throw await RefusedAsync(response, cancel);

                if (response.Content.Headers.ContentType?.MediaType != "text/event-stream")
                {
                    // Not streamed after all: one JSON body with the same content.
                    var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancel));
                    return (body?["response"]?.GetValue<string>() ?? throw Rest(null, "ARK-LLM answered without any text"), null, null);
                }

                var reader = new StreamReader(await response.Content.ReadAsStreamAsync(cancel), Encoding.UTF8);
                var (text, finished) = await ReadAsync(reader, cancel);
                keep = finished;
                return (text, finished ? response : null, finished ? reader : null);
            }
            catch (JsonException)
            {
                throw Rest(null, "ARK-LLM answered with something that is not JSON");
            }
            finally
            {
                // Disposing an unfinished stream hangs up, and the server stops generating.
                if (!keep) response.Dispose();
            }
        }

        async Task<ArkAgentModelException> RefusedAsync(HttpResponseMessage response, CancellationToken cancel)
        {
            var status = (int)response.StatusCode;
            var after = response.Headers.RetryAfter?.Delta
                        ?? (response.Headers.RetryAfter?.Date is { } at ? at.UtcDateTime - _now() : (TimeSpan?)null);
            string said = "";
            try { said = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancel))?["error"]?.GetValue<string>() ?? ""; }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException) { }
            return response.StatusCode switch
            {
                // Asking again with the same key changes nothing.
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => Rest(TimeSpan.FromMinutes(10), "ARK-LLM did not accept the API key"),
                HttpStatusCode.ServiceUnavailable => Rest(after, said.Length > 0 ? $"ARK-LLM is not ready: {said}" : "ARK-LLM is not ready"),
                HttpStatusCode.TooManyRequests => Rest(after, "ARK-LLM asked for fewer requests"),
                _ => Rest(after, $"ARK-LLM answered {status}{(said.Length > 0 ? ": " + AgentModelFactory.Short(said) : "")}")
            };
        }

        /// <summary>
        /// The events up to the answer's end. <c>Finished</c>: the server said so itself. False: the
        /// answer is complete, the model is not, and the stream is to be dropped.
        /// </summary>
        async Task<(string Text, bool Finished)> ReadAsync(StreamReader reader, CancellationToken cancel)
        {
            var text = new StringBuilder();
            var complete = -1;      // characters, once the JSON object in the answer is closed
            string? name = null;
            while (await reader.ReadLineAsync(cancel) is { } line)
            {
                if (line.Length == 0) { name = null; continue; }
                if (line[0] == ':') continue;                       // keep-alive
                if (line.StartsWith("event:", StringComparison.Ordinal)) { name = line[6..].Trim(); continue; }
                if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;

                switch (name)
                {
                    case "token":
                        text.Append(JsonNode.Parse(line[5..])?["text"]?.GetValue<string>() ?? "");
                        if (complete < 0) complete = ClosedAt(text);
                        // A little room to end by itself, which the server records as a normal call.
                        else if (text.Length - complete > 60) return (text.ToString(0, complete), false);
                        break;
                    case "done":
                        var answer = JsonNode.Parse(line[5..])?["response"]?.GetValue<string>();
                        return (string.IsNullOrEmpty(answer) ? text.ToString() : answer, true);
                    case "error":
                        throw Rest(null, "ARK-LLM reported a problem: " + AgentModelFactory.Short(JsonNode.Parse(line[5..])?["message"]?.GetValue<string>() ?? "unknown"));
                }
            }
            if (complete > 0) return (text.ToString(0, complete), false);
            throw Rest(null, "ARK-LLM stopped before it had finished");
        }

        /// <summary>Where the first JSON object in the text ends, or -1. Text that is not JSON never ends this way.</summary>
        static int ClosedAt(StringBuilder text)
        {
            int depth = 0, i = 0;
            var inString = false;
            while (i < text.Length && text[i] != '{') if (!(char.IsWhiteSpace(text[i]) || text[i] == '`' || char.IsLetter(text[i])) || i++ > 12) return -1;
            for (; i < text.Length; i++)
            {
                var c = text[i];
                if (inString)
                {
                    if (c == '\\') i++;
                    else if (c == '"') inString = false;
                }
                else if (c == '"') inString = true;
                else if (c == '{') depth++;
                else if (c == '}' && --depth == 0) return i + 1;
            }
            return -1;
        }

        async Task HearOutAsync(HttpResponseMessage response, StreamReader reader)
        {
            try
            {
                using var patience = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                while (await reader.ReadLineAsync(patience.Token) != null) { }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or HttpRequestException or ObjectDisposedException) { }
            finally
            {
                response.Dispose();
                Leave();
            }
        }

        static readonly Regex ControlToken = new(@"<(?=/?(?:start_of_turn|end_of_turn|bos|eos|pad|unk|mask)>|\|)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>The model's own turn markers, written by somebody in a message, would end the turn early or start another speaker's.</summary>
        internal static string Neutralize(string text) => ControlToken.Replace(text, "< ");
    }
}
