using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace HashCheckSentinel.Core
{
    public sealed class LiveWatcher : IDisposable
    {
        private FileSystemWatcher _watcher;
        private readonly ConcurrentQueue<Tuple<string, string>> _eventQueue = new ConcurrentQueue<Tuple<string, string>>();
        private readonly ConcurrentDictionary<string, DateTime> _debounceMap = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private CancellationTokenSource _cts;
        private Task _workerTask;

        public event Action<string, string> FileActivityDetected;

        public bool IsRunning => _watcher != null && _watcher.EnableRaisingEvents;

        public void Start(string rootFolder)
        {
            Stop();

            if (!Directory.Exists(rootFolder)) return;

            _cts = new CancellationTokenSource();

            _watcher = new FileSystemWatcher(rootFolder)
            {
                InternalBufferSize = 65536, // Maximum 64 KB buffer
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Attributes | NotifyFilters.CreationTime
            };

            _watcher.Created += (s, e) => EnqueueEvent(e.FullPath, "Created");
            _watcher.Changed += (s, e) => EnqueueEvent(e.FullPath, "Modified");
            _watcher.Deleted += (s, e) => EnqueueEvent(e.FullPath, "Deleted");
            _watcher.Renamed += (s, e) =>
            {
                EnqueueEvent(e.OldFullPath, "Deleted");
                EnqueueEvent(e.FullPath, "Modified");
            };

            _watcher.EnableRaisingEvents = true;

            _workerTask = Task.Factory.StartNew(() => ProcessQueueLoop(_cts.Token), TaskCreationOptions.LongRunning);
        }

        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }

            if (_cts != null)
            {
                _cts.Cancel();
                _cts.Dispose();
                _cts = null;
            }
        }

        private void EnqueueEvent(string fullPath, string changeType)
        {
            if (ShouldIgnore(fullPath)) return;

            // Debounce rapid bursts for the same file within 350ms
            var now = DateTime.UtcNow;
            if (_debounceMap.TryGetValue(fullPath, out DateTime last) && (now - last).TotalMilliseconds < 350)
            {
                return;
            }
            _debounceMap[fullPath] = now;

            _eventQueue.Enqueue(Tuple.Create(fullPath, changeType));
        }

        private void ProcessQueueLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                while (_eventQueue.TryDequeue(out var ev))
                {
                    try
                    {
                        var handler = FileActivityDetected;
                        if (handler != null) handler(ev.Item1, ev.Item2);
                    }
                    catch { }
                }

                try
                {
                    if (token.WaitHandle.WaitOne(150)) break;
                }
                catch
                {
                    break;
                }
            }
        }

        public static bool ShouldIgnore(string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath)) return true;

            string name = Path.GetFileName(fullPath);
            if (name.StartsWith("~$")) return true; // Office lock files
            if (name.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase)) return true;
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) return true;

            // Ignore internal baseline directory
            if (fullPath.IndexOf(".sentinel-baseline", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (fullPath.IndexOf(".git", StringComparison.OrdinalIgnoreCase) >= 0) return true;

            string ext = Path.GetExtension(fullPath);
            if (ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase)) return true;
            if (ext.Equals(".lock", StringComparison.OrdinalIgnoreCase)) return true;
            if (ext.Equals(".swp", StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
