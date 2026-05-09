using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace IPScanner
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<ScanResult> _results = [];
        private CancellationTokenSource? _cts;
        private readonly DispatcherTimer _uiTimer;
        private readonly HashSet<string> _addedIpSet = [];
        private bool _isScanning = false;
        private int _aliveCount = 0;
        private int _deadCount = 0;
        private int _totalScanned = 0;
        private int _totalToScan = 0;

        private readonly ConcurrentDictionary<int, ScanResult> _pendingResults = [];
        private int _pendingAlive = 0;
        private int _pendingDead = 0;
        private int _pendingTotal = 0;

        public MainWindow()
        {
            InitializeComponent();
            LvResults.ItemsSource = _results;

            _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _uiTimer.Tick += FlushPendingResults;
        }

        // ─────────────────────────────────────────────
        // Scan Start
        // ─────────────────────────────────────────────
        private async void BtnScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;

            string baseIP = TxtBaseIP.Text.Trim();
            if (!int.TryParse(TxtStartIP.Text.Trim(), out int start) ||
                !int.TryParse(TxtEndIP.Text.Trim(), out int end) ||
                !int.TryParse(TxtTimeout.Text.Trim(), out int timeout))
            {
                MessageBox.Show("입력값을 확인해주세요.", "오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (start < 1 || start > 254 || end < 1 || end > 254 || start > end)
            {
                MessageBox.Show("범위는 1~254 사이여야 하며, 시작이 끝보다 작아야 합니다.", "오류",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (timeout < 50 || timeout > 5000)
            {
                MessageBox.Show("타임아웃은 50~5000ms 사이로 설정해주세요.", "오류",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _results.Clear();
            _addedIpSet.Clear();
            _pendingResults.Clear();
            _aliveCount = _deadCount = _totalScanned = _pendingAlive = _pendingDead = _pendingTotal = 0;
            _totalToScan = end - start + 1;

            UpdateStats();
            UpdateProgress(0);

            _cts = new CancellationTokenSource();
            SetScanningState(true);
            _uiTimer.Start();

            TxtFooter.Text = $"스캔 중: {baseIP}.{start} ~ {baseIP}.{end}  |  타임아웃: {timeout}ms";

            try
            {
                await RunScanAsync(baseIP, start, end, timeout, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                TxtStatus.Text = "스캔이 중지되었습니다.";
            }
            finally
            {
                _uiTimer.Stop();
                FlushPendingResults(null, null);
                SetScanningState(false);

                _cts.Dispose();
                _cts = null;

                if (_totalScanned >= _totalToScan)
                {
                    TxtStatus.Text = $"스캔 완료 — 총 {_totalToScan}개 중 {_aliveCount}개 응답";
                    TxtPercent.Text = "100%";
                    UpdateProgress(1.0);
                }

                TxtFooter.Text = $"스캔 완료: {_aliveCount}개 응답, {_deadCount}개 무응답";
            }
        }

        // ─────────────────────────────────────────────
        // Core Scan Logic
        // ─────────────────────────────────────────────
        private async Task RunScanAsync(string baseIP, int start, int end, int timeout, CancellationToken ct)
        {
            int maxParallel = Math.Min(50, end - start + 1);
            using var semaphore = new SemaphoreSlim(maxParallel, maxParallel);
            var tasks = new List<Task>();

            for (int i = start; i <= end; i++)
            {
                ct.ThrowIfCancellationRequested();
                string ip = $"{baseIP}.{i}";
                int currentOctet = i;

                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var result = await ScanSingleIPAsync(ip, timeout, ct);
                        result.LastOctet = currentOctet;
                        EnqueueResult(result);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, ct));
            }

            await Task.WhenAll(tasks);
        }

        // ─────────────────────────────────────────────
        // Single IP Scan: Ping + Hostname
        // ─────────────────────────────────────────────
        private static async Task<ScanResult> ScanSingleIPAsync(string ip, int timeout, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var result = new ScanResult { IPAddress = ip };

            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeout);

                if (reply.Status == IPStatus.Success)
                {
                    result.IsAlive = true;
                    result.StatusIcon = "● 응답";
                    result.PingTime = $"{reply.RoundtripTime} ms";
                    result.TTL = reply.Options?.Ttl.ToString() ?? "-";

                    try
                    {
                        var host = await Dns.GetHostEntryAsync(ip, ct);
                        result.Hostname = host.HostName;
                    }
                    catch
                    {
                        result.Hostname = "(호스트명 없음)";
                    }
                }
                else
                {
                    result.SetDead();
                }
            }
            catch
            {
                result.SetDead();
            }

            return result;
        }

        // ─────────────────────────────────────────────
        // Thread-safe result queuing
        // ─────────────────────────────────────────────
        private void EnqueueResult(ScanResult result)
        {
            _pendingResults[result.LastOctet] = result;
            Interlocked.Increment(ref _pendingTotal);

            if (result.IsAlive) Interlocked.Increment(ref _pendingAlive);
            else Interlocked.Increment(ref _pendingDead);
        }

        // ─────────────────────────────────────────────
        // Batched UI Update
        // ─────────────────────────────────────────────
        private void FlushPendingResults(object? sender, EventArgs? e)
        {
            var sorted = _pendingResults.Values.OrderBy(r => r.LastOctet).ToList();

            foreach (var result in sorted)
            {
                if (!result.IsAlive) continue;
                if (_addedIpSet.Contains(result.IPAddress)) continue;

                int insertAt = 0;
                while (insertAt < _results.Count && _results[insertAt].LastOctet < result.LastOctet)
                    insertAt++;

                _results.Insert(insertAt, result);
                _addedIpSet.Add(result.IPAddress);
            }

            _aliveCount = _pendingAlive;
            _deadCount = _pendingDead;
            _totalScanned = _pendingTotal;

            UpdateStats();

            double progress = _totalToScan > 0 ? (double)_totalScanned / _totalToScan : 0;
            UpdateProgress(Math.Min(progress, 1.0));

            TxtStatus.Text = $"스캔 중... ({_totalScanned}/{_totalToScan})";
            TxtPercent.Text = $"{(int)(progress * 100)}%";
        }

        private void UpdateStats()
        {
            TxtAliveCount.Text = _aliveCount.ToString();
            TxtDeadCount.Text = _deadCount.ToString();
            TxtTotalCount.Text = _totalScanned.ToString();
        }

        private void UpdateProgress(double ratio)
        {
            if (ProgressBar.Parent is Border parent && parent.ActualWidth > 0)
                ProgressBar.Width = parent.ActualWidth * ratio;
        }

        // ─────────────────────────────────────────────
        // Stop Button
        // ─────────────────────────────────────────────
        private void BtnStop_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

        // ─────────────────────────────────────────────
        // Export to Clipboard
        // ─────────────────────────────────────────────
        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_results.Count == 0)
            {
                MessageBox.Show("복사할 결과가 없습니다.", "알림", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine("IP 주소\t\t호스트명\t\t\t응답시간\tTTL");
            sb.AppendLine(new string('-', 80));

            foreach (var r in _results)
                sb.AppendLine($"{r.IPAddress,-18}{r.Hostname,-35}{r.PingTime,-12}{r.TTL}");

            Clipboard.SetText(sb.ToString());
            MessageBox.Show($"{_results.Count}개 항목이 클립보드에 복사되었습니다.", "완료",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        // ─────────────────────────────────────────────
        // UI State Toggle
        // ─────────────────────────────────────────────
        private void SetScanningState(bool scanning)
        {
            _isScanning = scanning;
            BtnScan.IsEnabled = !scanning;
            BtnStop.IsEnabled = scanning;
            TxtBaseIP.IsEnabled = !scanning;
            TxtStartIP.IsEnabled = !scanning;
            TxtEndIP.IsEnabled = !scanning;
            TxtTimeout.IsEnabled = !scanning;
        }
    }

    // ─────────────────────────────────────────────
    // Data Model
    // ─────────────────────────────────────────────
    public class ScanResult : INotifyPropertyChanged
    {
        public bool IsAlive { get; set; }
        public int LastOctet { get; set; }
        public string StatusIcon { get; set; } = string.Empty;
        public string IPAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string PingTime { get; set; } = string.Empty;
        public string TTL { get; set; } = string.Empty;

        public void SetDead()
        {
            IsAlive = false;
            StatusIcon = "○ 무응답";
            PingTime = "-";
            TTL = "-";
            Hostname = "-";
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}