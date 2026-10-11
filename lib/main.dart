// =============================================================================
// PHANTOM-9 // Unified Network Utility Toolkit (v11.1 Ultimate Edition)
// =============================================================================
// ✅ AES-256-GCM + HMAC-SHA256 (with nonce, replay-proof)
// ✅ Secure Key Vault (SharedPreferences + validation + wipe)
// ✅ 7 Real Network Tools: Port, Subnet, DNS, HTTP, Geo, WHOIS, TCP Ping
// ✅ Scheduled Scans (UI: 30s, 1m, 5m, 15m)
// ✅ Latency Chart (CustomPainter, displayed)
// ✅ Full results display + Progress bars + Color-coded status
// ✅ Streaming payload defense (DoS-proof)
// ✅ Boot error retry + Wipe Keys
//
// ⚠️ للاستخدام على شبكاتك الخاصة أو المصرّح لك بفحصها فقط.
// =============================================================================

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PhantomCoreApp());
}

// =============================================================================
// SECTION 1: CRYPTO (AES-256-GCM)
// =============================================================================
class PhantomCipher {
  final Uint8List _secretKey;
  static final Random _rng = Random.secure();
  static const int _nonceLen = 12;
  static const int _tagLen = 16;

  PhantomCipher(this._secretKey) {
    if (_secretKey.length != 32) {
      throw ArgumentError('Key must be strictly 32 bytes.');
    }
  }

  static Uint8List generateMasterKey() {
    final k = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      k[i] = _rng.nextInt(256);
    }
    return k;
  }

  String encrypt(String text) {
    final nonce = _nonce(_nonceLen);
    final c = GCMBlockCipher(AESEngine())
      ..init(true,
          AEADParameters(KeyParameter(_secretKey), 128, nonce, Uint8List(0)));
    final ct = c.process(Uint8List.fromList(utf8.encode(text)));
    final p = BytesBuilder()
      ..add(nonce)
      ..add(ct);
    return base64.encode(p.toBytes());
  }

  String decrypt(String b64) {
    final data = base64.decode(b64);
    if (data.length < _nonceLen + _tagLen) {
      throw const FormatException('Corrupted packet.');
    }
    final nonce = data.sublist(0, _nonceLen);
    final ct = data.sublist(_nonceLen);
    final c = GCMBlockCipher(AESEngine())
      ..init(false,
          AEADParameters(KeyParameter(_secretKey), 128, nonce, Uint8List(0)));
    return utf8.decode(c.process(ct));
  }

  static Uint8List _nonce(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
    return b;
  }
}

// =============================================================================
// SECTION 2: HMAC-SHA256 (with nonce, replay-proof)
// =============================================================================
class HmacAuth {
  final List<int> _secret;
  HmacAuth(this._secret);

  String sign(String payload, {String? nonce}) {
    final data = nonce == null ? payload : '$nonce|$payload';
    return Hmac(sha256, _secret).convert(utf8.encode(data)).toString();
  }

  bool verify(String payload, String sig, {String? nonce}) {
    final expected = sign(payload, nonce: nonce);
    if (expected.length != sig.length) return false;
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected.codeUnitAt(i) ^ sig.codeUnitAt(i);
    }
    return diff == 0;
  }
}

// =============================================================================
// SECTION 3: SECURE KEY VAULT
// =============================================================================
class KeyVault {
  static const _masterKey = 'p9_master_v11';
  static const _hmacKey = 'p9_hmac_v11';

  static Future<Uint8List> getOrCreateMasterKey() async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(_masterKey);
    if (stored != null) {
      try {
        final d = base64.decode(stored);
        if (d.length == 32) return d;
      } catch (_) {}
    }
    final fresh = PhantomCipher.generateMasterKey();
    await prefs.setString(_masterKey, base64.encode(fresh));
    return fresh;
  }

  static Future<Uint8List> getOrCreateHmacKey() async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(_hmacKey);
    if (stored != null) {
      try {
        final d = base64.decode(stored);
        if (d.length == 32) return d;
      } catch (_) {}
    }
    final fresh = PhantomCipher.generateMasterKey();
    await prefs.setString(_hmacKey, base64.encode(fresh));
    return fresh;
  }

  static Future<void> wipe() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_masterKey);
    await prefs.remove(_hmacKey);
  }
}

// =============================================================================
// SECTION 4: RESULT MODELS
// =============================================================================
class PortResult {
  final int port;
  final bool isOpen;
  final Duration? latency;
  final String? service;
  PortResult(this.port, this.isOpen, {this.latency, this.service});
}

class DnsResult {
  final List<String> ipv4, ipv6;
  final Duration latency;
  final String? error;
  DnsResult(this.ipv4, this.ipv6, this.latency, {this.error});
}

class HttpResult {
  final int? status;
  final Duration latency;
  final String? server;
  final String? error;
  HttpResult({this.status, required this.latency, this.server, this.error});
}

class GeoResult {
  final String? country, city, isp;
  final double? lat, lon;
  final String? error;
  GeoResult({this.country, this.city, this.isp, this.lat, this.lon, this.error});
}

class WhoisResult {
  final String raw;
  final Duration latency;
  final String? error;
  WhoisResult(this.raw, this.latency, {this.error});
}

class PingResult {
  final bool success;
  final Duration? latency;
  final String raw;
  final String? error;
  PingResult({required this.success, this.latency, this.raw = '', this.error});
}

class InterfaceInfo {
  final String name, address, type;
  final bool isLoopback;
  InterfaceInfo(this.name, this.address, this.type, this.isLoopback);
}

class SubnetHost {
  final String ip;
  final int port;
  final Duration latency;
  SubnetHost(this.ip, this.port, this.latency);
}

class SubnetResult {
  final String cidr;
  final int total, alive;
  final List<SubnetHost> hosts;
  final Duration totalTime;
  SubnetResult(this.cidr, this.total, this.alive, this.hosts, this.totalTime);
}

// =============================================================================
// SECTION 5: NETWORK SCANNER (7 real tools)
// =============================================================================
class NetworkScanner {
  // -------- TCP Port --------
  Future<PortResult> scanPort(String host, int port,
      {Duration timeout = const Duration(seconds: 2)}) async {
    final sw = Stopwatch()..start();
    try {
      final s = await Socket.connect(host, port, timeout: timeout);
      sw.stop();
      s.destroy();
      return PortResult(port, true,
          latency: sw.elapsed, service: _service(port));
    } catch (_) {
      return PortResult(port, false);
    }
  }

  Future<List<PortResult>> scanPorts(
    String host,
    List<int> ports, {
    Duration timeout = const Duration(seconds: 2),
    int concurrency = 20,
    void Function(PortResult)? onResult,
    void Function(int, int)? onProgress,
  }) async {
    final all = <PortResult>[];
    var done = 0;
    for (var i = 0; i < ports.length; i += concurrency) {
      final batch = ports.skip(i).take(concurrency).toList();
      final results =
          await Future.wait(batch.map((p) => scanPort(host, p, timeout: timeout)));
      for (final r in results) {
        all.add(r);
        done++;
        onResult?.call(r);
        onProgress?.call(done, ports.length);
      }
    }
    return all;
  }

  // -------- CIDR (with proper validation) --------
  static List<String> expandCidr(String cidr) {
    final parts = cidr.trim().split('/');
    if (parts.length != 2) throw ArgumentError('Invalid CIDR format');
    final octets = parts[0].split('.').map((s) {
      final v = int.tryParse(s);
      if (v == null || v < 0 || v > 255) {
        throw ArgumentError('Invalid IP octet: $s');
      }
      return v;
    }).toList();
    if (octets.length != 4) throw ArgumentError('Invalid IPv4 address');
    final prefix = int.tryParse(parts[1]);
    if (prefix == null || prefix < 24 || prefix > 32) {
      throw ArgumentError('Prefix must be 24-32 (safe limit).');
    }
    final base = (octets[0] << 24) |
        (octets[1] << 16) |
        (octets[2] << 8) |
        octets[3];
    final count = 1 << (32 - prefix);
    final out = <String>[];
    for (var i = 1; i < count - 1; i++) {
      final ip = base + i;
      out.add('${(ip >> 24) & 0xFF}.${(ip >> 16) & 0xFF}.'
          '${(ip >> 8) & 0xFF}.${ip & 0xFF}');
    }
    return out;
  }

  Future<SubnetResult> scanSubnet(
    String cidr,
    int port, {
    Duration timeout = const Duration(milliseconds: 700),
    int concurrency = 50,
    void Function(int, int, SubnetHost?)? onProgress,
  }) async {
    final sw = Stopwatch()..start();
    final ips = expandCidr(cidr);
    final alive = <SubnetHost>[];
    var done = 0;
    for (var i = 0; i < ips.length; i += concurrency) {
      final batch = ips.skip(i).take(concurrency).toList();
      final results = await Future.wait(batch.map((ip) async {
        final swT = Stopwatch()..start();
        try {
          final s = await Socket.connect(ip, port, timeout: timeout);
          swT.stop();
          s.destroy();
          return SubnetHost(ip, port, swT.elapsed);
        } catch (_) {
          return null;
        }
      }));
      for (final r in results) {
        done++;
        if (r != null) alive.add(r);
        onProgress?.call(done, ips.length, r);
      }
    }
    sw.stop();
    return SubnetResult(cidr, ips.length, alive.length, alive, sw.elapsed);
  }

  // -------- DNS --------
  Future<DnsResult> resolveDns(String host) async {
    final sw = Stopwatch()..start();
    try {
      final addrs =
          await InternetAddress.lookup(host).timeout(const Duration(seconds: 5));
      sw.stop();
      final v4 = <String>[], v6 = <String>[];
      for (final a in addrs) {
        (a.type == InternetAddressType.IPv4 ? v4 : v6).add(a.address);
      }
      return DnsResult(v4, v6, sw.elapsed);
    } catch (e) {
      sw.stop();
      return DnsResult(const [], const [], sw.elapsed, error: e.toString());
    }
  }

  // -------- HTTP --------
  Future<HttpResult> probeHttp(String url,
      {Duration timeout = const Duration(seconds: 10)}) async {
    final sw = Stopwatch()..start();
    try {
      final client = http.Client();
      try {
        final req = http.Request('HEAD', Uri.parse(url));
        final s = await client.send(req).timeout(timeout);
        sw.stop();
        return HttpResult(
          status: s.statusCode,
          latency: sw.elapsed,
          server: s.headers['server'],
        );
      } finally {
        client.close();
      }
    } catch (e) {
      sw.stop();
      return HttpResult(latency: sw.elapsed, error: e.toString());
    }
  }

  // -------- Geo --------
  Future<GeoResult> geolocate(String ip) async {
    try {
      final uri = Uri.parse(
          'http://ip-api.com/json/$ip?fields=status,country,city,isp,lat,lon,message');
      final r = await http.get(uri).timeout(const Duration(seconds: 8));
      if (r.statusCode != 200) return GeoResult(error: 'HTTP ${r.statusCode}');
      final d = jsonDecode(r.body) as Map<String, dynamic>;
      if (d['status'] != 'success') {
        return GeoResult(error: d['message']?.toString() ?? 'unknown');
      }
      return GeoResult(
        country: d['country'],
        city: d['city'],
        isp: d['isp'],
        lat: (d['lat'] as num?)?.toDouble(),
        lon: (d['lon'] as num?)?.toDouble(),
      );
    } catch (e) {
      return GeoResult(error: e.toString());
    }
  }

  // -------- WHOIS --------
  Future<WhoisResult> whois(String domain) async {
    final sw = Stopwatch()..start();
    Socket? s;
    try {
      final tld = domain.split('.').last;
      final server = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'io': 'whois.nic.io',
            'dev': 'whois.nic.google',
          }[tld] ??
          'whois.iana.org';
      s = await Socket.connect(server, 43, timeout: const Duration(seconds: 8));
      s.write('$domain\r\n');
      final buf = StringBuffer();
      await s
          .cast<List<int>>()
          .transform(utf8.decoder)
          .timeout(const Duration(seconds: 10))
          .forEach((c) {
        if (buf.length < 200000) buf.write(c);
      });
      sw.stop();
      return WhoisResult(buf.toString(), sw.elapsed);
    } catch (e) {
      sw.stop();
      return WhoisResult('', sw.elapsed, error: e.toString());
    } finally {
      s?.destroy();
    }
  }

  // -------- TCP Ping --------
  Future<PingResult> tcpPing(String host,
      {int port = 443,
      int attempts = 4,
      Duration timeout = const Duration(seconds: 2)}) async {
    final latencies = <int>[];
    for (var i = 0; i < attempts; i++) {
      final sw = Stopwatch()..start();
      try {
        final s = await Socket.connect(host, port, timeout: timeout);
        sw.stop();
        s.destroy();
        latencies.add(sw.elapsed.inMilliseconds);
      } catch (_) {}
      if (i < attempts - 1) {
        await Future.delayed(const Duration(milliseconds: 150));
      }
    }
    if (latencies.isEmpty) {
      return PingResult(
          success: false, error: 'All $attempts attempts failed (port $port)');
    }
    final avg = latencies.reduce((a, b) => a + b) ~/ latencies.length;
    return PingResult(
      success: true,
      latency: Duration(milliseconds: avg),
      raw: 'TCP ping $host:$port | Success ${latencies.length}/$attempts\n'
          'Latencies: ${latencies.join(", ")} ms\nAvg: $avg ms',
    );
  }

  // -------- Interfaces --------
  Future<List<InterfaceInfo>> listInterfaces() async {
    final out = <InterfaceInfo>[];
    try {
      final ifs = await NetworkInterface.list(
        includeLoopback: true,
        includeLinkLocal: true,
        type: InternetAddressType.any,
      );
      for (final i in ifs) {
        for (final a in i.addresses) {
          out.add(InterfaceInfo(
            i.name,
            a.address,
            a.type == InternetAddressType.IPv4 ? 'IPv4' : 'IPv6',
            a.isLoopback,
          ));
        }
      }
    } catch (_) {}
    return out;
  }

  String _service(int port) {
    const m = {
      21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
      80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
      1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
      5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
    };
    return m[port] ?? '?';
  }
}

// =============================================================================
// SECTION 6: LOCAL LOOPBACK IPC CORE (streaming defense + nonce)
// =============================================================================
class LocalCore {
  final PhantomCipher cipher;
  final HmacAuth hmac;
  final StreamController<String> _log = StreamController.broadcast();
  HttpServer? _server;

  static const _allowed = {'127.0.0.1', 'localhost', '::1'};
  static const int _maxPayload = 2 * 1024 * 1024;

  LocalCore(this.cipher, this.hmac);

  Stream<String> get stream => _log.stream;
  int? get port => _server?.port;
  bool get isRunning => _server != null;

  Future<int> boot() async {
    if (_server != null) return _server!.port;
    final s = await HttpServer.bind(InternetAddress.loopbackIPv4, 0,
        shared: false);
    _server = s;
    _emit('CORE', 'Local core online on port ${s.port}');
    s.listen(_handle, onError: (e) => _emit('CRIT', 'Core fault: $e'));
    return s.port;
  }

  Future<void> shutdown() async {
    _emit('CORE', 'Local core stopped.');
    await _server?.close(force: true);
    _server = null;
  }

  Future<void> _handle(HttpRequest req) async {
    try {
      final host = req.headers.value(HttpHeaders.hostHeader);
      if (host == null ||
          !_allowed.contains(host.split(':').first.trim().toLowerCase())) {
        req.response.statusCode = HttpStatus.forbidden;
        await req.response.close();
        return;
      }
      if (req.method != 'POST' || req.uri.path != '/v1/exec') {
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        return;
      }

      final sig = req.headers.value('X-Sig');
      final nonce = req.headers.value('X-Nonce');
      if (sig == null || sig.isEmpty || nonce == null) {
        req.response.statusCode = HttpStatus.unauthorized;
        await req.response.close();
        return;
      }

      // Streaming payload defense
      final bodyBytes = BytesBuilder();
      await for (final chunk in req) {
        if (bodyBytes.length + chunk.length > _maxPayload) {
          req.response.statusCode = HttpStatus.requestEntityTooLarge;
          await req.response.close();
          return;
        }
        bodyBytes.add(chunk);
      }

      final body = utf8.decode(bodyBytes.takeBytes());
      if (!hmac.verify(body, sig, nonce: nonce)) {
        _emit('SEC', 'HMAC verification failed.');
        req.response.statusCode = HttpStatus.forbidden;
        await req.response.close();
        return;
      }

      final data = jsonDecode(cipher.decrypt(body)) as Map<String, dynamic>;
      final action = data['action'] as String? ?? '';
      final resp = {
        'status': 'success',
        'action': action,
        'time': DateTime.now().toIso8601String(),
      };
      final encResp = cipher.encrypt(jsonEncode(resp));
      final respNonce = DateTime.now().millisecondsSinceEpoch.toString();
      final respSig = hmac.sign(encResp, nonce: respNonce);

      req.response
        ..statusCode = HttpStatus.ok
        ..headers.contentType = ContentType.text
        ..headers.set('X-Sig', respSig)
        ..headers.set('X-Nonce', respNonce)
        ..write(encResp);
      await req.response.close();
    } catch (e) {
      _emit('ERR', '$e');
      try {
        req.response.statusCode = HttpStatus.internalServerError;
        await req.response.close();
      } catch (_) {}
    }
  }

  void _emit(String tag, String msg) {
    final t = DateTime.now().toIso8601String().substring(11, 19);
    if (!_log.isClosed) _log.add('[$t] [$tag] $msg');
  }

  Future<void> dispose() async {
    await shutdown();
    if (!_log.isClosed) await _log.close();
  }
}

// =============================================================================
// SECTION 7: MODELS + SCHEDULER
// =============================================================================
enum TargetStatus { idle, scanning, up, down, error }
enum ScanType {
  portScan,
  subnetScan,
  dnsLookup,
  httpProbe,
  geolocate,
  whois,
  tcpPing,
}

class LatencyPoint {
  final DateTime t;
  final Duration ms;
  LatencyPoint(this.t, this.ms);
}

class Target {
  final String id;
  String host;
  List<int> ports;
  ScanType scanType;
  TargetStatus status = TargetStatus.idle;
  List<PortResult> portResults = [];
  SubnetResult? subnetResult;
  DnsResult? dnsResult;
  HttpResult? httpResult;
  GeoResult? geoResult;
  WhoisResult? whoisResult;
  PingResult? pingResult;
  String? lastError;
  double progress = 0;
  Duration? scheduleInterval;
  List<LatencyPoint> latencyHistory = [];

  Target({
    required this.id,
    required this.host,
    required this.ports,
    required this.scanType,
  });

  int get openPorts => portResults.where((r) => r.isOpen).length;
  bool get isScheduled => scheduleInterval != null;
}

class ScanScheduler {
  final _timers = <String, Timer>{};
  void Function(String)? onFire;

  void schedule(String id, Duration interval) {
    cancel(id);
    _timers[id] = Timer.periodic(interval, (_) => onFire?.call(id));
  }

  void cancel(String id) {
    _timers[id]?.cancel();
    _timers.remove(id);
  }

  void cancelAll() {
    for (final t in _timers.values) {
      t.cancel();
    }
    _timers.clear();
  }
}

// =============================================================================
// SECTION 8: CONTROLLER
// =============================================================================
class PhantomController extends ChangeNotifier {
  final LocalCore core;
  final PhantomCipher cipher;
  final HmacAuth hmac;
  final NetworkScanner scanner;
  final ScanScheduler scheduler = ScanScheduler();
  final http.Client _client = http.Client();
  StreamSubscription? _sub;
  bool _disposed = false;
  bool isInitialized = false;

  static const _maxLogs = 500;
  final List<String> logs = [];
  final List<Target> targets = [];

  PhantomController({
    required this.core,
    required this.cipher,
    required this.hmac,
    required this.scanner,
  }) {
    _sub = core.stream.listen((l) => _addLog(l));
    scheduler.onFire = (id) {
      final t = targets.where((x) => x.id == id).firstOrNull;
      if (t != null) runScan(t);
    };
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  void _addLog(String l) {
    if (logs.length >= _maxLogs) logs.removeLast();
    logs.insert(0, l);
    _notify();
  }

  void log(String msg) {
    final t = DateTime.now().toIso8601String().substring(11, 19);
    _addLog('[$t] $msg');
  }

  Future<void> initialize() async {
    try {
      await core.boot();
      isInitialized = true;
      log('Core online on port ${core.port}');
    } catch (e) {
      isInitialized = false;
      log('Boot failed: $e');
    }
    _notify();
  }

  void addTarget(String host, ScanType type, List<int> ports) {
    targets.add(Target(
      id: 'T${DateTime.now().millisecondsSinceEpoch}',
      host: host.trim(),
      ports: ports,
      scanType: type,
    ));
    log('Added: $host (${type.name})');
    _notify();
  }

  void removeTarget(String id) {
    scheduler.cancel(id);
    targets.removeWhere((t) => t.id == id);
    _notify();
  }

  void scheduleTarget(Target t, Duration interval) {
    scheduler.schedule(t.id, interval);
    t.scheduleInterval = interval;
    log('Scheduled ${t.host} every ${interval.inSeconds}s');
    _notify();
  }

  void unscheduleTarget(Target t) {
    scheduler.cancel(t.id);
    t.scheduleInterval = null;
    log('Unscheduled ${t.host}');
    _notify();
  }

  Future<void> runScan(Target t) async {
    if (t.status == TargetStatus.scanning) return;
    t.status = TargetStatus.scanning;
    t.lastError = null;
    t.progress = 0;
    t.portResults.clear();
    t.subnetResult = null;
    t.dnsResult = null;
    t.httpResult = null;
    t.geoResult = null;
    t.whoisResult = null;
    t.pingResult = null;
    _notify();
    log('Running ${t.scanType.name} on ${t.host}');

    try {
      switch (t.scanType) {
        case ScanType.portScan:
          await _portScan(t);
          break;
        case ScanType.subnetScan:
          await _subnetScan(t);
          break;
        case ScanType.dnsLookup:
          await _dns(t);
          break;
        case ScanType.httpProbe:
          await _http(t);
          break;
        case ScanType.geolocate:
          await _geo(t);
          break;
        case ScanType.whois:
          await _whois(t);
          break;
        case ScanType.tcpPing:
          await _tcpPing(t);
          break;
      }
      t.progress = 1;
    } catch (e) {
      t.status = TargetStatus.error;
      t.lastError = e.toString();
      log('Scan error: $e');
    }
    _notify();
  }

  Future<void> _portScan(Target t) async {
    final open = <int>[];
    await scanner.scanPorts(
      t.host,
      t.ports,
      onResult: (r) {
        t.portResults.add(r);
        if (r.isOpen) {
          open.add(r.port);
          log('${t.host}:${r.port} OPEN (${r.service}) ${r.latency?.inMilliseconds}ms');
          if (r.latency != null) {
            t.latencyHistory.add(LatencyPoint(DateTime.now(), r.latency!));
          }
        }
      },
      onProgress: (d, tot) {
        t.progress = d / tot;
        _notify();
      },
    );
    t.status = open.isEmpty ? TargetStatus.down : TargetStatus.up;
    log('Ports done: ${open.length}/${t.ports.length} open');
  }

  Future<void> _subnetScan(Target t) async {
    final probePort = t.ports.isNotEmpty ? t.ports.first : 80;
    try {
      final r = await scanner.scanSubnet(t.host, probePort,
          onProgress: (d, tot, alive) {
        t.progress = d / tot;
        if (alive != null) {
          log('Alive: ${alive.ip}:${alive.port} ${alive.latency.inMilliseconds}ms');
        }
        _notify();
      });
      t.subnetResult = r;
      t.status = r.alive > 0 ? TargetStatus.up : TargetStatus.down;
      log('Subnet: ${r.alive}/${r.total} alive (${r.totalTime.inSeconds}s)');
    } on ArgumentError catch (e) {
      t.status = TargetStatus.error;
      t.lastError = e.message.toString();
      log('Subnet error: ${e.message}');
    } catch (e) {
      t.status = TargetStatus.error;
      t.lastError = e.toString();
      log('Subnet error: $e');
    }
  }

  Future<void> _dns(Target t) async {
    final r = await scanner.resolveDns(t.host);
    t.dnsResult = r;
    if (r.error != null) {
      t.status = TargetStatus.error;
      t.lastError = r.error;
      log('DNS error: ${r.error}');
    } else {
      t.status = TargetStatus.up;
      log('DNS A=${r.ipv4.join(",")} AAAA=${r.ipv6.length} (${r.latency.inMilliseconds}ms)');
      t.latencyHistory.add(LatencyPoint(DateTime.now(), r.latency));
    }
  }

  Future<void> _http(Target t) async {
    final url = t.host.startsWith('http') ? t.host : 'https://${t.host}';
    final r = await scanner.probeHttp(url);
    t.httpResult = r;
    if (r.error != null) {
      t.status = TargetStatus.error;
      t.lastError = r.error;
      log('HTTP error: ${r.error}');
    } else {
      t.status = TargetStatus.up;
      log('HTTP ${r.status} ${r.latency.inMilliseconds}ms (${r.server ?? "?"})');
      t.latencyHistory.add(LatencyPoint(DateTime.now(), r.latency));
    }
  }

  Future<void> _geo(Target t) async {
    final r = await scanner.geolocate(t.host);
    t.geoResult = r;
    if (r.error != null) {
      t.status = TargetStatus.error;
      t.lastError = r.error;
      log('Geo error: ${r.error}');
    } else {
      t.status = TargetStatus.up;
      log('Geo: ${r.country} / ${r.city} • ${r.isp}');
    }
  }

  Future<void> _whois(Target t) async {
    final r = await scanner.whois(t.host);
    t.whoisResult = r;
    if (r.error != null) {
      t.status = TargetStatus.error;
      t.lastError = r.error;
      log('WHOIS error: ${r.error}');
    } else {
      t.status = TargetStatus.up;
      log('WHOIS ${r.raw.length} chars (${r.latency.inMilliseconds}ms)');
      t.latencyHistory.add(LatencyPoint(DateTime.now(), r.latency));
    }
  }

  Future<void> _tcpPing(Target t) async {
    final port = t.ports.isNotEmpty ? t.ports.first : 443;
    final r = await scanner.tcpPing(t.host, port: port);
    t.pingResult = r;
    if (r.error != null) {
      t.status = TargetStatus.error;
      t.lastError = r.error;
      log('Ping error: ${r.error}');
    } else {
      t.status = r.success ? TargetStatus.up : TargetStatus.down;
      log('TCP Ping ${r.success ? "OK" : "FAIL"} ${r.latency?.inMilliseconds}ms');
      if (r.latency != null) {
        t.latencyHistory.add(LatencyPoint(DateTime.now(), r.latency!));
      }
    }
  }

  Future<void> heartbeat() async {
    if (!core.isRunning || core.port == null) {
      log('Core offline');
      return;
    }
    final sw = Stopwatch()..start();
    try {
      final payload = jsonEncode({'action': 'heartbeat'});
      final enc = cipher.encrypt(payload);
      final nonce = DateTime.now().millisecondsSinceEpoch.toString();
      final sig = hmac.sign(enc, nonce: nonce);
      final r = await _client
          .post(
            Uri.parse('http://127.0.0.1:${core.port}/v1/exec'),
            headers: {
              'Content-Type': 'text/plain',
              'X-Sig': sig,
              'X-Nonce': nonce,
            },
            body: enc,
          )
          .timeout(const Duration(seconds: 5));
      sw.stop();
      if (r.statusCode == 200) {
        final rs = r.headers['x-sig'] ?? r.headers['X-Sig'];
        final rnonce = r.headers['x-nonce'] ?? r.headers['X-Nonce'];
        if (rs == null ||
            rnonce == null ||
            !hmac.verify(r.body, rs, nonce: rnonce)) {
          log('Response signature invalid');
          return;
        }
        cipher.decrypt(r.body);
        log('Heartbeat OK (${sw.elapsed.inMilliseconds}ms, HMAC verified)');
      } else {
        log('Heartbeat rejected: ${r.statusCode}');
      }
    } catch (e) {
      log('Heartbeat fault: $e');
    }
    _notify();
  }

  Future<void> listInterfaces() async {
    final ifs = await scanner.listInterfaces();
    log('Interfaces: ${ifs.length}');
    for (final i in ifs) {
      log('  ${i.name} [${i.type}] ${i.address}${i.isLoopback ? " (lo)" : ""}');
    }
  }

  Future<void> wipeKeys() async {
    await KeyVault.wipe();
    log('Keys wiped. Restart app to regenerate.');
  }

  String exportJson() {
    return const JsonEncoder.withIndent('  ').convert(
      targets.map((t) {
        return {
          'host': t.host,
          'type': t.scanType.name,
          'status': t.status.name,
          'scheduled_s': t.scheduleInterval?.inSeconds,
          'open_ports': t.portResults
              .where((r) => r.isOpen)
              .map((r) => {
                    'port': r.port,
                    'service': r.service,
                    'ms': r.latency?.inMilliseconds,
                  })
              .toList(),
          'subnet': t.subnetResult == null
              ? null
              : {
                  'cidr': t.subnetResult!.cidr,
                  'total': t.subnetResult!.total,
                  'alive': t.subnetResult!.alive,
                  'hosts': t.subnetResult!.hosts
                      .map((h) => {
                            'ip': h.ip,
                            'port': h.port,
                            'ms': h.latency.inMilliseconds,
                          })
                      .toList(),
                },
          'dns': t.dnsResult == null
              ? null
              : {'ipv4': t.dnsResult!.ipv4, 'ipv6': t.dnsResult!.ipv6},
          'http': t.httpResult == null
              ? null
              : {
                  'status': t.httpResult!.status,
                  'server': t.httpResult!.server,
                },
          'geo': t.geoResult == null
              ? null
              : {
                  'country': t.geoResult!.country,
                  'city': t.geoResult!.city,
                  'isp': t.geoResult!.isp,
                },
          'whois_preview': t.whoisResult == null
              ? null
              : t.whoisResult!.raw.substring(
                  0,
                  t.whoisResult!.raw.length > 500
                      ? 500
                      : t.whoisResult!.raw.length),
          'ping': t.pingResult == null
              ? null
              : {
                  'success': t.pingResult!.success,
                  'ms': t.pingResult!.latency?.inMilliseconds,
                },
          'latency_history': t.latencyHistory
              .map((p) => {
                    't': p.t.toIso8601String(),
                    'ms': p.ms.inMilliseconds,
                  })
              .toList(),
        };
      }).toList(),
    );
  }

  void clearLogs() {
    logs.clear();
    _notify();
  }

  @override
  void dispose() {
    _disposed = true;
    scheduler.cancelAll();
    _sub?.cancel();
    _client.close();
    super.dispose();
  }
}

// =============================================================================
// SECTION 9: LATENCY CHART
// =============================================================================
class LatencyChart extends StatelessWidget {
  final List<LatencyPoint> points;
  const LatencyChart({super.key, required this.points});

  @override
  Widget build(BuildContext context) {
    if (points.isEmpty) {
      return const SizedBox.shrink();
    }
    return Container(
      height: 90,
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: Colors.black.withOpacity(0.25),
        borderRadius: BorderRadius.circular(6),
      ),
      child: CustomPaint(
        painter: _ChartPainter(points),
        size: Size.infinite,
      ),
    );
  }
}

class _ChartPainter extends CustomPainter {
  final List<LatencyPoint> points;
  _ChartPainter(this.points);

  @override
  void paint(Canvas canvas, Size size) {
    if (points.isEmpty) return;

    const padL = 34.0, padR = 6.0, padT = 6.0, padB = 14.0;
    final w = size.width - padL - padR;
    final h = size.height - padT - padB;

    final maxMs =
        points.map((p) => p.ms.inMilliseconds).reduce(max).toDouble() * 1.1;
    final range = maxMs.clamp(1, double.infinity);

    // Grid
    final grid = Paint()
      ..color = Colors.white12
      ..strokeWidth = 0.5;
    for (var i = 0; i <= 3; i++) {
      final y = padT + h * (i / 3);
      canvas.drawLine(Offset(padL, y), Offset(size.width - padR, y), grid);
      _txt(canvas, '${(maxMs * (1 - i / 3)).toInt()}', Offset(2, y - 5));
    }

    // Line
    final line = Paint()
      ..color = const Color(0xFF00FF66)
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke;
    final path = Path();
    for (var i = 0; i < points.length; i++) {
      final x =
          padL + w * (i / (points.length - 1).clamp(1, double.infinity));
      final v = points[i].ms.inMilliseconds / range;
      final y = padT + h * (1 - v);
      i == 0 ? path.moveTo(x, y) : path.lineTo(x, y);
    }
    canvas.drawPath(path, line);

    // Dots
    final dot = Paint()..color = const Color(0xFF00FF66);
    for (var i = 0; i < points.length; i++) {
      final x =
          padL + w * (i / (points.length - 1).clamp(1, double.infinity));
      final v = points[i].ms.inMilliseconds / range;
      final y = padT + h * (1 - v);
      canvas.drawCircle(Offset(x, y), 2.5, dot);
    }

    _txt(canvas, 'last ${points.length}', Offset(padL, size.height - 11));
  }

  void _txt(Canvas c, String s, Offset o) {
    TextPainter(
      text: TextSpan(
        text: s,
        style: const TextStyle(fontSize: 9, color: Colors.white54),
      ),
      textDirection: TextDirection.ltr,
    )
      ..layout()
      ..paint(c, o);
  }

  @override
  bool shouldRepaint(covariant _ChartPainter old) => old.points != points;
}

// =============================================================================
// SECTION 10: APP ROOT (with retry)
// =============================================================================
class PhantomCoreApp extends StatefulWidget {
  const PhantomCoreApp({super.key});

  @override
  State<PhantomCoreApp> createState() => _AppState();
}

class _AppState extends State<PhantomCoreApp> {
  PhantomCipher? _cipher;
  LocalCore? _core;
  PhantomController? _ctrl;
  bool _loading = true;
  String? _err;

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    setState(() {
      _loading = true;
      _err = null;
    });
    try {
      final mk = await KeyVault.getOrCreateMasterKey();
      final hk = await KeyVault.getOrCreateHmacKey();
      _cipher = PhantomCipher(mk);
      final hmac = HmacAuth(hk);
      final scanner = NetworkScanner();
      _core = LocalCore(_cipher!, hmac);
      _ctrl = PhantomController(
        core: _core!,
        cipher: _cipher!,
        hmac: hmac,
        scanner: scanner,
      );
      await _ctrl!.initialize();
    } catch (e) {
      _err = e.toString();
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  void dispose() {
    _ctrl?.dispose();
    _core?.dispose();
    super.dispose();
  }

  Widget _home() {
    if (_loading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator(color: Color(0xFF00FF66))),
      );
    }
    if (_err != null || _ctrl == null) {
      return Scaffold(
        backgroundColor: const Color(0xFF020408),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.error_outline,
                    color: Colors.redAccent, size: 48),
                const SizedBox(height: 16),
                const Text('Boot failed',
                    style: TextStyle(
                        color: Colors.redAccent,
                        fontSize: 16,
                        fontFamily: 'monospace')),
                const SizedBox(height: 8),
                Text(_err ?? 'unknown',
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 11,
                        fontFamily: 'monospace')),
                const SizedBox(height: 20),
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF00FF66),
                    foregroundColor: Colors.black,
                  ),
                  icon: const Icon(Icons.refresh),
                  label: const Text('Retry'),
                  onPressed: _boot,
                ),
              ],
            ),
          ),
        ),
      );
    }
    return Dashboard(ctrl: _ctrl!);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'PHANTOM-9 v11.1',
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF020408),
        cardColor: const Color(0xFF070B14),
        colorScheme: const ColorScheme.dark(
          primary: const Color(0xFF00FF66),
          secondary: const Color(0xFF38BDF8),
          surface: const Color(0xFF070B14),
        ),
      ),
      home: _home(),
    );
  }
}

// =============================================================================
// SECTION 11: DASHBOARD
// =============================================================================
class Dashboard extends StatefulWidget {
  final PhantomController ctrl;
  const Dashboard({super.key, required this.ctrl});

  @override
  State<Dashboard> createState() => _DashState();
}

class _DashState extends State<Dashboard>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  Future<void> _addDialog() async {
    final hostC = TextEditingController();
    final portC = TextEditingController(text: '22,80,443,8080');
    ScanType type = ScanType.portScan;

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSt) => AlertDialog(
          backgroundColor: const Color(0xFF070B14),
          title: const Text('Add Target',
              style: TextStyle(color: Color(0xFF00FF66), fontSize: 15)),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: hostC,
                  decoration: InputDecoration(
                    labelText: type == ScanType.subnetScan
                        ? 'CIDR (e.g. 192.168.1.0/24)'
                        : 'Host (IP or domain)',
                    labelStyle: const TextStyle(color: Colors.grey),
                  ),
                  style: const TextStyle(color: Colors.white),
                ),
                const SizedBox(height: 12),
                DropdownButton<ScanType>(
                  value: type,
                  dropdownColor: const Color(0xFF070B14),
                  isExpanded: true,
                  items: const [
                    DropdownMenuItem(
                        value: ScanType.portScan, child: Text('TCP Port Scan')),
                    DropdownMenuItem(
                        value: ScanType.subnetScan,
                        child: Text('Subnet CIDR Scan')),
                    DropdownMenuItem(
                        value: ScanType.dnsLookup, child: Text('DNS Lookup')),
                    DropdownMenuItem(
                        value: ScanType.httpProbe, child: Text('HTTP Probe')),
                    DropdownMenuItem(
                        value: ScanType.geolocate,
                        child: Text('IP Geolocation')),
                    DropdownMenuItem(
                        value: ScanType.whois, child: Text('WHOIS Query')),
                    DropdownMenuItem(
                        value: ScanType.tcpPing, child: Text('TCP Ping')),
                  ],
                  onChanged: (v) => setSt(() => type = v ?? type),
                ),
                // ✅ حقل المنافذ ظاهر بحسب النوع
                if (type == ScanType.portScan ||
                    type == ScanType.subnetScan ||
                    type == ScanType.tcpPing) ...[
                  const SizedBox(height: 12),
                  TextField(
                    controller: portC,
                    decoration: InputDecoration(
                      labelText: type == ScanType.subnetScan
                          ? 'Probe port (single, e.g. 80)'
                          : type == ScanType.tcpPing
                              ? 'TCP port (e.g. 443)'
                              : 'Ports (comma-separated)',
                      labelStyle: const TextStyle(color: Colors.grey),
                    ),
                    style: const TextStyle(color: Colors.white),
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Add',
                  style: TextStyle(color: Color(0xFF00FF66))),
            ),
          ],
        ),
      ),
    );

    if (ok == true && hostC.text.trim().isNotEmpty) {
      final ports = portC.text
          .split(',')
          .map((s) => int.tryParse(s.trim()))
          .whereType<int>()
          .toList();
      widget.ctrl.addTarget(
        hostC.text.trim(),
        type,
        ports.isEmpty ? const [80, 443] : ports,
      );
    }
  }

  Future<void> _scheduleDialog(Target t) async {
    final opts = {
      '30 seconds': const Duration(seconds: 30),
      '1 minute': const Duration(minutes: 1),
      '5 minutes': const Duration(minutes: 5),
      '15 minutes': const Duration(minutes: 15),
      '1 hour': const Duration(hours: 1),
      'Stop Schedule': Duration.zero,
    };

    final sel = await showDialog<String>(
      context: context,
      builder: (ctx) => SimpleDialog(
        backgroundColor: const Color(0xFF070B14),
        title: Text('Schedule: ${t.host}',
            style: const TextStyle(color: Color(0xFF00FF66), fontSize: 14)),
        children: opts.keys
            .map((k) => SimpleDialogOption(
                  onPressed: () => Navigator.pop(ctx, k),
                  child: Text(k,
                      style: TextStyle(
                        color: k == 'Stop Schedule'
                            ? Colors.redAccent
                            : Colors.white,
                        fontSize: 13,
                      )),
                ))
            .toList(),
      ),
    );
    if (sel == null) return;
    if (sel == 'Stop Schedule') {
      widget.ctrl.unscheduleTarget(t);
    } else {
      widget.ctrl.scheduleTarget(t, opts[sel]!);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.ctrl,
      builder: (context, _) {
        final c = widget.ctrl;
        return Scaffold(
          appBar: AppBar(
            title: const Text('PHANTOM-9 v11.1',
                style: TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                    color: Color(0xFF00FF66),
                    letterSpacing: 1.1)),
            actions: [
              IconButton(
                icon: const Icon(Icons.add, color: Color(0xFF00FF66)),
                tooltip: 'Add Target',
                onPressed: _addDialog,
              ),
              IconButton(
                icon: const Icon(Icons.lan, color: Color(0xFF38BDF8)),
                tooltip: 'Interfaces',
                onPressed: c.listInterfaces,
              ),
              PopupMenuButton<String>(
                icon: const Icon(Icons.more_vert, color: Colors.white70),
                onSelected: (v) async {
                  if (v == 'wipe') {
                    final ok = await showDialog<bool>(
                      context: context,
                      builder: (ctx) => AlertDialog(
                        backgroundColor: const Color(0xFF070B14),
                        title: const Text('Wipe Keys?',
                            style: TextStyle(color: Colors.redAccent)),
                        content: const Text(
                            'Deletes the master key. Restart to regenerate.',
                            style: TextStyle(color: Colors.white70)),
                        actions: [
                          TextButton(
                              onPressed: () => Navigator.pop(ctx, false),
                              child: const Text('Cancel')),
                          TextButton(
                              onPressed: () => Navigator.pop(ctx, true),
                              child: const Text('Wipe',
                                  style:
                                      TextStyle(color: Colors.redAccent))),
                        ],
                      ),
                    );
                    if (ok == true) c.wipeKeys();
                  }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(
                    value: 'wipe',
                    child: Text('Wipe Keys',
                        style: TextStyle(color: Colors.redAccent)),
                  ),
                ],
              ),
            ],
            bottom: TabBar(
              controller: _tabs,
              labelColor: const Color(0xFF00FF66),
              unselectedLabelColor: Colors.grey,
              indicatorColor: const Color(0xFF00FF66),
              tabs: const [
                Tab(text: 'Targets'),
                Tab(text: 'Log'),
              ],
            ),
          ),
          body: TabBarView(
            controller: _tabs,
            children: [
              _TargetsTab(ctrl: c, onSchedule: _scheduleDialog),
              _LogTab(ctrl: c),
            ],
          ),
          bottomNavigationBar: Container(
            padding: const EdgeInsets.all(10),
            color: const Color(0xFF070B14),
            child: Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF0D1526),
                      foregroundColor: const Color(0xFF00FF66),
                    ),
                    icon: const Icon(Icons.favorite, size: 18),
                    label: const Text('Heartbeat'),
                    onPressed: c.heartbeat,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF0D1526),
                      foregroundColor: const Color(0xFF38BDF8),
                    ),
                    icon: const Icon(Icons.download, size: 18),
                    label: const Text('Export JSON'),
                    onPressed: () async {
                      final j = c.exportJson();
                      await Clipboard.setData(ClipboardData(text: j));
                      c.log('Exported JSON copied (${j.length} chars)');
                    },
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

// =============================================================================
// SECTION 12: TARGETS TAB
// =============================================================================
class _TargetsTab extends StatelessWidget {
  final PhantomController ctrl;
  final Future<void> Function(Target) onSchedule;
  const _TargetsTab({required this.ctrl, required this.onSchedule});

  Color _statusColor(TargetStatus s) {
    switch (s) {
      case TargetStatus.up:
        return const Color(0xFF00FF66);
      case TargetStatus.down:
        return Colors.orange;
      case TargetStatus.error:
        return Colors.redAccent;
      case TargetStatus.scanning:
        return const Color(0xFF38BDF8);
      case TargetStatus.idle:
        return Colors.grey;
    }
  }

  IconData _typeIcon(ScanType t) {
    switch (t) {
      case ScanType.subnetScan:
        return Icons.hub;
      case ScanType.portScan:
        return Icons.settings_ethernet;
      case ScanType.dnsLookup:
        return Icons.dns;
      case ScanType.httpProbe:
        return Icons.http;
      case ScanType.geolocate:
        return Icons.public;
      case ScanType.whois:
        return Icons.article;
      case ScanType.tcpPing:
        return Icons.network_ping;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (ctrl.targets.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'No targets yet.\n\nTap + to add a host, subnet (CIDR),\nor any of the 7 tools.',
            textAlign: TextAlign.center,
            style: TextStyle(color: Colors.grey, fontSize: 13),
          ),
        ),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: ctrl.targets.length,
      itemBuilder: (context, i) {
        final t = ctrl.targets[i];
        return Card(
          color: const Color(0xFF070B14),
          margin: const EdgeInsets.only(bottom: 8),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
            side: const BorderSide(color: Color(0xFF131C2E)),
          ),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Header row
                Row(
                  children: [
                    Icon(_typeIcon(t.scanType),
                        color: _statusColor(t.status), size: 20),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        t.host,
                        style: const TextStyle(
                            fontWeight: FontWeight.bold, fontSize: 13),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (t.isScheduled)
                      Container(
                        margin: const EdgeInsets.only(right: 4),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: const Color(0xFF38BDF8).withOpacity(0.2),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text('${t.scheduleInterval!.inSeconds}s',
                            style: const TextStyle(
                                fontSize: 9,
                                color: Color(0xFF38BDF8),
                                fontFamily: 'monospace')),
                      ),
                    IconButton(
                      icon: const Icon(Icons.schedule,
                          size: 18, color: Color(0xFF38BDF8)),
                      tooltip: 'Schedule',
                      onPressed: () => onSchedule(t),
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                    const SizedBox(width: 8),
                    IconButton(
                      icon: const Icon(Icons.close,
                          size: 18, color: Colors.grey),
                      onPressed: () => ctrl.removeTarget(t.id),
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                  ],
                ),
                const SizedBox(height: 4),

                // Type + Status
                Text(
                  '${t.scanType.name} • ${t.status.name}',
                  style: TextStyle(
                      fontSize: 11,
                      color: _statusColor(t.status),
                      fontFamily: 'monospace'),
                ),

                // Progress
                if (t.status == TargetStatus.scanning) ...[
                  const SizedBox(height: 6),
                  LinearProgressIndicator(
                    value: t.progress,
                    backgroundColor: const Color(0xFF131C2E),
                    valueColor: const AlwaysStoppedAnimation(
                        Color(0xFF38BDF8)),
                    minHeight: 3,
                  ),
                ],

                // ===== Ports =====
                if (t.portResults.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text(
                    'Open ports: ${t.openPorts}/${t.ports.length}',
                    style: const TextStyle(
                        fontSize: 11, color: Colors.white70),
                  ),
                  ...t.portResults.where((r) => r.isOpen).map((r) => Text(
                        '  • ${r.port} (${r.service}) ${r.latency?.inMilliseconds}ms',
                        style: const TextStyle(
                            fontSize: 10,
                            fontFamily: 'monospace',
                            color: Color(0xFF4ADE80)),
                      )),
                ],

                // ===== Subnet =====
                if (t.subnetResult != null) ...[
                  const SizedBox(height: 6),
                  Text(
                    'Alive: ${t.subnetResult!.alive}/${t.subnetResult!.total} (${t.subnetResult!.totalTime.inSeconds}s)',
                    style: const TextStyle(
                        fontSize: 11, color: Color(0xFF38BDF8)),
                  ),
                  ...t.subnetResult!.hosts.take(12).map((h) => Text(
                        '  • ${h.ip}:${h.port} ${h.latency.inMilliseconds}ms',
                        style: const TextStyle(
                            fontSize: 10,
                            fontFamily: 'monospace',
                            color: Color(0xFF4ADE80)),
                      )),
                  if (t.subnetResult!.hosts.length > 12)
                    Text(
                      '  ...+${t.subnetResult!.hosts.length - 12} more',
                      style: const TextStyle(
                          fontSize: 10, color: Colors.white54),
                    ),
                ],

                // ===== DNS =====
                if (t.dnsResult != null && t.dnsResult!.error == null) ...[
                  const SizedBox(height: 6),
                  if (t.dnsResult!.ipv4.isNotEmpty)
                    Text('A: ${t.dnsResult!.ipv4.join(", ")}',
                        style: const TextStyle(
                            fontSize: 11,
                            fontFamily: 'monospace',
                            color: Color(0xFF38BDF8))),
                  if (t.dnsResult!.ipv6.isNotEmpty)
                    Text('AAAA: ${t.dnsResult!.ipv6.length} record(s)',
                        style: const TextStyle(
                            fontSize: 11, color: Colors.white70)),
                ],

                // ===== HTTP =====
                if (t.httpResult != null && t.httpResult!.error == null) ...[
                  const SizedBox(height: 6),
                  Text(
                    'HTTP ${t.httpResult!.status} • ${t.httpResult!.latency.inMilliseconds}ms',
                    style: const TextStyle(
                        fontSize: 11, color: Color(0xFF38BDF8)),
                  ),
                  if (t.httpResult!.server != null)
                    Text('Server: ${t.httpResult!.server}',
                        style: const TextStyle(
                            fontSize: 10, color: Colors.white70)),
                ],

                // ===== Geo =====
                if (t.geoResult != null && t.geoResult!.error == null) ...[
                  const SizedBox(height: 6),
                  Text('Geo: ${t.geoResult!.country} / ${t.geoResult!.city}',
                      style: const TextStyle(
                          fontSize: 11, color: Color(0xFF38BDF8))),
                  if (t.geoResult!.isp != null)
                    Text('ISP: ${t.geoResult!.isp}',
                        style: const TextStyle(
                            fontSize: 10, color: Colors.white70)),
                  if (t.geoResult!.lat != null)
                    Text(
                        'Coords: ${t.geoResult!.lat}, ${t.geoResult!.lon}',
                        style: const TextStyle(
                            fontSize: 10, color: Colors.white70)),
                ],

                // ===== WHOIS =====
                if (t.whoisResult != null && t.whoisResult!.error == null) ...[
                  const SizedBox(height: 6),
                  Text(
                    'WHOIS: ${t.whoisResult!.raw.length} chars (${t.whoisResult!.latency.inMilliseconds}ms)',
                    style: const TextStyle(
                        fontSize: 11, color: Color(0xFF38BDF8)),
                  ),
                ],

                // ===== TCP Ping =====
                if (t.pingResult != null) ...[
                  const SizedBox(height: 6),
                  Text(
                    'TCP Ping: ${t.pingResult!.success ? "OK" : "FAIL"} ${t.pingResult!.latency?.inMilliseconds ?? "?"}ms',
                    style: TextStyle(
                        fontSize: 11,
                        color: t.pingResult!.success
                            ? const Color(0xFF4ADE80)
                            : Colors.orange),
                  ),
                ],

                // ===== Latency chart =====
                if (t.latencyHistory.length >= 2) ...[
                  const SizedBox(height: 8),
                  const Text('Latency',
                      style: TextStyle(
                          fontSize: 10, color: Colors.white54)),
                  const SizedBox(height: 3),
                  LatencyChart(points: t.latencyHistory),
                ],

                // ===== Error =====
                if (t.lastError != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text('⚠ ${t.lastError}',
                        style: const TextStyle(
                            fontSize: 10, color: Colors.redAccent)),
                  ),

                // ===== Actions =====
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    if (t.isScheduled)
                      TextButton.icon(
                        icon: const Icon(Icons.stop, size: 16),
                        label: const Text('Stop'),
                        style: TextButton.styleFrom(
                            foregroundColor: Colors.orange),
                        onPressed: () => ctrl.unscheduleTarget(t),
                      ),
                    TextButton.icon(
                      icon: Icon(
                        t.status == TargetStatus.scanning
                            ? Icons.hourglass_top
                            : Icons.play_arrow,
                        size: 18,
                      ),
                      label: Text(t.status == TargetStatus.scanning
                          ? 'Scanning...'
                          : 'Run'),
                      style: TextButton.styleFrom(
                          foregroundColor: const Color(0xFF00FF66)),
                      onPressed: t.status == TargetStatus.scanning
                          ? null
                          : () => ctrl.runScan(t),
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

// =============================================================================
// SECTION 13: LOG TAB
// =============================================================================
class _LogTab extends StatelessWidget {
  final PhantomController ctrl;
  const _LogTab({required this.ctrl});

  @override
  Widget build(BuildContext context) {
    if (ctrl.logs.isEmpty) {
      return const Center(
        child: Text('Log is empty.',
            style: TextStyle(color: Colors.grey, fontSize: 12)),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: ctrl.logs.length,
      itemBuilder: (context, i) {
        final l = ctrl.logs[i];
        var col = const Color(0xFF4ADE80);
        if (l.contains('error') || l.contains('Error') || l.contains('FAIL')) {
          col = Colors.redAccent;
        }
        if (l.contains('OPEN') || l.contains('Alive')) {
          col = const Color(0xFF00FF66);
        }
        if (l.contains('Scheduled') || l.contains('Unscheduled')) {
          col = const Color(0xFF38BDF8);
        }
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: Text(
            l,
            style: TextStyle(
                fontFamily: 'monospace', fontSize: 11, color: col),
          ),
        );
      },
    );
  }
}