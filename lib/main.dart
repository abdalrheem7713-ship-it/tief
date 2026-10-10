import 'package:flutter/material.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PhantomApp());
}

class PhantomApp extends StatelessWidget {
  const PhantomApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'PHANTOM-9 Dashboard',
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        primaryColor: const Color(0xFF1F6FEB),
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({Key? key}) : super(key: key);

  @override
  _DashboardScreenState createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final List<Map<String, String>> activeCells = [
    {"id": "CELL-ALPHA-01", "ip": "192.168.1.15", "status": "متخفي (Active)"},
    {"id": "CELL-BETA-02", "ip": "10.0.4.8", "status": "مستقر (Sync)"},
    {"id": "CELL-GAMMA-03", "ip": "172.16.0.22", "status": "خامل (Sleeping)"},
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text(
          'PHANTOM-9 // لوحة القيادة',
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF58A6FF)),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.radar, color: Color(0xFF2EA043)),
            onPressed: () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('جاري فحص شبكة الـ Mesh والبحث عن إشارات جديدة...')),
              );
            },
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text("حالة النظام المركزية", style: TextStyle(color: Colors.grey, fontSize: 12)),
                  SizedBox(height: 5),
                  Text("🟢 الشبكة مؤمنة بالكامل (Mesh Active)", style: TextStyle(color: Color(0xFF2EA043), fontSize: 16, fontWeight: FontWeight.bold)),
                  SizedBox(height: 10),
                  Text("العقل المدبر (Hive Mind): يعمل بوضع التخفي المتكيف", style: TextStyle(color: Colors.white70, fontSize: 13)),
                ],
              ),
            ),
            const SizedBox(height: 20),
            const Text(
              "الخلايا النشطة حالياً (Active Cells):",
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            const SizedBox(height: 10),
            Expanded(
              child: ListView.builder(
                itemCount: activeCells.length,
                itemBuilder: (context, index) {
                  final cell = activeCells[index];
                  return Container(
                    margin: const EdgeInsets.only(bottom: 10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF21262D),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF30363D)),
                    ),
                    child: ListTile(
                      leading: const Icon(Icons.fingerprint, color: Color(0xFF58A6FF)),
                      title: Text(cell["id"]!, style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white)),
                      subtitle: Text("IP: ${cell["ip"]} | ${cell["status"]}", style: const TextStyle(color: Colors.grey, fontSize: 12)),
                      trailing: const Icon(Icons.arrow_forward_ios, size: 16, color: Colors.white54),
                      onTap: () {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text('تم توجيه الاتصال إلى الخلية: ${cell["id"]}')),
                        );
                      },
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}