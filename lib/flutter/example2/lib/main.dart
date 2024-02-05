import 'package:didkit/didkit.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MainApp());
}

class MainApp extends StatelessWidget {
  const MainApp({super.key});

  @override
  Widget build(BuildContext context) {

    void test(){
      print("Version");
      print(DIDKit.getVersion());
    }
    return  MaterialApp(
      home: Scaffold(
        body: Center(
          
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text('Hello World!'),
              FilledButton(onPressed: test, child: const Text("aqui"))
            ],
          ),
        ),
      ),
    );
  }
}
