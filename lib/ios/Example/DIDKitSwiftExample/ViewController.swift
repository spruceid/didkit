//
//  ViewController.swift
//  DIDKitSwiftExample
//
//  Created by Guilherme Souza on 14/07/21.
//

import DIDKit
import UIKit

class ViewController: UIViewController {

  @IBOutlet weak var textView: UITextView!

  override func viewDidLoad() {
    super.viewDidLoad()
    navigationItem.title = "DIDKit v\(DIDKit.version())"
    navigationItem.rightBarButtonItem = UIBarButtonItem(
      barButtonSystemItem: .refresh, target: self, action: #selector(refresh))
    textView.contentInset = .init(top: 20, left: 20, bottom: 20, right: 20)

    refresh()
  }

  @objc func refresh() {
    do {
      let key = try DIDKit.generateEd25519Key()
      let did = try DIDKit.keyToDID(method: "tz", jwk: key)
      textView.text = """
        Key:
        \(prettify(key))

        \(did)
        """
    } catch {
      debugPrint(error)
    }
  }

}

func prettify(_ jsonString: String) -> String {
  var data = jsonString.data(using: .utf8)!
  let object = try! JSONSerialization.jsonObject(with: data, options: [])
  data = try! JSONSerialization.data(
    withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
  return String(data: data, encoding: .utf8)!
}
