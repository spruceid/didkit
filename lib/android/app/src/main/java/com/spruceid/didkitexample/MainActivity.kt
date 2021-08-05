package com.spruceid.didkitexample

import android.annotation.SuppressLint
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView
import com.spruceid.DIDKit

class MainActivity : AppCompatActivity() {
    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val key = DIDKit.generateEd25519Key()
        val did = DIDKit.keyToDID("tz", key)

        findViewById<TextView>(R.id.textView).text =
            """
                DIDKit v${DIDKit.getVersion()}
                
                Key -> $key
                
                DID -> $did
            """.trimIndent()
    }
}