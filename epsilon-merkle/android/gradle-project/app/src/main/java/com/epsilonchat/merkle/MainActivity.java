package com.epsilonchat.merkle;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebSettings;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final String SERVER_URL = "http://192.168.1.139:8848";

    private RecyclerView rvMessages;
    private MessageAdapter adapter;
    private EditText etMessage;
    private TextView tvStatus;
    private TextView tvBalance;
    private NativeBridge bridge;
    private boolean useNative = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Try native mode first
        bridge = new NativeBridge();
        try {
            String nodeId = bridge.startMesh();
            if (nodeId != null && !nodeId.isEmpty()) {
                useNative = true;
            }
        } catch (UnsatisfiedLinkError e) {
            useNative = false;
        }

        if (useNative) {
            setupNativeUI();
        } else {
            setupWebViewUI();
        }
    }

    private void setupNativeUI() {
        setContentView(R.layout.activity_main);

        rvMessages = findViewById(R.id.rvMessages);
        etMessage = findViewById(R.id.etMessage);
        tvStatus = findViewById(R.id.tvStatus);
        tvBalance = findViewById(R.id.tvBalance);
        Button btnSend = findViewById(R.id.btnSend);
        Button btnInvite = findViewById(R.id.btnInvite);
        Button btnConnect = findViewById(R.id.btnConnect);
        Button btnProof = findViewById(R.id.btnProof);
        Button btnClaim = findViewById(R.id.btnClaim);

        adapter = new MessageAdapter();
        rvMessages.setLayoutManager(new LinearLayoutManager(this));
        rvMessages.setAdapter(adapter);

        tvStatus.setText("connected");
        tvStatus.setTextColor(0xFF3FB950);

        // Add welcome message
        adapter.addMessage(new MessageAdapter.Message(
            "EpsilonChat", "Native mode active. Type a message below.",
            now(), false));

        btnSend.setOnClickListener(v -> {
            String text = etMessage.getText().toString().trim();
            if (text.isEmpty()) return;
            adapter.addMessage(new MessageAdapter.Message(
                "You", text, now(), true));
            etMessage.setText("");
            rvMessages.scrollToPosition(adapter.getItemCount() - 1);

            // In native mode: bridge.sendMessage(text, "all")
            try {
                bridge.sendMessage(text, "all");
            } catch (Exception e) {
                Toast.makeText(this, "Send error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });

        btnInvite.setOnClickListener(v -> {
            try {
                String invite = bridge.generateInvite();
                if (invite != null) {
                    adapter.addMessage(new MessageAdapter.Message(
                        "System", "Invite: " + invite.substring(0, Math.min(40, invite.length())),
                        now(), false));
                    rvMessages.scrollToPosition(adapter.getItemCount() - 1);
                }
            } catch (Exception e) {
                Toast.makeText(this, "Invite error", Toast.LENGTH_SHORT).show();
            }
        });

        btnConnect.setOnClickListener(v -> {
            try {
                bridge.connect(SERVER_URL);
                adapter.addMessage(new MessageAdapter.Message(
                    "System", "Connected to mesh", now(), false));
            } catch (Exception e) {
                Toast.makeText(this, "Connect error", Toast.LENGTH_SHORT).show();
            }
        });

        btnProof.setOnClickListener(v -> {
            try {
                String result = bridge.requestProof(0);
                adapter.addMessage(new MessageAdapter.Message(
                    "System", "Proof: " + (result != null ? result : "pending"),
                    now(), false));
            } catch (Exception e) {
                Toast.makeText(this, "Proof error", Toast.LENGTH_SHORT).show();
            }
        });

        btnClaim.setOnClickListener(v -> {
            try {
                String result = bridge.claimRewards("hash", 0);
                adapter.addMessage(new MessageAdapter.Message(
                    "System", "Claim: " + (result != null ? result : "pending"),
                    now(), false));
            } catch (Exception e) {
                Toast.makeText(this, "Claim error", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void setupWebViewUI() {
        // Fallback: WebView loading the web UI from Mac server
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        webView.loadUrl(SERVER_URL);

        // Fallback to local assets after 5s
        new Handler().postDelayed(() -> {
            if (webView.getTitle() == null || webView.getTitle().isEmpty()) {
                webView.loadUrl("file:///android_asset/index.html");
            }
        }, 5000);

        setContentView(webView);
    }

    private String now() {
        return new SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            .format(new Date());
    }
}