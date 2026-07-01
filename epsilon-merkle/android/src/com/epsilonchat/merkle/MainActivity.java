package com.epsilonchat.merkle;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import android.widget.Toast;

public class MainActivity extends Activity {
    private WebView webView;
    // Try multiple potential server addresses
    private static final String SERVER_URL = "http://192.168.1.139:8848";
    private static final String LOCAL_FALLBACK = "file:///android_asset/index.html";

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        // Custom WebViewClient: if server fails to load, fall back to local assets
        webView.setWebViewClient(new WebViewClient() {
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                if (failingUrl != null && failingUrl.startsWith("http")) {
                    // Server not reachable — load local HTML which has SERVER_URL hardcoded
                    view.loadUrl(LOCAL_FALLBACK);
                }
            }
        });

        // Try Mac server first
        webView.loadUrl(SERVER_URL);

        // After 5 seconds, check if page loaded; if not, fall back to local
        final WebView finalWebView = webView;
        new Handler().postDelayed(new Runnable() {
            public void run() {
                String title = finalWebView.getTitle();
                if (title == null || title.isEmpty()) {
                    finalWebView.loadUrl(LOCAL_FALLBACK);
                }
            }
        }, 5000);

        setContentView(webView);
    }

    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}