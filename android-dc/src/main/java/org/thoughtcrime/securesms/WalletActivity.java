package org.thoughtcrime.securesms;

import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.ActionBar;
import com.b44t.messenger.DcContext;
import org.thoughtcrime.securesms.connect.DcHelper;
import org.thoughtcrime.securesms.util.Util;

/**
 * Shows the EpsilonChat wallet: SOL balance, EPS balance, wallet address, with a refresh button.
 * The balances are read from the core via the JNI bridge methods on {@link DcContext}:
 * {@link DcContext#epsilonGetBalance()}, {@link DcContext#epsilonGetWalletAddress()}.
 */
public class WalletActivity extends BaseActionBarActivity {

  private static final String TAG = "WalletActivity";

  private DcContext dcContext;

  private TextView solBalance;
  private TextView epsBalance;
  private TextView walletAddress;
  private TextView walletAddressEmpty;
  private View refreshButton;
  private ProgressBar refreshProgress;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.wallet_activity);

    dcContext = DcHelper.getContext(this);

    ActionBar actionBar = getSupportActionBar();
    if (actionBar != null) {
      actionBar.setTitle(R.string.wallet_title);
      actionBar.setDisplayHomeAsUpEnabled(true);
    }

    solBalance = findViewById(R.id.sol_balance);
    epsBalance = findViewById(R.id.eps_balance);
    walletAddress = findViewById(R.id.wallet_address);
    walletAddressEmpty = findViewById(R.id.wallet_address_empty);
    refreshButton = findViewById(R.id.refresh_button);
    refreshProgress = findViewById(R.id.refresh_progress);

    refreshButton.setOnClickListener(v -> refresh());

    // Initial refresh on the background thread so the UI never blocks.
    refresh();
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  /** Reads the balances from core and updates the views. Runs off the main thread. */
  private void refresh() {
    setRefreshing(true);
    Util.runOnBackground(
        () -> {
          final String balanceJson;
          final String address;
          try {
            balanceJson = dcContext.epsilonGetBalance();
            address = dcContext.epsilonGetWalletAddress();
          } catch (Exception e) {
            runOnUiThread(
                () -> {
                  setRefreshing(false);
                  Toast.makeText(this, R.string.wallet_refresh_failed, Toast.LENGTH_SHORT).show();
                });
            return;
          }

          // epsilonGetBalance() returns a JSON object: {"sol":0.0,"eps":0.0}
          // Parse it defensively — core may return null/empty when no wallet is configured.
          final double sol = parseJsonDouble(balanceJson, "sol");
          final double eps = parseJsonDouble(balanceJson, "eps");
          final boolean hasAddress = address != null && !address.isEmpty();

          runOnUiThread(
              () -> {
                solBalance.setText(formatSol(sol));
                epsBalance.setText(formatEps(eps));
                if (hasAddress) {
                  walletAddress.setText(address);
                  walletAddress.setVisibility(View.VISIBLE);
                  walletAddressEmpty.setVisibility(View.GONE);
                } else {
                  walletAddress.setVisibility(View.GONE);
                  walletAddressEmpty.setVisibility(View.VISIBLE);
                }
                setRefreshing(false);
                Toast.makeText(this, R.string.wallet_refreshed, Toast.LENGTH_SHORT).show();
              });
        });
  }

  private void setRefreshing(boolean refreshing) {
    refreshProgress.setVisibility(refreshing ? View.VISIBLE : View.GONE);
    refreshButton.setEnabled(!refreshing);
  }

  // ---- helpers ----

  private static String formatSol(double sol) {
    return String.format(java.util.Locale.US, "%.6f SOL", sol);
  }

  private static String formatEps(double eps) {
    return String.format(java.util.Locale.US, "%.4f EPS", eps);
  }

  /**
   * Tiny JSON double extractor — avoids pulling in org.json for one field. Returns 0.0 if the key
   * is missing or the value is not a number.
   */
  private static double parseJsonDouble(String json, String key) {
    if (json == null) return 0.0;
    String needle = "\"" + key + "\"";
    int i = json.indexOf(needle);
    if (i < 0) return 0.0;
    int colon = json.indexOf(':', i);
    if (colon < 0) return 0.0;
    int start = colon + 1;
    while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
    int end = start;
    while (end < json.length()
        && (Character.isDigit(json.charAt(end))
            || json.charAt(end) == '-'
            || json.charAt(end) == '+'
            || json.charAt(end) == '.'
            || json.charAt(end) == 'e'
            || json.charAt(end) == 'E')) {
      end++;
    }
    if (end == start) return 0.0;
    try {
      return Double.parseDouble(json.substring(start, end));
    } catch (NumberFormatException e) {
      return 0.0;
    }
  }
}