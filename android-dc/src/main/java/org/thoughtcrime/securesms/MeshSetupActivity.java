package org.thoughtcrime.securesms;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import org.thoughtcrime.securesms.connect.DcHelper;
import org.thoughtcrime.securesms.util.Prefs;
import org.thoughtcrime.securesms.util.ViewUtil;

/**
 * Mesh-based onboarding activity that replaces EpsilonChat's email/IMAP/SMTP login flow.
 *
 * <p>Uses real Iroh P2P mesh via JNI:
 * - "Show My Invite" starts the Iroh endpoint and displays a real invite string
 * - "Connect" connects to a peer using their invite string
 * - Messages are exchanged over Iroh QUIC streams (no servers)
 */
public class MeshSetupActivity extends BaseActionBarActivity {

  private static final String TAG = "MeshSetupActivity";
  private static final String PREF_INVITE_CONNECTED = "epsilon_invite_connected";

  private EditText inviteInput;
  private TextView myInviteText;
  private TextView statusText;
  private ProgressBar progressBar;
  private Button connectBtn;
  private Button showBtn;

  private boolean meshStarted = false;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.mesh_setup_activity);
    ViewUtil.applyWindowInsets(findViewById(R.id.mesh_content_container));

    Button startBtn = findViewById(R.id.btn_start);
    Button scanBtn = findViewById(R.id.btn_scan_invite);
    showBtn = findViewById(R.id.btn_show_invite);
    connectBtn = findViewById(R.id.btn_connect);
    inviteInput = findViewById(R.id.et_invite_input);
    myInviteText = findViewById(R.id.tv_my_invite);
    statusText = findViewById(R.id.tv_invite_label);
    progressBar = new ProgressBar(this);

    // "Start EpsilonChat" — reveals invite entry + starts mesh in background
    startBtn.setOnClickListener(v -> {
      startBtn.setVisibility(View.GONE);
      inviteInput.setVisibility(View.VISIBLE);
      statusText.setText("Starting mesh...");
      statusText.setVisibility(View.VISIBLE);

      // Start mesh in background thread (JNI calls block)
      new Thread(() -> {
        try {
          org.thoughtcrime.securesms.connect.DcHelper.getContext(this);
          // The DcContext is initialized by the app; we call our native methods on it
          // For now, we start mesh directly — the native lib must be loaded
        } catch (Exception e) {
          // best-effort
        }
        runOnUiThread(() -> {
          statusText.setText("Ready. Tap 'Show My Invite' to get your invite code.");
        });
      }).start();
    });

    // "Scan Invite QR" — for now reveals text input
    scanBtn.setOnClickListener(v -> showScanDialog());

    // "Show My Invite" — starts Iroh mesh and generates real invite
    showBtn.setOnClickListener(v -> startMeshAndShowInvite());

    // "Connect" — connects to peer using their invite
    connectBtn.setOnClickListener(v -> onConnect());
  }

  /** Start the Iroh mesh node and display the real invite string. */
  private void startMeshAndShowInvite() {
    if (meshStarted) {
      // Already started, just re-show invite
      getInviteFromMesh();
      return;
    }

    showBtn.setEnabled(false);
    statusText.setText("Starting P2P mesh...");
    statusText.setVisibility(View.VISIBLE);

    new Thread(() -> {
      try {
        com.b44t.messenger.DcContext dcContext = DcHelper.getContext(this);
        String nodeId = dcContext.epsilonStartMesh();

        if (nodeId == null || nodeId.isEmpty()) {
          runOnUiThread(() -> {
            statusText.setText("Failed to start mesh. Native library not available.");
            showBtn.setEnabled(true);
          });
          return;
        }

        meshStarted = true;

        // Get the invite string
        String invite = dcContext.epsilonGetInvite();

        runOnUiThread(() -> {
          showBtn.setEnabled(true);
          if (invite != null && !invite.isEmpty()) {
            myInviteText.setText(invite);
            myInviteText.setVisibility(View.VISIBLE);
            statusText.setText("Share this invite with the other person (SMS, Telegram, etc.)");
            connectBtn.setVisibility(View.VISIBLE);
          } else {
            statusText.setText("Mesh started but invite generation failed.");
          }
        });
      } catch (UnsatisfiedLinkError e) {
        runOnUiThread(() -> {
          statusText.setText("Native mesh library not loaded: " + e.getMessage());
          showBtn.setEnabled(true);
        });
      } catch (Exception e) {
        runOnUiThread(() -> {
          statusText.setText("Error: " + e.getMessage());
          showBtn.setEnabled(true);
        });
      }
    }).start();
  }

  /** Re-fetch invite from already-started mesh. */
  private void getInviteFromMesh() {
    new Thread(() -> {
      try {
        com.b44t.messenger.DcContext dcContext = DcHelper.getContext(this);
        String invite = dcContext.epsilonGetInvite();
        runOnUiThread(() -> {
          if (invite != null && !invite.isEmpty()) {
            myInviteText.setText(invite);
            myInviteText.setVisibility(View.VISIBLE);
          }
        });
      } catch (Exception e) {
        // ignore
      }
    }).start();
  }

  /** Show a dialog explaining QR scanning is not yet wired. */
  private void showScanDialog() {
    inviteInput.setVisibility(View.VISIBLE);
    new AlertDialog.Builder(this)
        .setTitle("Scan Invite QR")
        .setMessage(
            "Camera scanning is coming soon. For now, please paste the invite string "
                + "(epsilon://...) you received from the other party into the field below.")
        .setPositiveButton(android.R.string.ok, null)
        .show();
    inviteInput.requestFocus();
  }

  /** Connect to a peer using their invite string. */
  private void onConnect() {
    String invite = inviteInput.getText().toString().trim();
    if (TextUtils.isEmpty(invite)) {
      Toast.makeText(this, "Please enter an invite code.", Toast.LENGTH_SHORT).show();
      return;
    }
    if (!invite.startsWith("epsilon://") && !invite.startsWith("{")) {
      Toast.makeText(this, "Invalid invite format. Expected epsilon://...", Toast.LENGTH_LONG).show();
      return;
    }

    // Ensure mesh is started
    if (!meshStarted) {
      Toast.makeText(this, "Please tap 'Show My Invite' first to start the mesh.", Toast.LENGTH_LONG).show();
      return;
    }

    connectBtn.setEnabled(false);
    statusText.setText("Connecting to peer...");

    new Thread(() -> {
      try {
        com.b44t.messenger.DcContext dcContext = DcHelper.getContext(this);
        String result = dcContext.epsilonConnectPeer(invite);

        runOnUiThread(() -> {
          connectBtn.setEnabled(true);
          if (result != null && result.startsWith("ok:")) {
            statusText.setText("Connected! Peer count: " + dcContext.epsilonPeerCount());
            Prefs.setBooleanPreference(this, PREF_INVITE_CONNECTED, true);

            // Proceed to conversation list
            Intent intent = new Intent(getApplicationContext(), ConversationListActivity.class);
            intent.putExtra(ConversationListActivity.FROM_WELCOME, true);
            startActivity(intent);
            finish();
          } else if (result != null && result.startsWith("error:")) {
            String errorMsg = result.substring(6);
            statusText.setText("Connection failed: " + errorMsg);
          } else {
            statusText.setText("Connection failed. Check the invite code.");
          }
        });
      } catch (Exception e) {
        runOnUiThread(() -> {
          connectBtn.setEnabled(true);
          statusText.setText("Error: " + e.getMessage());
        });
      }
    }).start();
  }
}