package pro.javacard.gp;

import pro.javacard.capfile.CAPFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class CAPFileExt {

    private final CAPFile cap;
    private final byte[] bin;


    public CAPFileExt(byte[] bytes) throws IOException {
        bin = bytes.clone();
        cap = CAPFile.fromBytes(bin);
    }

    public CAPFileExt(CAPFile cap) throws IOException {
        this.cap = cap;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        cap.store(out);
        bin = out.toByteArray();
    }


    public byte[] getCode() throws IOException {
        return buildLoadFileCode(cap, bin);
    }

    public byte[] getLoadFileDataHash(String algorithm) throws IOException {
        try {
            return MessageDigest.getInstance(algorithm).digest(getCode());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm, e);
        }
    }


    private static byte[] buildLoadFileCode(CAPFile cap, byte[] capFileBytes) throws IOException {
        List<byte[]> nativeComponents = readNativeComponents(capFileBytes);
        if (nativeComponents.isEmpty()) {
            return cap.getCode();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] nativeComponent : nativeComponents) {
            out.write(nativeComponent);
        }

        byte[] standardCode = cap.getCode();
        // cap.getCode() strips the Debug component bytes but leaves the stale Debug
        // size in the Directory component. Zero it so the Directory agrees with
        // what we actually send, matching JCOP shell.
        zeroDebugSizeInDirectory(cap, standardCode);
        out.write(standardCode);
        return out.toByteArray();
    }

    private static void zeroDebugSizeInDirectory(CAPFile cap, byte[] standardCode) {
        byte[] header = cap.getComponent("Header");
        if (header == null) return;
        // Directory layout: tag(1) + length(2) + component_sizes[12] (u2 each).
        // Debug size is the 12th u2 in component_sizes.
        int debugSizeOffset = header.length + 3 + (11 * 2);
        if (standardCode.length < debugSizeOffset + 2) return;
        standardCode[debugSizeOffset] = 0;
        standardCode[debugSizeOffset + 1] = 0;
    }

    private static List<byte[]> readNativeComponents(byte[] capFileBytes) throws IOException {
        List<byte[]> components = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(capFileBytes))) {
            ZipEntry entry;
            byte[] buf = new byte[1024];
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.getName().endsWith(".capx")) continue;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int len;
                while ((len = zis.read(buf)) != -1) {
                    baos.write(buf, 0, len);
                }
                components.add(baos.toByteArray());
            }
        }
        // Order by the component tag byte so the native header (0xEF) is loaded
        // before the native text (0xE0) and rodata (0xE1) sections, matching the
        // order the JCOP loader expects.
        components.sort(Comparator.comparingInt(CAPFileExt::nativeComponentPriority));
        return components;
    }

    private static int nativeComponentPriority(byte[] component) {
        if (component.length == 0) return Integer.MAX_VALUE;
        int tag = component[0] & 0xFF;
        return tag == 0xEF ? -1 : tag;
    }

}
