package com.rasp.hooks;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javassist.*;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class FileHook implements ClassFileTransformer {
    private static final Set<String> ALLOWED_FILE_EXTENSIONS = new HashSet<>(Arrays.asList("css", "jpg"));
    private static String[] travelPath = new String[]{"../", "..\\", ".."};
    private static Set<String> dangerPathList = new HashSet<String>(Arrays.asList(
            "/etc/passwd",
            "/etc/shadow",
            "/root/",
            "/proc/",
            "/run/secrets/",
            "/var/lib/secret",
            "/etc/ssl/private/",
            System.getProperty("user.home") + "/.ssh/",
            "/f",
            "C:\\\\Windows\\\\System32\\\\config\\\\SAM",
            "C:\\\\Windows\\\\System32\\\\config\\\\SYSTEM",
            "C:\\\\Users\\\\.*\\\\.ssh\\\\",
            "C:\\\\ProgramData\\\\Docker\\\\secrets\\\\"
    ));

    private static boolean doFileHook = false;

    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            if (root.has("FileHook") && root.get("FileHook").isJsonObject()) {
                JsonObject fileHook = root.getAsJsonObject("FileHook");

                doFileHook = fileHook.has("doFileHook") && fileHook.get("doFileHook").getAsBoolean();
                if (doFileHook) {
                    if (fileHook.has("dangerPaths")) {
                        dangerPathList.clear();
                        for (JsonElement path : fileHook.getAsJsonArray("dangerPaths")) {
                            dangerPathList.add(path.getAsString());
                        }
                        System.out.println("Danger paths loaded: " + dangerPathList);
                    }

                    if (fileHook.has("allowedExtensions")) {
                        ALLOWED_FILE_EXTENSIONS.clear();
                        for (JsonElement ext : fileHook.getAsJsonArray("allowedExtensions")) {
                            ALLOWED_FILE_EXTENSIONS.add(ext.getAsString());
                        }
                        System.out.println("Allowed extensions loaded: " + ALLOWED_FILE_EXTENSIONS);
                    }
                }
            } else {
                System.out.println("No FileHook configuration found in hook.json");
            }

        } catch (Exception e) {
            System.err.println("Error initializing FileHook: " + e.getMessage());
        }
    }


    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (doFileHook && className.equals("java/io/FileInputStream")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the FileHook");
                CtClass clz = pool.get(loadName);

                CtBehavior[] ctBehaviors = clz.getDeclaredConstructors();
                for (CtBehavior cb : ctBehaviors) {
                    CtClass[] parameterTypes = cb.getParameterTypes();
                    if (parameterTypes != null && parameterTypes.length == 1 && parameterTypes[0].getName().equals("java.io.File")) {
                        String code = "System.out.println(\"In the FileHook \" + $1);" +
                                "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());" +
                                "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);" +
                                "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);" +

                                "Class hookClass = Class.forName(\"com.rasp.hooks.FileHook\",true, raspClassLoaderInstance);" +
                                "java.lang.reflect.Method checkFilePathMethod = hookClass.getDeclaredMethod(\"checkFilePath\", new Class []{(java.io.File).class});" +
                                "checkFilePathMethod.invoke(hookClass.newInstance(), new Object[]{$1});";
                        cb.insertBefore(code);
                    }
                }
                System.out.println("Finish the FileHook");

                return clz.toBytecode();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return classfileBuffer;
    }


    public static void checkFilePath(String filePath) throws Exception {
        if (filePath == null) {
            return;
        }
        if (isPathTraversal(filePath)) {
            throw new SecurityException("PathTraversal is not allowed: " + filePath);
        }
        if (isDangerPath(filePath)) {
            throw new SecurityException("DangerPath is not allowed: " + filePath);
        }

    }

    public static void checkFilePath(File file) throws Exception {
        String filePath = file.getPath();
        checkFilePath(filePath);
    }

    public static boolean isPathTraversal(String filePath) {
        for (String item : travelPath) {
            if (filePath.contains(item)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isDangerPath(String filePath) {
        File file = new File(filePath);
        String realpath = "";
        try {
            realpath = file.getCanonicalPath();
        } catch (IOException e) {
            realpath = file.getAbsolutePath();
        }
        if (realpath.contains("flag")) {
            return true;
        }
        for (String dangerPath : dangerPathList) {
            if (realpath.startsWith(dangerPath)) {
                return true;
            }
        }
        return false;
    }

}