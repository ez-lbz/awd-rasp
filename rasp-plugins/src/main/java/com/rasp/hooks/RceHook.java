package com.rasp.hooks;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javassist.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.*;

public class RceHook implements ClassFileTransformer {
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "ping 127.0.0.1"
    ));
    private static boolean doRCEHook = false;


    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            if (root.has("RCEHook") && root.get("RCEHook").isJsonObject()) {
                JsonObject RCEHook = root.getAsJsonObject("RCEHook");

                doRCEHook = RCEHook.has("doRCEHook") && RCEHook.get("doRCEHook").getAsBoolean();
                if (doRCEHook) {
                    if (RCEHook.has("safeCommands")) {
                        ALLOWED_COMMANDS.clear();
                        for (JsonElement path : RCEHook.getAsJsonArray("safeCommands")) {
                            ALLOWED_COMMANDS.add(path.getAsString());
                        }
                        System.out.println("Safe Cmds loaded: " + ALLOWED_COMMANDS);
                    }
                }
            } else {
                System.out.println("No RCEHook configuration found in hook.json");
            }

        } catch (Exception e) {
            System.err.println("Error initializing RCEHook: " + e.getMessage());
        }
    }


    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {
        if (doRCEHook && className.endsWith("ProcessImpl")) {
            try {
                System.out.println("RCEHook is enabled for class: " + className);
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the RCEHook");
                CtClass clz = pool.get(loadName);

                CtMethod startMethod = clz.getDeclaredMethod("start",
                        new CtClass[]{
                                pool.get("java.lang.String[]"),
                                pool.get("java.util.Map"),
                                pool.get("java.lang.String"),
                                pool.get("[L" + ProcessBuilder.Redirect.class.getName().replace('.', '/') + ";"),
                                CtClass.booleanType
                        }
                );

                String code = ""
                        + "{"
                        + "System.out.println(\"In the RCEHook \" + java.util.Arrays.toString($1) + Thread.currentThread().getContextClassLoader());"
                        + "String cmd = String.join(\" \", $1);"
                        + "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"
                        + "java.lang.reflect.Method getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"
                        + "ClassLoader raspClassLoaderInstance = (ClassLoader) getRaspClassLoader.invoke(null, new Object[0]);"
                        + "Class hookClass = Class.forName(\"com.rasp.hooks.RceHook\", true, raspClassLoaderInstance);"
                        + "java.lang.reflect.Method checkCmd = hookClass.getDeclaredMethod(\"checkCmd\", new Class[]{String.class});"
                        + "checkCmd.invoke(hookClass.newInstance(), new Object[]{cmd});"
                        + "}";

                startMethod.insertBefore(code);

                System.out.println("Finish the RceHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        }
        if (doRCEHook && className.endsWith("UnixProcess")) {
            try {
                System.out.println("RCEHook is enabled for class: " + className);
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the RCEHook");
                CtClass clz = pool.get(loadName);
                CtBehavior[] ctBehaviors = clz.getDeclaredConstructors();
                for (CtBehavior cb : ctBehaviors) {
                    CtClass[] params = cb.getParameterTypes();
                    if (params.length == 0) {
                        System.out.println("  -> No parameters");
                    } else {
                        for (int i = 0; i < params.length; i++) {
                            System.out.println("  -> Param " + i + ": " + params[i].getName());
                        }
                    }

                    String code = "{"
                            + "  java.util.List<String> decode = new java.util.ArrayList<>();"
                            + "  decode.addAll(java.util.Arrays.asList(new String($1).split(\"\\u0000\")));"
                            + "  decode.addAll(java.util.Arrays.asList(new String($2).split(\"\\u0000\")));"
                            + "  String cmd = String.join(\" \", decode).trim();"
                            + "  System.out.println(\"In the RCEHook command: \" + cmd + Thread.currentThread().getContextClassLoader());"
                            + "  Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"
                            + "  java.lang.reflect.Method getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"  // 改动
                            + "  ClassLoader raspClassLoaderInstance = (ClassLoader) getRaspClassLoader.invoke(null, new Object[0]);"  // 改动
                            + "  Class hookClass = Class.forName(\"com.rasp.hooks.RceHook\", true, raspClassLoaderInstance);"
                            + "  java.lang.reflect.Method checkCmd = hookClass.getDeclaredMethod(\"checkCmd\", new Class[]{String.class});"  // 改动
                            + "  checkCmd.invoke(hookClass.newInstance(), new Object[]{cmd});"  // 改动
                            + "}";

                    cb.insertBefore(code);
                }

                System.out.println("Finish the RceHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        }
        return classfileBuffer;
    }

    public static void checkCmd(String cmd) throws Exception {
        boolean allowed = false;
        for (String allow : ALLOWED_COMMANDS) {
            if (cmd.contains(allow)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            System.out.println("RCE Attack Detected: " + cmd);
            throw new RuntimeException("RCE Attack -- RASP");
        }
    }


}
