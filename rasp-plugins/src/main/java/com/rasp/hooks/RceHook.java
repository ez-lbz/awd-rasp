package com.rasp.hooks;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtBehavior;
import javassist.CtClass;

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
                        System.out.println("Danger Cmds loaded: " + ALLOWED_COMMANDS);
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
        if (doRCEHook && className.endsWith("ProcessImpl")||className.endsWith("UnixProcess")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the RCEHook");
                CtClass clz = pool.get(loadName);
                // Hook住init方法
                CtBehavior[] ctBehaviors = clz.getDeclaredConstructors();
                for(CtBehavior cb: ctBehaviors) {
                    // 插入检测函数
                    String code = "System.out.println(\"In the RCEHook \" + $1 + Thread.currentThread().getContextClassLoader());" +
                            // 获取参数
                            "String _ = String.join(\" \", $1);" +
                            // 通过反射动态加载 RaspClassLoader, 因为ProcessImpl由BootStarpClassLoader加载，没办法直接调用RaspClassLoader
                            "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
                            "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
                            "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                            "Class hookClass = Class.forName(\"com.rasp.hooks.RceHook\",true, raspClassLoaderInstance);"+
                            "java.lang.reflect.Method checkCmd = hookClass.getDeclaredMethod(\"checkCmd\", new Class []{String.class});" +
                            "checkCmd.invoke(hookClass.newInstance(), new Object[]{_});";
                    cb.insertBefore(code);
                }

                System.out.println("Finish the RceHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        } else {
            return classfileBuffer;
        }
    }

    public static void checkCmd(String cmd) throws Exception {
        if (!ALLOWED_COMMANDS.contains(cmd)){
            throw new RuntimeException("RCE Attack -- RASP");
        }
    }

}
