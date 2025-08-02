package com.rasp.hooks;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.ProtectionDomain;

public class JNDIHook implements ClassFileTransformer {
    // 协议黑名单
    private static String[] dangerProtocol = new String[]{"ldap://", "rmi://", "ldaps://"};
    private static boolean doJNDIHook = false;

    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (root.has("JNDIHook") && root.get("JNDIHook").isJsonObject()) {
                JsonObject jndiHook = root.getAsJsonObject("JNDIHook");
                doJNDIHook = jndiHook.has("doJNDIHook") && jndiHook.get("doJNDIHook").getAsBoolean();
            } else {
                System.out.println("No JNDIHook configuration found in hook.json");
            }
        } catch (Exception e) {
            System.out.println("Error initializing JNDIHook: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {

        if (doJNDIHook && className.equals("javax/naming/InitialContext")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the JNDIHook");
                CtClass clz = pool.get(loadName);
                CtMethod ctMethod = clz.getDeclaredMethod("lookup");

                String code = "System.out.println(\"In the JNDIHook \" + $1);" +
                        "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
                        "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
                        "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                        "Class hookClass = Class.forName(\"com.rasp.hooks.JNDIHook\",true, raspClassLoaderInstance);" +
                        "java.lang.reflect.Method checkProtocol = hookClass.getDeclaredMethod(\"checkProtocol\", new Class []{String.class});" +
                        "checkProtocol.invoke(hookClass.newInstance(), new Object[]{$1});"
                        ;

                ctMethod.insertBefore(code);
                System.out.println("Finish the JNDIHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        } else {
            return classfileBuffer;
        }
    }


    public static void checkProtocol(String url) throws Exception{
        for (String item : dangerProtocol) {
            if (url.contains(item)) {
                throw new SecurityException("JNDI Injection");
            }
        }
    }
}

