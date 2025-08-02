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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SpELHook implements ClassFileTransformer {
    private static Set<String> spelBlackList = new HashSet<>(Arrays.asList(
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "javax.script.ScriptEngineManager",
            "java.net.URLClassLoader",
            "java.lang.ClassLoader",
            "org.springframework.expression.Expression",
            "org.thymeleaf.context.AbstractEngineContext",
            "com.sun.org.apache.bcel.internal.util.JavaWrapper",
            "java.lang.System",
            "org.springframework.cglib.core.ReflectUtils",
            "java.io.File",
            "javax.management.remote.rmi.RMIConnector",
            "java.io.FileInputStream"
    ));

    private static boolean doSpELHook = false;

    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            if (root.has("SpELHook") && root.get("SpELHook").isJsonObject()) {
                JsonObject SpELHook = root.getAsJsonObject("SpELHook");

                doSpELHook = SpELHook.has("doSpELHook") && SpELHook.get("doSpELHook").getAsBoolean();
                if (doSpELHook) {
                    if (SpELHook.has("dangerSpELs")) {
                        spelBlackList.clear();
                        for (JsonElement path : SpELHook.getAsJsonArray("dangerSpELs")) {
                            spelBlackList.add(path.getAsString());
                        }
                        System.out.println("Danger SpELs loaded: " + spelBlackList);
                    }
                }
            } else {
                System.out.println("No SpELHook configuration found in hook.json");
            }

        } catch (Exception e) {
            System.err.println("Error initializing SpELHook: " + e.getMessage());
        }
    }


    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {
        if (doSpELHook && className.equals("org/springframework/expression/common/TemplateAwareExpressionParser")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);
                pool.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));

                System.out.println("Into the SpELHook");
                CtClass clz = pool.get(loadName);
                CtMethod ctMethod = clz.getDeclaredMethod("parseExpression");

                String code = "System.out.println(\"In the SpELHook \" + $1);" +
                        "Class hookClass = Class.forName(\"com.rasp.hooks.SpELHook\",true, com.rasp.myLoader.RaspClassLoader.getRaspClassLoader());" +
                        "java.lang.reflect.Method checkSpEL = hookClass.getDeclaredMethod(\"checkSpEL\", new Class []{String.class});" +
                        "checkSpEL.invoke(hookClass.newInstance(), new Object[]{$1});";


                ctMethod.insertBefore(code);
                System.out.println("Finish the SpELHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        } else {
            return classfileBuffer;
        }
    }

    public static void checkSpEL(String expression) throws Exception {
        for (String item : spelBlackList) {
            if (expression.contains(item)) {
                throw new SecurityException("illegal expression" + expression);
            }
        }
    }
}
