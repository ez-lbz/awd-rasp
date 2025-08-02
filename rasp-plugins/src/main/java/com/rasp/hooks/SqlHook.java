package com.rasp.hooks;

import com.alibaba.druid.wall.WallFilter;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javassist.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import com.alibaba.druid.wall.WallUtils;

public class SqlHook implements ClassFileTransformer {
    private static boolean doSqlHook = false;

    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (root.has("SqlHook") && root.get("SqlHook").isJsonObject()) {
                JsonObject sqlHook = root.getAsJsonObject("SqlHook");
                doSqlHook = sqlHook.has("doSqlHook") && sqlHook.get("doSqlHook").getAsBoolean();
            } else {
                System.out.println("No SqlHook configuration found in hook.json");
            }
        } catch (Exception e) {
            System.out.println("Error initializing SqlHook: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {
        if (doSqlHook && className.equals("com/mysql/jdbc/StatementImpl")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the SQLHook");
                CtClass clz = pool.get(loadName);
                // Hook住executeInternal、executeQuery等
                CtMethod ctMethod = clz.getDeclaredMethod("executeQuery");

                String code = "System.out.println(\"In the SQLHook \" + $1);" +
                        "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
                        "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
                        "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                        "Class hookClass = Class.forName(\"com.rasp.vulHook.SqlHook\",true, Thread.currentThread().getContextClassLoader());" +
                        "java.lang.reflect.Method checkSql = hookClass.getDeclaredMethod(\"checkSql\", new Class []{String.class});" +
                        "checkSql.invoke(hookClass.newInstance(), new Object[]{$1});";


                ctMethod.insertBefore(code);
                System.out.println("Finish the SQLHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        }else if(className.equals("com/mysql/cj/jdbc/ClientPreparedStatement")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the SQLHook");
                CtClass clz = pool.get(loadName);
                CtClass[] parameterTypes = new CtClass[] {
                        pool.get("com.mysql.cj.jdbc.JdbcConnection"),
                        pool.get("java.lang.String"),
                        pool.get("java.lang.String"),
                        pool.get("com.mysql.cj.ParseInfo")
                };
                CtConstructor ctConstructor = clz.getDeclaredConstructor(parameterTypes);


                String code = "System.out.println(\"In the SQLHook \" + $2);" +
//                        "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
//                        "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
//                        "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                        "Class hookClass = Class.forName(\"com.rasp.hooks.SqlHook\",true, com.rasp.myLoader.RaspClassLoader.getRaspClassLoader());" +
                        "java.lang.reflect.Method checkSql = hookClass.getDeclaredMethod(\"checkSql\", new Class []{String.class});" +
                        "checkSql.invoke(hookClass.newInstance(), new Object[]{$2});";
                ctConstructor.insertBefore(code);

                System.out.println("Finish the SQLHook");

                return clz.toBytecode();
            }catch (Exception e) {
                throw new RuntimeException(e);
            }
        }else {
            return classfileBuffer;
        }

    }

    public static void checkSql(String sql) throws Exception{
        boolean validate = WallUtils.isValidateMySql(sql);
        if (validate){
            return;
        }
        else{
            throw new SecurityException("SQL Injection : " + sql);
        }
    }

}
