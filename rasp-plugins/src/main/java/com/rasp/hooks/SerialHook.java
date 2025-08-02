package com.rasp.hooks;

import com.google.gson.JsonElement;
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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SerialHook implements ClassFileTransformer {
    private static final Set<String> BlackClassSet = new HashSet<>(Arrays.asList(
            "org.springframework.transaction.support.AbstractPlatformTransactionManager",
            "java.rmi.server.UnicastRemoteObject",
            "java.rmi.server.RemoteObjectInvocationHandler",
            "com.bea.core.repackaged.springframework.transaction.support.AbstractPlatformTransactionManager",
            "java.rmi.server.RemoteObject",
            "com.tangosol.coherence.rest.util.extractor.MvelExtractor",
            "java.lang.Runtime",
            "oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor",
            "org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor",
            "org.eclipse.persistence.internal.descriptors.InstanceVariableAttributeAccessor",
            "org.apache.commons.fileupload.disk.DiskFileItem",
            "oracle.jdbc.pool.OraclePooledConnection",
            "com.tangosol.util.extractor.ReflectionExtractor",
            "com.tangosol.internal.util.SimpleBinaryEntry",
            "com.tangosol.coherence.component.util.daemon.queueProcessor.service.grid.partitionedService.PartitionedCache$Storage$BinaryEntry",
            "com.sun.rowset.JdbcRowSetImpl",
            "org.eclipse.persistence.internal.indirection.ProxyIndirectionHandler",
            "bsh.XThis",
            "bsh.Interpreter",
            "com.mchange.v2.c3p0.PoolBackedDataSource",
            "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
            "org.apache.commons.beanutils.BeanComparator",
            "java.lang.reflect.Proxy",
            "clojure.lang.PersistentArrayMap",
            "org.apache.commons.io.output.DeferredFileOutputStream",
            "org.apache.commons.io.output.ThresholdingOutputStream",
            "org.apache.wicket.util.upload.DiskFileItem",
            "org.apache.wicket.util.io.DeferredFileOutputStream",
            "org.apache.wicket.util.io.ThresholdingOutputStream",
            "com.sun.org.apache.bcel.internal.util.ClassLoader",
            "com.sun.syndication.feed.impl.ObjectBean",
            "org.springframework.beans.factory.ObjectFactory",
            "org.springframework.aop.framework.AdvisedSupport",
            "org.springframework.aop.target.SingletonTargetSource",
            "com.vaadin.data.util.NestedMethodProperty",
            "com.vaadin.data.util.PropertysetItem",
            "javax.management.BadAttributeValueExpException",
            "org.apache.myfaces.context.servlet.FacesContextImpl",
            "org.apache.myfaces.context.servlet.FacesContextImplBase",
            "org.apache.commons.collections.functors.InvokerTransformer",
            "org.apache.commons.collections.functors.InstantiateTransformer",
            "org.apache.commons.collections4.functors.InvokerTransformer",
            "org.apache.commons.collections4.functors.InstantiateTransformer",
            "java.lang.ProcessBuilder",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "java.security.SignedObject",
            "com.sun.jndi.ldap.LdapAttribute",
            "javax.naming.InitialContext",
            "org.springframework.aop.framework.JdkDynamicAopProxy",
            "org.springframework.aop.aspectj",
            "org.apache.xbean.naming.context",
            "JSONArray",
            "POJONode",
            "ToStringBean",
            "EqualsBean",
            "ProxyLazyValue",
            "SwingLazyValue",
            "UIDefaults",
            "XString",
            "org.springframework.cache.interceptor.BeanFactoryCacheOperationSourceAdvisor",
            "org.springframework.aop.aspectj.AspectInstanceFactory",
            "org.slf4j",
            "groovy",
            "sun.print.UnixPrintService"
    ));

    private static boolean doSerialHook = false;
    private static String serialHookClassName = "";

    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("hook.json")), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            if (root.has("SerialHook") && root.get("SerialHook").isJsonObject()) {
                JsonObject SerialHook = root.getAsJsonObject("SerialHook");

                doSerialHook = SerialHook.has("doSerialHook") && SerialHook.get("doSerialHook").getAsBoolean();
                if (doSerialHook) {
                    if (SerialHook.has("dangerClasses")) {
                        BlackClassSet.clear();
                        for (JsonElement path : SerialHook.getAsJsonArray("dangerClasses")) {
                            BlackClassSet.add(path.getAsString());
                        }
                        System.out.println("Danger SerialClasses loaded: " + BlackClassSet);
                    }
                    if (SerialHook.has("serialClassName") && !SerialHook.get("serialClassName").getAsString().isEmpty()) {
                        serialHookClassName = SerialHook.get("serialClassName").getAsString();
                        System.out.println("SerialHook class name set to: " + serialHookClassName);
                    } else {
                        System.out.println("No serialClassName specified in SerialHook configuration");
                    }
                }
            } else {
                System.out.println("No SerialHook configuration found in hook.json");
            }

        } catch (Exception e) {
            System.err.println("Error initializing SpELHook: " + e.getMessage());
        }
    }




    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {

        if (doSerialHook && (className.equals("java/io/ObjectInputStream") || className.equals(serialHookClassName))) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the SerialHook");
                CtClass clz = pool.get(loadName);
                CtMethod ctMethod = clz.getDeclaredMethod("resolveClass");

                String code = "System.out.println(\"In the SerialHook \" + $1);" +
                        "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
                        "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
                        "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                        "Class hookClass = Class.forName(\"com.rasp.hooks.SerialHook\",true, Thread.currentThread().getContextClassLoader());" +
                        "java.lang.reflect.Method checkName = hookClass.getDeclaredMethod(\"checkName\", new Class []{String.class});" +
                        "checkName.invoke(hookClass.newInstance(), new Object[]{$1.getName()});"
                        ;

                ctMethod.insertBefore(code);
                System.out.println("Finish the SerialHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        } else if (doSerialHook && className.equals("com/caucho/hessian/io/SerializerFactory")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the SerialHook");
                CtClass clz = pool.get(loadName);
                CtMethod ctMethod = clz.getDeclaredMethod("getDeserializer", new CtClass[]{pool.get("java.lang.String")});

                String code = "System.out.println(\"In the SerialHook \" + $1);" +
                        "Class raspClassLoaderClass = Class.forName(\"com.rasp.myLoader.RaspClassLoader\", true, Thread.currentThread().getContextClassLoader());"+
                        "java.lang.reflect.Method  getRaspClassLoader = raspClassLoaderClass.getMethod(\"getRaspClassLoader\", new Class[0]);"+
                        "ClassLoader raspClassLoaderInstance = getRaspClassLoader.invoke(null, new Object[0]);"+

                        "Class hookClass = Class.forName(\"com.rasp.hooks.SerialHook\",true, Thread.currentThread().getContextClassLoader());" +
                        "java.lang.reflect.Method checkName = hookClass.getDeclaredMethod(\"checkName\", new Class []{String.class});" +
                        "checkName.invoke(hookClass.newInstance(), new Object[]{$1});"
                        ;
                ctMethod.insertBefore(code);
                System.out.println("Finish the SerialHook");
                return clz.toBytecode();
            } catch (Exception e) {
                System.out.println(e);
                throw new RuntimeException(e);
            }
        } else {
            return classfileBuffer;
        }
    }


    public static void checkName(String name) throws Exception {
        for (String black : BlackClassSet) {
            if (name.contains(black)) {
                throw new SecurityException("Illegal Deserialization Class: " + name);
            }
        }
    }

}