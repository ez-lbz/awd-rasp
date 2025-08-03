package com.rasp.myLoader;

import com.rasp.raspMain.MyAgent;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class RaspClassLoader extends URLClassLoader {
    private static File jarFile;
    private static volatile RaspClassLoader raspClassLoader;
    public RaspClassLoader(URL[] urls) {
        super(urls);
    }

    public static RaspClassLoader getRaspClassLoader() throws Exception {
        if (raspClassLoader == null) {
            synchronized (RaspClassLoader.class) {
                if (raspClassLoader == null) {
                    raspClassLoader = new RaspClassLoader(new URL[0]);
                    ProtectionDomain protectionDomain = RaspClassLoader.class.getProtectionDomain();
                    CodeSource codeSource = protectionDomain.getCodeSource();
                    URL premainJarUrl = codeSource.getLocation();
                    String premainJarPath = String.valueOf(Paths.get(premainJarUrl.toURI()).getParent());
                    File jarUrl = new File( premainJarPath + "/rasp-plugins.jar");
                    raspClassLoader.loadJar(jarUrl);
                }
            }
        }
        return raspClassLoader;
    }


    public void loadJar(File jarFile) throws Exception {
        if (jarFile.exists()) {
            this.jarFile = jarFile;
            addURL(jarFile.toURI().toURL());
        } else {
            throw new RuntimeException("JAR file not found: " + jarFile.getAbsolutePath());
        }
    }

    public List<Object> getAllHookClasses() throws Exception {
        List<Object> result = new ArrayList<>();
        JarFile jar = new JarFile(jarFile);
        Enumeration<JarEntry> entries = jar.entries();

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name.endsWith(".class") && name.startsWith("com/rasp/hooks")) {
                String className = name.replace("/", ".").replace(".class", "");
                Class<?> loadedClass = loadClass(className);
                Object instance = loadedClass.newInstance();

                System.out.println("Loaded class: " + className);
                result.add(instance);
            }
        }

        jar.close();
        return result;
    }

}
