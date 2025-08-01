package com.rasp.raspMain;

import com.rasp.myLoader.RaspClassLoader;


import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.List;


public class MyAgent {
    public static void premain(String args, Instrumentation ins) throws Exception {
        System.out.println("\n" +
                "\n" +
                "      __          _______         _____            _____ _____  \n" +
                "     /\\ \\        / |  __ \\       |  __ \\    /\\    / ____|  __ \\ \n" +
                "    /  \\ \\  /\\  / /| |  | |______| |__) |  /  \\  | (___ | |__) |\n" +
                "   / /\\ \\ \\/  \\/ / | |  | |______|  _  /  / /\\ \\  \\___ \\|  ___/ \n" +
                "  / ____ \\  /\\  /  | |__| |      | | \\ \\ / ____ \\ ____) | |     \n" +
                " /_/    \\_\\/  \\/   |_____/       |_|  \\_/_/    \\_|_____/|_|     \n" +
                "                                                                \n" +
                "                                                                \n" +
                "\n");

        List<Object> hooks = RaspClassLoader.getRaspClassLoader().getAllHookClasses();

        for (Object hook : hooks) {
            ins.addTransformer((ClassFileTransformer) hook, true);
        }


        Class[] allLoadedClasses = ins.getAllLoadedClasses();
        for (Class aClass : allLoadedClasses) {
            if (ins.isModifiableClass(aClass) && !aClass.getName().startsWith("java.lang.invoke.LambdaForm")){
                ins.retransformClasses(new Class[]{aClass});
            }
        }
        System.out.println("======Premain Finish=======");
    }
}
