# Java-based Lightweight RASP Defense Project

```


      __          _______         _____            _____ _____  
     /\ \        / |  __ \       |  __ \    /\    / ____|  __ \ 
    /  \ \  /\  / /| |  | |______| |__) |  /  \  | (___ | |__) |
   / /\ \ \/  \/ / | |  | |______|  _  /  / /\ \  \___ \|  ___/ 
  / ____ \  /\  /  | |__| |      | | \ \ / ____ \ ____) | |     
 /_/    \_\/  \/   |_____/       |_|  \_/_/    \_|_____/|_|     
                                                                
                                                                

```

## Overview

This project is a Java-developed Runtime Application Self-Protection (RASP) solution designed to provide lightweight, real-time defense directly within the application runtime. It offers effective protection against a range of common attack vectors, including:

- Unauthorized file reads
- JNDI injection
- Remote Code Execution (RCE)
- Deserialization attacks
- SPEL expression injection
- SQL injection
- Server-Side Request Forgery (SSRF)

## Advantages of RASP

Compared to traditional security tools like WAFs, RASP embeds protection inside the application, which allows for more precise attack detection and significantly reduces false positives. This minimizes disruptions in legitimate application usage and avoids the overhead of external detection mechanisms.

This project is designed to be lightweight, with a focus solely on attack interception. Unlike existing RASP tools such as OpenRASP or JRASP, it omits the web control console to reduce complexity and resource consumption. This makes it especially suitable for offline CTF competition scenarios like AWD and AWDP, where reliable, low-overhead defense is critical.

## Why Use This Tool Instead of Other WAFs?

Traditional WAFs are not invasive and typically sit outside the application, which can lead to more false positives or missed detections. In internet environments, some false positives are tolerable, but in competition scenarios, excessive false alarms or overblocking can heavily penalize scoring. This RASP tool provides a balance by embedding lightweight, accurate defense with minimal false positives, optimized for the competition environment.

## Usage

- The project is developed and tested primarily on **Java 8**, but it also supports higher Java runtime environments.
- Make sure to place the following files in the same directory:
    - `rasp-main.jar`
    - `rasp-plugins.jar`
    - `hook.json`
- To run the protected application, use the following startup command:

```bash
java -javaagent:rasp-main.jar -Xbootclasspath/a:rasp-plugins.jar -jar shiro-login-demo-1.0.0.jar
```

## License

This project is licensed under the WTFPL (Do What The Fuck You Want To Public License).

## References

- [OpenRASP by Baidu](https://github.com/baidu/openrasp)
- [TinyRASP by chenlvtang](https://github.com/chenlvtang/TinyRASP)
