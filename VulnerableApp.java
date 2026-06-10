import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Scanner;

/**
 * Demo application intentionally containing a vulnerability pattern
 * aligned with a CISA KEV (e.g., Log4Shell - CVE-2021-44228).
 *
 * DO NOT use in production.
 */
public class VulnerableApp {

    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter your username:");
        String userInput = scanner.nextLine();

        // ❌ Vulnerable pattern:
        // Logging unsanitized user input (Log4j <= 2.14.1)
        // can trigger JNDI lookups (Log4Shell / KEV vulnerability)
        logger.info("User logged in: " + userInput);

        System.out.println("Hello, " + userInput);
    }
}