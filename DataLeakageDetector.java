import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

/**
 * Data Leakage Detection System
 * Main class for detecting sensitive data in files and text
 */
public class DataLeakageDetector {
    
    // Static patterns for different types of sensitive data
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = new HashMap<>();
    private final List<LeakageRule> rules = new ArrayList<>();
    private final List<DetectionResult> detectionResults = new ArrayList<>();
    
    // Initialize all detection patterns
    static {
        SENSITIVE_PATTERNS.put("SSN", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));
        SENSITIVE_PATTERNS.put("Credit Card", Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"));
        SENSITIVE_PATTERNS.put("Email", Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"));
        SENSITIVE_PATTERNS.put("Phone", Pattern.compile("\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b"));
        SENSITIVE_PATTERNS.put("API Key", Pattern.compile("(?i)api[_-]?key[\\s][:=][\\s]['\"]?([a-zA-Z0-9]{32,})['\"]?"));
        SENSITIVE_PATTERNS.put("Password", Pattern.compile("(?i)password[\\s][:=][\\s]['\"]?([^\\s'\"]{8,})['\"]?"));
        SENSITIVE_PATTERNS.put("IP Address", Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"));
    }
    
    /**
     * Main entry point of the application
     */
    public static void main(String[] args) {
        System.out.println("Starting Data Leakage Detection System...");
        
        DataLeakageDetector detector = new DataLeakageDetector();
        detector.initializeRules();
        
        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        
        while (running) {
            try {
                System.out.println("\n" + "=".repeat(50));
                System.out.println("   DATA LEAKAGE DETECTION SYSTEM");
                System.out.println("=".repeat(50));
                System.out.println("1. Scan File/Directory");
                System.out.println("2. Analyze Text Content");
                System.out.println("3. Monitor Network Logs");
                System.out.println("4. View Detection Results");
                System.out.println("5. Generate Report");
                System.out.println("6. Add Custom Rule");
                System.out.println("7. Clear Results");
                System.out.println("8. Test Sample Data");
                System.out.println("9. Exit");
                System.out.println("-".repeat(50));
                System.out.print("Choose an option (1-9): ");
                
                int choice = scanner.nextInt();
                scanner.nextLine(); // consume newline
                
                switch (choice) {
                    case 1:
                        detector.handleFileScan(scanner);
                        break;
                    case 2:
                        detector.handleTextAnalysis(scanner);
                        break;
                    case 3:
                        detector.handleNetworkLogAnalysis(scanner);
                        break;
                    case 4:
                        detector.displayResults();
                        break;
                    case 5:
                        detector.generateReport();
                        break;
                    case 6:
                        detector.addCustomRule(scanner);
                        break;
                    case 7:
                        detector.clearResults();
                        break;
                    case 8:
                        detector.testSampleData();
                        break;
                    case 9:
                        System.out.println("Exiting Data Leakage Detection System...");
                        running = false;
                        break;
                    default:
                        System.out.println("❌ Invalid option! Please choose 1-9.");
                }
            } catch (InputMismatchException e) {
                System.out.println("❌ Invalid input! Please enter a number.");
                scanner.nextLine(); // consume invalid input
            } catch (Exception e) {
                System.out.println("❌ Error: " + e.getMessage());
            }
        }
        
        scanner.close();
        System.out.println("Thank you for using Data Leakage Detection System!");
    }
    
    /**
     * Initialize detection rules with severity levels
     */
    private void initializeRules() {
        rules.add(new LeakageRule("HIGH", "SSN Detection", "Social Security Numbers found"));
        rules.add(new LeakageRule("HIGH", "Credit Card Detection", "Credit card numbers detected"));
        rules.add(new LeakageRule("MEDIUM", "Email Detection", "Email addresses found"));
        rules.add(new LeakageRule("HIGH", "API Key Detection", "API keys detected"));
        rules.add(new LeakageRule("HIGH", "Password Detection", "Passwords detected"));
        rules.add(new LeakageRule("LOW", "Phone Detection", "Phone numbers found"));
        rules.add(new LeakageRule("MEDIUM", "IP Address Detection", "IP addresses detected"));
    }
    
    /**
     * Handle file scanning user input
     */
    private void handleFileScan(Scanner scanner) {
        System.out.print("Enter file or directory path: ");
        String path = scanner.nextLine().trim();
        
        if (path.isEmpty()) {
            System.out.println("❌ Path cannot be empty!");
            return;
        }
        
        System.out.println("🔍 Scanning: " + path);
        scanPath(path);
    }
    
    /**
     * Handle text analysis user input
     */
    private void handleTextAnalysis(Scanner scanner) {
        System.out.println("Enter text to analyze (type 'END' on a new line to finish):");
        StringBuilder textBuilder = new StringBuilder();
        String line;
        
        while (!(line = scanner.nextLine()).equals("END")) {
            textBuilder.append(line).append("\n");
        }
        
        String text = textBuilder.toString().trim();
        if (text.isEmpty()) {
            System.out.println("❌ No text provided!");
            return;
        }
        
        System.out.println("🔍 Analyzing provided text...");
        analyzeText(text, "User Input");
    }
    
    /**
     * Handle network log analysis
     */
    private void handleNetworkLogAnalysis(Scanner scanner) {
        System.out.print("Enter network log file path: ");
        String logPath = scanner.nextLine().trim();
        
        if (logPath.isEmpty()) {
            System.out.println("❌ Path cannot be empty!");
            return;
        }
        
        System.out.println("🔍 Analyzing network logs: " + logPath);
        analyzeNetworkLogs(logPath);
    }
    
    /**
     * Scan a file or directory for sensitive data
     */
    public void scanPath(String pathStr) {
        Path path = Paths.get(pathStr);
        
        if (!Files.exists(path)) {
            System.out.println("❌ Path does not exist: " + pathStr);
            return;
        }
        
        try {
            if (Files.isDirectory(path)) {
                System.out.println("📁 Scanning directory recursively...");
                long fileCount = Files.walk(path)
                     .filter(Files::isRegularFile)
                     .filter(this::isTextFile)
                     .peek(this::scanFile)
                     .count();
                System.out.println("✅ Scanned " + fileCount + " files.");
            } else {
                scanFile(path);
                System.out.println("✅ File scan complete.");
            }
        } catch (IOException e) {
            System.out.println("❌ Error scanning path: " + e.getMessage());
        }
    }
    
    /**
     * Scan individual file
     */
    private void scanFile(Path filePath) {
        try {
            String content = Files.readString(filePath);
            analyzeText(content, filePath.toString());
            System.out.println("📄 Scanned: " + filePath.getFileName());
        } catch (IOException e) {
            System.out.println("⚠  Could not read file " + filePath + ": " + e.getMessage());
        }
    }
    
    /**
     * Check if file is a text file we can analyze
     */
    private boolean isTextFile(Path path) {
        String fileName = path.getFileName().toString().toLowerCase();
        return fileName.endsWith(".txt") || fileName.endsWith(".java") || 
               fileName.endsWith(".py") || fileName.endsWith(".js") ||
               fileName.endsWith(".json") || fileName.endsWith(".xml") ||
               fileName.endsWith(".csv") || fileName.endsWith(".log") ||
               fileName.endsWith(".properties") || fileName.endsWith(".yml") ||
               fileName.endsWith(".yaml") || fileName.endsWith(".sql");
    }
    
    /**
     * Analyze text content for sensitive data
     */
    public void analyzeText(String content, String source) {
        int initialCount = detectionResults.size();
        
        for (Map.Entry<String, Pattern> entry : SENSITIVE_PATTERNS.entrySet()) {
            String patternName = entry.getKey();
            Pattern pattern = entry.getValue();
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                String match = matcher.group();
                DetectionResult result = new DetectionResult(
                    patternName,
                    match,
                    source,
                    LocalDateTime.now(),
                    getSeverity(patternName),
                    getContext(content, matcher.start(), matcher.end())
                );
                detectionResults.add(result);
                
                // Immediate alert
                System.out.println("🚨 LEAK DETECTED: " + patternName + " in " + getShortSource(source));
                System.out.println("   Match: " + maskSensitiveData(match));
                System.out.println("   Severity: " + getSeverityIcon(result.getSeverity()) + " " + result.getSeverity());
                System.out.println();
            }
        }
        
        int newDetections = detectionResults.size() - initialCount;
        if (newDetections == 0) {
            System.out.println("✅ No sensitive data detected in " + getShortSource(source));
        }
    }
    
    /**
     * Get short version of source path for display
     */
    private String getShortSource(String source) {
        if (source.length() > 50) {
            return "..." + source.substring(source.length() - 47);
        }
        return source;
    }
    
    /**
     * Get severity icon
     */
    private String getSeverityIcon(String severity) {
        switch (severity) {
            case "HIGH": return "🔴";
            case "MEDIUM": return "🟡";
            case "LOW": return "🟢";
            default: return "⚪";
        }
    }
    
    /**
     * Determine severity level based on data type
     */
    private String getSeverity(String patternName) {
        switch (patternName) {
            case "SSN":
            case "Credit Card":
            case "API Key":
            case "Password":
                return "HIGH";
            case "Email":
            case "IP Address":
                return "MEDIUM";
            default:
                return "LOW";
        }
    }
    
    /**
     * Extract context around the match
     */
    private String getContext(String content, int start, int end) {
        int contextStart = Math.max(0, start - 50);
        int contextEnd = Math.min(content.length(), end + 50);
        return content.substring(contextStart, contextEnd).replaceAll("\\s+", " ");
    }
    
    /**
     * Mask sensitive data for safe display
     */
    private String maskSensitiveData(String data) {
        if (data.length() <= 4) {
            return "*".repeat(data.length());
        }
        return data.substring(0, 2) + "*".repeat(data.length() - 4) + data.substring(data.length() - 2);
    }
    
    /**
     * Analyze network logs for data leaks
     */
    public void analyzeNetworkLogs(String logPath) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(logPath));
            int leakCount = 0;
            
            for (String line : lines) {
                if (line.toLowerCase().contains("password") || 
                    line.toLowerCase().contains("ssn") ||
                    line.toLowerCase().contains("credit")) {
                    
                    DetectionResult result = new DetectionResult(
                        "Network Leak",
                        "Sensitive data in network traffic",
                        logPath,
                        LocalDateTime.now(),
                        "HIGH",
                        line.length() > 100 ? line.substring(0, 100) + "..." : line
                    );
                    detectionResults.add(result);
                    leakCount++;
                    
                    System.out.println("🚨 NETWORK LEAK DETECTED in: " + getShortSource(logPath));
                    System.out.println("   Context: " + (line.length() > 80 ? line.substring(0, 80) + "..." : line));
                }
            }
            
            if (leakCount == 0) {
                System.out.println("✅ No network leaks detected in log file.");
            } else {
                System.out.println("⚠  Found " + leakCount + " potential network leaks!");
            }
            
        } catch (IOException e) {
            System.out.println("❌ Error reading network logs: " + e.getMessage());
        }
    }
    
    /**
     * Display all detection results
     */
    public void displayResults() {
        if (detectionResults.isEmpty()) {
            System.out.println("✅ No data leakages detected yet.");
            System.out.println("💡 Try scanning some files or analyzing text content.");
            return;
        }
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("                 DETECTION RESULTS");
        System.out.println("=".repeat(60));
        
        Map<String, Long> severityCount = new HashMap<>();
        Map<String, Long> typeCount = new HashMap<>();
        
        for (int i = 0; i < detectionResults.size(); i++) {
            DetectionResult result = detectionResults.get(i);
            System.out.println((i + 1) + ". " + result);
            System.out.println();
            
            severityCount.merge(result.getSeverity(), 1L, Long::sum);
            typeCount.merge(result.getType(), 1L, Long::sum);
        }
        
        System.out.println("=".repeat(60));
        System.out.println("                    SUMMARY");
        System.out.println("=".repeat(60));
        System.out.println("📊 Total detections: " + detectionResults.size());
        
        System.out.println("\n🎯 By Severity:");
        severityCount.entrySet().stream()
            .sorted((e1, e2) -> getSeverityOrder(e2.getKey()) - getSeverityOrder(e1.getKey()))
            .forEach(entry -> System.out.println("   " + getSeverityIcon(entry.getKey()) + 
                    " " + entry.getKey() + ": " + entry.getValue()));
        
        System.out.println("\n📋 By Type:");
        typeCount.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .forEach(entry -> System.out.println("   • " + entry.getKey() + ": " + entry.getValue()));
    }
    
    /**
     * Get severity order for sorting
     */
    private int getSeverityOrder(String severity) {
        switch (severity) {
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }
    
    /**
     * Generate detailed report file
     */
    public void generateReport() {
        if (detectionResults.isEmpty()) {
            System.out.println("❌ No detection results to report.");
            return;
        }
        
        try {
            String reportFileName = "leak_detection_report_" + 
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".txt";
            
            try (PrintWriter writer = new PrintWriter(new FileWriter(reportFileName))) {
                writer.println("DATA LEAKAGE DETECTION REPORT");
                writer.println("Generated: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                writer.println("=" + "=".repeat(70));
                writer.println();
                
                Map<String, Long> severityCount = new HashMap<>();
                Map<String, Long> typeCount = new HashMap<>();
                
                for (int i = 0; i < detectionResults.size(); i++) {
                    DetectionResult result = detectionResults.get(i);
                    writer.println((i + 1) + ". " + result.toDetailedString());
                    writer.println();
                    severityCount.merge(result.getSeverity(), 1L, Long::sum);
                    typeCount.merge(result.getType(), 1L, Long::sum);
                }
                
                writer.println("\nSUMMARY");
                writer.println("========");
                writer.println("Total detections: " + detectionResults.size());
                
                writer.println("\nBy Severity:");
                severityCount.forEach((severity, count) -> 
                    writer.println("  " + severity + ": " + count));
                
                writer.println("\nBy Type:");
                typeCount.forEach((type, count) -> 
                    writer.println("  " + type + ": " + count));
                
                writer.println("\nRECOMMENDATIONS");
                writer.println("===============");
                if (severityCount.getOrDefault("HIGH", 0L) > 0) {
                    writer.println("- URGENT: Address HIGH severity issues immediately");
                    writer.println("- Remove or encrypt sensitive data found in files");
                    writer.println("- Review access controls for affected files");
                }
                if (severityCount.getOrDefault("MEDIUM", 0L) > 0) {
                    writer.println("- Review MEDIUM severity items for potential risks");
                    writer.println("- Consider data classification policies");
                }
                writer.println("- Implement regular scanning procedures");
                writer.println("- Train developers on secure coding practices");
            }
            
            System.out.println("📄 Report generated successfully: " + reportFileName);
            
        } catch (IOException e) {
            System.out.println("❌ Error generating report: " + e.getMessage());
        }
    }
    
    /**
     * Add custom detection rule
     */
    private void addCustomRule(Scanner scanner) {
        System.out.print("Enter rule name: ");
        String name = scanner.nextLine().trim();
        
        if (name.isEmpty()) {
            System.out.println("❌ Rule name cannot be empty!");
            return;
        }
        
        System.out.print("Enter regex pattern: ");
        String pattern = scanner.nextLine().trim();
        
        if (pattern.isEmpty()) {
            System.out.println("❌ Pattern cannot be empty!");
            return;
        }
        
        System.out.print("Enter severity (HIGH/MEDIUM/LOW): ");
        String severity = scanner.nextLine().trim().toUpperCase();
        
        if (!severity.matches("HIGH|MEDIUM|LOW")) {
            System.out.println("❌ Severity must be HIGH, MEDIUM, or LOW!");
            return;
        }
        
        try {
            Pattern compiledPattern = Pattern.compile(pattern);
            SENSITIVE_PATTERNS.put(name, compiledPattern);
            rules.add(new LeakageRule(severity, name, "Custom rule: " + name));
            System.out.println("✅ Custom rule '" + name + "' added successfully!");
        } catch (Exception e) {
            System.out.println("❌ Error adding custom rule: " + e.getMessage());
        }
    }
    
    /**
     * Clear all detection results
     */
    private void clearResults() {
        detectionResults.clear();
        System.out.println("✅ All detection results cleared.");
    }
    
    /**
     * Test the system with sample data
     */
    private void testSampleData() {
        System.out.println("🧪 Testing system with sample sensitive data...");
        
        String testData = "Configuration file:\n" +
                         "database_password=secretpass123\n" +
                         "admin_email=admin@company.com\n" +
                         "employee_ssn=123-45-6789\n" +
                         "backup_server=192.168.1.100\n" +
                         "contact_phone=555-123-4567\n" +
                         "api_key=sk_live_51234567890abcdef1234567890abcdef\n" +
                         "credit_card_test=4532-1234-5678-9012";
        
        analyzeText(testData, "Sample Test Data");
        System.out.println("✅ Sample data test complete!");
    }
}

/**
 * Detection Result class to store information about found leaks
 */
class DetectionResult {
    private String type;
    private String match;
    private String source;
    private LocalDateTime timestamp;
    private String severity;
    private String context;
    
    public DetectionResult(String type, String match, String source, 
                          LocalDateTime timestamp, String severity, String context) {
        this.type = type;
        this.match = match;
        this.source = source;
        this.timestamp = timestamp;
        this.severity = severity;
        this.context = context;
    }
    
    // Getters
    public String getType() { return type; }
    public String getMatch() { return match; }
    public String getSource() { return source; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getSeverity() { return severity; }
    public String getContext() { return context; }
    
    @Override
    public String toString() {
        return String.format("[%s] %s %s - %s\n   Source: %s\n   Context: %s",
            timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
            getSeverityIcon(),
            severity,
            type,
            getShortSource(source),
            context.length() > 80 ? context.substring(0, 80) + "..." : context
        );
    }
    
    public String toDetailedString() {
        return String.format("[%s] %s - Type: %s, Source: %s, Severity: %s\n  Context: %s",
            timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
            type,
            type,
            source,
            severity,
            context
        );
    }
    
    private String getSeverityIcon() {
        switch (severity) {
            case "HIGH": return "🔴";
            case "MEDIUM": return "🟡";
            case "LOW": return "🟢";
            default: return "⚪";
        }
    }
    
    private String getShortSource(String source) {
        if (source.length() > 40) {
            return "..." + source.substring(source.length() - 37);
        }
        return source;
    }
}

/**
 * Leakage Rule class to define detection rules
 */
class LeakageRule {
    private String severity;
    private String name;
    private String description;
    
    public LeakageRule(String severity, String name, String description) {
        this.severity = severity;
        this.name = name;
        this.description = description;
    }
    
    // Getters
    public String getSeverity() { return severity; }
    public String getName() { return name; }
    public String getDescription() { return description; }
}