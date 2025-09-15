# DataLeakageDetection
This Java-based Data Leakage Detection System provides a practical approach to identifying and tracing the sources of confidential data leaks in organizational environments. By assigning unique, invisible alterations (for example, encrypted tags or digital watermarks) to each piece of sensitive data distributed to agents or users with unique, undetectable alterations. If a data leak occurs, the system compares the leaked data with stored allocations to accurately identify the responsible agent.

Features:

Agent management (creation, tracking by ID and name)

Data allocation to agents with distinct alterations

Secure storage and retrieval of allocated data

Detection of leaked data and tracing back to the source

Simple, console-based interaction

Tech Used:

Java (Core)

HashMap and other basic data structures

How it Works:

Admin allocates data (e.g., confidential record) to agents, each with a custom alteration (tag or watermark).

If a copy of data is leaked, the system analyzes its unique alteration code to identify which agent it originally belonged to.

The process is automated and works for text-based data; can be extended to files/images.

Getting Started:

Make sure Java is installed on your system.

Compile your code using:
javac DataLeakageDetector.java

Run the main class:
java DataLeakageDetector

Sample Usage:

Enter agent details and allocate data using the prompts.

Simulate a data leak and let the system trace the source.
