# SSLDebugger

This tool will check against the Java keystore to see if the SSL certificate presented by the specified peer is trusted.

# Requirements
This tool is compatible with Java 8.

# Usage for JAR package
1. Open the command line and navigate to the folder where the SSLDebugger.jar has been saved.
2. Run the following command

`java -jar SSLDebugger.jar www.example.com 443`

where `www.example.com` is the host/peer you want to test against and `443` is the port number. The port number is optional and will default to `443` if omitted.

Once the test is complete, a folder will be created in the current directory, containing results of the test.

# Samples
The `samples` folder contains samples of what you can expect this script to output after a test.
