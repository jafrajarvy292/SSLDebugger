# SSLDebugger

This tool will check against the Java keystore to see if the SSL certificate presented by the specified peer is trusted.

# Setup

There are 2 ways to set this up on your machine: use the compiled binaries or compile the source file yourself.

## Using the Compiled Binaries
If you wish to use the compiled binaries, then save the contents of the `bin` folder to a local folder.

## Compile the source code yourself
To compile yourself, ensure you have JDK installed on your machine, since we'll be using the `javac.exe` executable.
1. Save the contents of the `src` folder to a local folder.
2. Open a command line and navigate to that folder.
3. Run the following command:

`javac SSLDebugger.java`

# Usage
Once you have the compiled binaries on your system, then
1. Open the command line and navigate to the folder where the binaries are located.
2. Run the following command

`java SSLDebugger www.example.com 443`

where `www.example.com` is the host/peer you want to test against and `443` is the port number. The port number is optional: if omitted, the system will default to `443`.

Once the test is complete, a folder will be created in the same directory where the binaries were ran, containing results of the test.

# Samples
The `samples` folder contains samples of what you can expect this script to output after a test.
