# SSLDebugger

This tool will check against the Java keystore to see if the SSL certificate presented by the specified peer is trusted.

# Setup

There are 2 ways to set this up on your machine: use the compiled binaries or compile the source file yourself to generate the binaries.

## Using the Compiled Binaries
If you wish to use the compiled binaries, then save the contents of the `bin` folder to a local folder.

## Compile the source code yourself
To compile the source file yourself, ensure you have JDK installed on your machine, then:
1. Save the contents of the `src` folder to a local folder.
2. Open a command line and navigate to that folder.
3. Run the following command:

`javac SSLDebugger.java`

If successful, you should see new binary files in the folder.

# Usage
Once you have the compiled binaries on your system, then
1. Open the command line and navigate to the folder where the binaries are located.
2. Run the following command

`java SSLDebugger www.example.com 443`

where `www.example.com` is the host/peer you want to test against and `443` is the port number. The port number is optional and will default to `443` if omitted.

Once the test is complete, a folder will be created in the current directory, containing results of the test.

# Samples
The `samples` folder contains samples of what you can expect this script to output after a test.

# Running Test from Outside the Working Folder
If you are unable to navigate your command line to the folder where the binaries are located, then you will need to pass the `-classpath` argument in the command, like below:

`java -classpath "C:\SSLDebugger" SSLDebugger www.example.com 443`

In this scenario, the folder containing the test results will be created in your working directory.
