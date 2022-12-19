import java.io.File;
import java.io.FileWriter;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This script is used to test SSL connections against a given host and port. It will
 * check to see if the SSL certificate presented by the host is found in Java's database
 * of trusted certificates. The script will output information to a log and will output
 * the host certificates and Java's trusted certificates to the file system for review.
 * @author David Tran
 *
 */
class SSLDebugger {
	public static void main(String[] args) throws Exception {
		//Set testMode to true to use default host and port instead of user-provided values
		boolean testMode = false;
		String host = "untrusted-root.badssl.com";
		int port = 443;
		
		boolean isCertTrusted;
		String logFolderName;
		String fileSeparator = System.getProperty("file.separator");
		String newLine = System.getProperty("line.separator");
		File logFolder;
		File logFile;
		FileWriter logFileWriter = null;
		
		//Check that user provided correct number of arguments
		if (args.length == 0 && testMode == false) {
		System.out.println("Missing required arguments...");
		System.out.println("Usage: java SSLDebugger host [port]");
		System.out.println("Example: java SSLDebugger www.example.com 443");
		return;
		}
		
		if (args.length == 2) {
			host = args[0];
			port = Integer.parseInt(args[1]);
		} else if (args.length == 1) {
			host = args[0];
		}
		
		//Validation of host to check that user didn't include the protocol portion or path
		Pattern hostPattern = Pattern.compile("/");
		Matcher hostMatcher = hostPattern.matcher(host);
		if (hostMatcher.find() == true) {
			System.out.println("Invalid host. Please include only the domain that needs to be checked.");
			System.out.println("For example, if you need to check https://www.example.com, then pass in only www.example.com.");
			return;
		}
		
		logFolderName = generateLogFolderName(host);
		logFolder = new File(logFolderName);
		
		//Create log folder
		if (!logFolder.mkdirs()) {
			System.out.println("Could not create the log folder needed to store debugging information.");
			return;
		}
		
		//Create log file
		logFile = new File(logFolderName + fileSeparator + "debug.log");
		try {
			if (!logFile.createNewFile()) {
				System.out.println("Could not create the log file.");
				return;
			}
		} catch (Exception e) {
			System.out.println(e);
		}
		
		//Open log file for writing
		try {
			logFileWriter = new FileWriter(logFile);
		} catch (Exception e) {
			System.out.println(e);
		}
				
	
		
		//Print DISCLAIMER
		logFileWriter.write(sectionHeader("DISCLAIMER"));
		logFileWriter.write(newLine);
		logFileWriter.write("The information contained within this log file is accurate only" + newLine);
		logFileWriter.write("in relation to this script. While the information provided here might apply to" + newLine);
		logFileWriter.write("other Java applications, there is no guarantee that it will be correct, as each" + newLine);
		logFileWriter.write("Java application has the ability to set different configuration values at the time" + newLine);
		logFileWriter.write("of execution." + newLine);
				
		//Test host certificate against default trust manager and log results
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write(sectionHeader("SSL TEST RESULT"));
		logFileWriter.write(newLine);
		try {
			isCertTrusted = testDefaultTM(host, port);
			//Print test results to log
			if (isCertTrusted == true) {
				logFileWriter.write("Server certificate for " + host + " on port " + port + " is TRUSTED");
			} 
		} catch (Exception e) {
			logFileWriter.write("Server certificate for " + host + " on port " + port + " is NOT TRUSTED for reason:");
			logFileWriter.write(newLine);
			logFileWriter.write(e.getMessage());
		}
		
		//Output details of host's certificate chain and save to disk
		try {
			X509Certificate[] peerCerts = getPeerCerts(host, port);
			String certificateFolderName = logFolderName + fileSeparator + "Host Certificates";
			File certificateFolder = new File(certificateFolderName);
			certificateFolder.mkdir();
			logFileWriter.write(newLine);
			logFileWriter.write(newLine);
			logFileWriter.write(newLine);
			logFileWriter.write(newLine);
			logFileWriter.write(sectionHeader("HOST CERTIFICATE CHAIN"));
			logFileWriter.write(newLine);
			logFileWriter.write("Certificate chain downloaded from " + host + ":" + port + " is below, starting with its own.");
			logFileWriter.write(newLine);
			logFileWriter.write("These certificates will also be saved to the same area this log file is found.");
			logFileWriter.write(newLine);
			logFileWriter.write(newLine);
					
			for(int i = 0; i < peerCerts.length; i++) {
				//Output details of current certificate to debug file
				logFileWriter.write("Certificate " + (i+1) + " Details: " + peerCerts[i].getSubjectX500Principal());
				logFileWriter.write(newLine);
				logFileWriter.write("Certificate " + (i+1) + " Issued By: " + peerCerts[i].getIssuerX500Principal());
				logFileWriter.write(newLine);
				logFileWriter.write(newLine);
				
				//Save current certificate to disk
				File certificate = new File(certificateFolderName + fileSeparator + "Certificate " + (i+1) + ".pem");
				certificate.createNewFile();
				FileWriter certificateWriter = new FileWriter(certificate);
				certificateWriter.write(X509toPEM(peerCerts[i]));
				certificateWriter.close();
			}
		} catch (Exception e) {
			logFileWriter.write(e.toString());
		}
		
		//Write runtime/environment variables
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write(sectionHeader("JAVA RUNTIME VARIABLES") + newLine);
		logFileWriter.write("jave.home = " + System.getProperty("java.home") + newLine);
		logFileWriter.write(newLine);
		logFileWriter.write("java.version = " + System.getProperty("java.version") + newLine);
		logFileWriter.write(newLine);
		logFileWriter.write("user.name = " + System.getProperty("user.name") + newLine);
		
		//Write summary of the test
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write(sectionHeader("JAVA TRUST MANAGER DETAILS") + newLine);
		logFileWriter.write("Possible location of your cacerts file = ");
		logFileWriter.write(System.getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "security");
		logFileWriter.write(newLine);
		logFileWriter.write(newLine);
		logFileWriter.write("Note: If a jssecacerts file is found in the same folder where your cacerts" + newLine);
		logFileWriter.write("file is found, then Java will use the jssecacerts file. Be sure you are updating" + newLine);
		logFileWriter.write("the correct file." + newLine);
		logFileWriter.write("Documenation regarding Java's logic on this:" + newLine);
		logFileWriter.write("https://stackoverflow.com/questions/5709392/why-does-java-have-both-the-cacerts-and-jssecacerts-files" + newLine);
		logFileWriter.write("https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager" + newLine);
		logFileWriter.write(newLine);
		logFileWriter.write("The certificates found in Java's database of trusted certificates are detailed below" + newLine);
		logFileWriter.write("and have been saved to the same area this log file is found." + newLine);

		//Retrieve all of the trusted certificates from the trust manager
		ArrayList<X509Certificate> trustedCertificates = getJavaTrustedCerts();

		//Output details of each certificate from trust manager to log
		logFileWriter.write(newLine);
		for(int i = 0; i < trustedCertificates.size(); i++) {
			logFileWriter.write("Certificate " + (i+1) + " Details: " + trustedCertificates.get(i).getSubjectX500Principal() + newLine);
			logFileWriter.write("Certificate " + (i+1) + " Issued By: " + trustedCertificates.get(i).getSubjectX500Principal() + newLine);
			logFileWriter.write(newLine);
		}
		
		//Save each certificate from trust manager to disk
		try {
			String trustedCertsFolderName = logFolderName + fileSeparator + "Trusted Certificates";
			File trustedCertsFolder = new File(trustedCertsFolderName);
			trustedCertsFolder.mkdir();
			for(int i = 0; i < trustedCertificates.size(); i++) {
				String certificateFileName = new String("Certificate " + (i+1) + ".pem");
				File certificateFile = new File(trustedCertsFolderName + fileSeparator + certificateFileName);
				certificateFile.createNewFile();
				FileWriter certificateFileWriter = new FileWriter(certificateFile);
				certificateFileWriter.write(X509toPEM(trustedCertificates.get(i)));
				certificateFileWriter.close();
			}
			
		} catch (Exception e) {
			System.out.println(e.toString());
		}
		
		//Close log file
		logFileWriter.close();
	}
	
	/**
	 * Returns an ArrayList of all X509Certificates found in the trust 
	 * manager's database
	 * @return
	 */
	public static ArrayList<X509Certificate> getJavaTrustedCerts() {
		try {
			ArrayList<X509Certificate> finalCertificateArray = new ArrayList<X509Certificate>();
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		    trustManagerFactory.init((KeyStore) null);
		    
		    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		    
		    for(TrustManager trustManager : trustManagers) {
		    	X509TrustManager X509TrustManager = (X509TrustManager)trustManager;
		    	X509Certificate[] certificates = X509TrustManager.getAcceptedIssuers();
		    	for (X509Certificate certificate : certificates) {
		    		finalCertificateArray.add(certificate);
		    	}
		    }
		    return finalCertificateArray;
			
		} catch (Exception e) {
			System.out.println(e.toString());
			return null;
		}
	}
	
	/**
	 * Tests a host and port against the default trust manager.
	 * @param host
	 * @param port
	 * @return Returns true if peer is trusted, else throws exception
	 * @throws Exception
	 */
	public static boolean testDefaultTM(String host, int port) throws Exception {
		try {
			SSLContext sslContext = SSLContext.getDefault();
			SSLSocketFactory sslf = sslContext.getSocketFactory();
			SSLSocket socket = (SSLSocket)sslf.createSocket(host, port);
			socket.startHandshake();
			return true;
		} catch (Exception e) {
			throw new Exception(e);
		}
	}
	
	/**
	 * This method will retrieve the certificate chain from the host/peer. To ensure certificates can
	 * be retrieved, even from untrusted peers, a passthrough Trust Manager will be used. Do
	 * not use this apporach to determine whether peer certificates are trusted, as it will trust
	 * everything.
	 * @param host
	 * @param port
	 * @return
	 */
	public static X509Certificate[] getPeerCerts(String host, int port) {
		try {
			SSLContext sslContext = SSLContext.getInstance("TLS");
			
			X509TrustManager acceptAllCertsTrustManager = new X509TrustManager() {
			    public void checkClientTrusted(X509Certificate[] chain,
			            String authType) throws CertificateException {
			    }
			    public void checkServerTrusted(X509Certificate[] chain,
			            String authType) throws CertificateException {
			    }
			    public X509Certificate[] getAcceptedIssuers() {
			        return null;
			    }
			};
			sslContext.init(null, new TrustManager[] { acceptAllCertsTrustManager }, null);			
			SSLSocketFactory sslf = sslContext.getSocketFactory();
			SSLSocket socket = (SSLSocket)sslf.createSocket(host, port);
			socket.startHandshake();
			X509Certificate[] peerCertificates = (X509Certificate[]) socket.getSession().getPeerCertificates();
			return peerCertificates;
		} catch (Exception e) {
			System.out.println(e);
			return null;
		}
		
	}
	
	/**
	 * Converts a X509Certificate object to your typical PEM format and returns
	 * the result as a string.
	 * @param cert
	 * @return
	 */
	public static String X509toPEM(X509Certificate cert) {
		String newLine = System.getProperty("line.separator");
		String beginning = "-----BEGIN CERTIFICATE-----";
		String ending = "-----END CERTIFICATE-----";
		try {
			byte[] unformatted = Base64.getEncoder().encode(cert.getEncoded());
			String formatted = new String(unformatted);
			formatted = formatted.replaceAll("(.{64})", "$1" + newLine);
			formatted = beginning + newLine + formatted + newLine + ending + newLine;
			return formatted;		
		} catch (Exception e) {
			System.out.println(e);
			return null;
		}
	}
	
	/**
	 * Generates a unique name for the log folder, where debugging information
	 * will be stored.
	 * @param host
	 * @return
	 */
	public static String generateLogFolderName(String host) {
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-dd-MM hh.mm.ssa");
		String folderName = sdf.format(date) + " - " + host;
		return folderName;
	}
	
	/**
	 * Generates a section header/title bar and returns it as a string
	 * @param input
	 * @return
	 */
	public static String sectionHeader(String input) {
		String sectionHeader = new String();
		String border = "##########";
		sectionHeader = border + " " + input.toUpperCase() + " " + border;
		return sectionHeader;
	}
}
