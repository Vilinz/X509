package x509;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.omg.CORBA.VersionSpecHelper;

public class x509 { 	
	public static String bytesToHex(byte[] bytes) {  
	    StringBuffer sb = new StringBuffer();  
	    int count = 0;
	    for(int i = 0; i < bytes.length; i++) {  
	    	count++;
	        String hex = Integer.toHexString(bytes[i] & 0xFF);  
	        if(hex.length() < 2){  
	            sb.append(0);  
	        }  
	        sb.append(hex); 
	        if(i != bytes.length - 1) {
	        	sb.append(":");
	        }
	        if(count == 16) {
	        	count = 0;
	        	sb.append("\n    ");	        
	        }
	    }  
	    return sb.toString();  
	}  
	public static void main(String args[]) {
		try {
			FileInputStream inStream = new FileInputStream("D:/java/x509/src/x509/x509.cer");
		    CertificateFactory cf=CertificateFactory.getInstance("X.509");
		    X509Certificate cert=(X509Certificate)cf.generateCertificate(inStream);
		    
		    System.out.println("Type: " + cert.getType());
		    
		    System.out.println("  version: " + cert.getVersion());
		    System.out.println("  serialNumber");
		    byte b[] = cert.getSerialNumber().toByteArray();
		    String string = bytesToHex(b);
		    System.out.println("    " + string);
		    
		    System.out.println("  SignatureValue: " + cert.getSigAlgOID());
		    System.out.println("  Signature Algorithm: " + cert.getSigAlgName());
		    System.out.println("  Issuer: " + cert.getIssuerX500Principal());
		    System.out.println("  Validity");
		    System.out.println("    Not Before: " + cert.getNotBefore());
		    System.out.println("    Not After: " + cert.getNotAfter());
		    
		    System.out.println("  Subject: " + cert.getSubjectX500Principal() + "\n");
		    
		    System.out.println("  Subject Publc Key Info.");
		    System.out.println("  Publc Key.");
		    System.out.println("    " + bytesToHex(cert.getPublicKey().getEncoded()));
		     
		    System.out.println("  Extention");
		    System.out.println("    Extention key usage: " + cert.getExtendedKeyUsage());
		    System.out.println("    Extention Basic Constraints: " + cert.getBasicConstraints());
		    System.out.println("    Critical Extension OIDs: " + cert.getCriticalExtensionOIDs());
		    
		    System.out.println("  Signature Algorithm: " + cert.getSigAlgName());
		    System.out.println("  Signature:");
		    String string2 = bytesToHex(cert.getSignature());
		    System.out.println("    " + string2);
		  }
		 catch (  Exception e) {
		    throw new RuntimeException(e);
		  }
	}
}
