package model.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

public class CertificateReader {
	public List<Certificate> getCertificatesFromBase64EncFile(String filePath) {
		List<Certificate> certificates = new ArrayList<>();
		
		try {
			FileInputStream fis = new FileInputStream(filePath);
			BufferedInputStream bis = new BufferedInputStream(fis);

			// instanciranje factory objekta i postavljamo tip sertifikata da je X509.
			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			// iteracije dokle god ima bajtova u stream-u koji nisu procitani
			while (bis.available() > 0) {
				// kreiranje sertifikata od bajtova
				Certificate certificate = cf.generateCertificate(bis);
				
				// dodavanje sertifikata u listu
				certificates.add(certificate);
			}
		} catch (CertificateException | IOException e) {
			e.printStackTrace();
		}
		
		return certificates;
	}

}
