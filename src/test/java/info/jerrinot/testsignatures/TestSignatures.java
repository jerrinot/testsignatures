package info.jerrinot.testsignatures;

import io.questdb.cutlass.line.tcp.AuthDb;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.ClassRule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import java.util.Base64;

import static org.junit.Assert.fail;

public class TestSignatures {
    @ClassRule
    public static GenericContainer<?> keyGen = new GenericContainer<>("jerrinot/pyjwk-gen:latest")
            .withExposedPorts(5000);

    private static final int CHALLENGE_LEN = 512;
    private static final String SIGNATURE_TYPE_DER = "SHA256withECDSA";
    private static final String SIGNATURE_TYPE_P1363 = "SHA256withECDSAinP1363Format";


    @Test
    public void testSignature() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("http://" + keyGen.getHost() + ":" + keyGen.getMappedPort(5000) + "/"))
                .GET()
                .build();

        HttpClient client = HttpClient.newBuilder().build();
        JSONParser parser = new JSONParser();

        byte[] challengeBytes = new byte[CHALLENGE_LEN];
        SecureRandom srand = new SecureRandom();

        Signature sigDER = Signature.getInstance(SIGNATURE_TYPE_DER);
        Signature sigP1363 = Signature.getInstance(SIGNATURE_TYPE_P1363);

        for (int i = 0; i < 1_000; i++) {
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            JSONObject jsonObject = (JSONObject) parser.parse(resp.body());

            String d = (String) jsonObject.get("d");
            String x = (String) jsonObject.get("x");
            String y = (String) jsonObject.get("y");

            int n = 0;
            while (n < CHALLENGE_LEN) {
                int r = (int) (srand.nextDouble() * 0x5f) + 0x20;
                challengeBytes[n] = (byte) r;
                n++;
            }

            PrivateKey privateKey = AuthDb.importPrivateKey(d);
            PublicKey publicKey = AuthDb.importPublicKey(x, y);

            byte[] signature = signAndEncode(privateKey, challengeBytes);
            byte[] signatureRaw = Base64.getDecoder().decode(signature);

            Signature sig = signatureRaw.length == 64 ? sigP1363 : sigDER;
            sig.initVerify(publicKey);
            sig.update(challengeBytes);
            boolean verify = sig.verify(signatureRaw);

            if (!verify) {
                fail("Failure at iteration no. " + i);
            }
        }
    }

    private byte[] signAndEncode(PrivateKey privateKey, byte[] challengeBytes) {
        byte[] rawSignature;
        try {
            Signature sig = Signature.getInstance(SIGNATURE_TYPE_DER);
            sig.initSign(privateKey);
            sig.update(challengeBytes);
            rawSignature = sig.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encode(rawSignature);
    }
}
