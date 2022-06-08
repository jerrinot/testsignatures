package info.jerrinot.testsignatures;

import io.questdb.cutlass.line.tcp.AuthDb;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Before;
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


    private HttpRequest request;
    private JSONParser parser;
    private byte[] challengeBytes;
    private Signature sigDER;
    private Signature sigP1363;
    private HttpClient client;
    private static final SecureRandom srand = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        request = HttpRequest.newBuilder()
                .uri(new URI("http://" + keyGen.getHost() + ":" + keyGen.getMappedPort(5000) + "/"))
                .GET()
                .build();

        client = HttpClient.newBuilder().build();
        parser = new JSONParser();

        challengeBytes = new byte[CHALLENGE_LEN];

        sigDER = Signature.getInstance(SIGNATURE_TYPE_DER);
        sigP1363 = Signature.getInstance(SIGNATURE_TYPE_P1363);
    }



    @Test
    public void testSignature() throws Exception {
        String prevD = "";
        String prevX = "";
        String prevY = "";

        for (int i = 0; i < 1_000; i++) {
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            JSONObject jsonObject = (JSONObject) parser.parse(resp.body());

            String d = (String) jsonObject.get("d");
            String x = (String) jsonObject.get("x");
            String y = (String) jsonObject.get("y");



            for (int l = 0; l < 2; l++) {
                refreshChallenge(challengeBytes);

                PrivateKey privateKey = AuthDb.importPrivateKey(d);
                PublicKey publicKey = AuthDb.importPublicKey(x, y);

                byte[] signature = signAndEncode(privateKey, challengeBytes);

                Signature sig = signature.length == 64 ? sigP1363 : sigDER;
                sig.initVerify(publicKey);
                sig.update(challengeBytes);
                boolean verify = sig.verify(signature);

                if (!verify) {
                    System.out.println("Current X = " + x + "("+x.length()+"), Previous X = " + prevX + "("+prevX.length()+")");
                    System.out.println("Current Y = " + y + "("+y.length()+"), Previous X = " + prevY + "("+prevY.length()+")");
                    System.out.println("Current D = " + d + "("+d.length()+"), Previous X = " + prevD + "("+prevD.length()+")");
                    fail("Failure wit keys no. " + i +" challenge iteraiton no. " + l);
                }
                prevX = x;
                prevY = y;
                prevD = d;
            }
        }
    }

    private static void refreshChallenge(byte[] challengeBytes) {
        int n = 0;
        while (n < CHALLENGE_LEN) {
            int r = (int) (srand.nextDouble() * 0x5f) + 0x20;
            challengeBytes[n] = (byte) r;
            n++;
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
        return rawSignature;
    }
}
