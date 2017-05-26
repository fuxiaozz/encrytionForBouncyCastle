package com.fuxiao86;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by fuxiao
 * on 2017/5/26.
 * email: fuxiao86@163.com.cn
 */
public class RSADemo {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");

        // 加载公钥
        String publicKeyStr = "MIGJAoGBAMudKMBYe2wsGNGKks1SrKFPKWtddigX+0kkkSsuT976uSyjPSz28VUG\n" +
                "e9yP7Hytp+K0tWTyLLTmeFLzovtlO0ZgPifk4h0nkv3FZ+8RG2rt8LzywElpbqqG\n" +
                "eKaUzg26YLVmBb6NbQVOKXrry3BzSSiZ40PulLO6Qsivz3yhm6M/AgMBAAE=";
        byte[] publicKeyData = Base64.decode(publicKeyStr);

        org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1PublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(publicKeyData);
        BigInteger modules = pkcs1PublicKey.getModulus();
        BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modules, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);


        // 加载私钥
        String privateKeyStr = "MIICXQIBAAKBgQDLnSjAWHtsLBjRipLNUqyhTylrXXYoF/tJJJErLk/e+rksoz0s\n" +
                "9vFVBnvcj+x8rafitLVk8iy05nhS86L7ZTtGYD4n5OIdJ5L9xWfvERtq7fC88sBJ\n" +
                "aW6qhnimlM4NumC1ZgW+jW0FTil668twc0komeND7pSzukLIr898oZujPwIDAQAB\n" +
                "AoGBALeEAoK6PSOV6xiRSRb9+NG6w54dMq2YT8fwyVad+ycB23w79JteRs1XdrOo\n" +
                "lIEbE0HllchR7bFuN+yr4q2q4+xCbwqYdfA+H62+y3YU/kbKUuB3m09Ip4dWH0tl\n" +
                "Pl+B3Oaj81GvHZtV8JU7kWW/AqeZ7I7wrjkYJSjt4xZJcCLBAkEA7EAkXxblJ3A6\n" +
                "tSQLGoXauMqJQ4Iav4cbQQ0kTlVcNrDnOkX7nc4ZwjbcmufA+URb0ZqC4ftqfP+v\n" +
                "9tabcZy8+QJBANyilFltxmFkDLsJU2oBZNSZHB09kCBmodkg0avuXdmeiVxeMAm2\n" +
                "5wYhwiqDdxktqrKG4eU9uiw6ede54UoKh/cCQQDU3MIory9Pho5O8afTgPFeeJaO\n" +
                "reY91ZTX2uhwb/bDDEd6uN2KBM4usFG6fL/hmBcG1ynARVBgSdyZEipCho+5AkAz\n" +
                "CmVZPtzqwNN1HVYvqrzhtb3cQdaquDNu4HnA1Xbelh9ev+dLCAXv1DVv0lPl/juD\n" +
                "61IszxfXjXuMXVLx5vfHAkAYoliSAWkIi9sfony0uUJ1ecicPkpSM+g9iABefh3L\n" +
                "f18gCz8xv3r/8RfkYhTRMhzXdi2EUtVOx8DvlBm3Wtfr";

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyStr));
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        SecureRandom random = Utils.createFixedRandom();

        String content = "admin";

        // 加密
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, random);
        byte[] encryptData = cipher.doFinal(content.getBytes());
        System.out.println("加密信息 = " + Base64.toBase64String(encryptData));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptData = cipher.doFinal(encryptData);
        System.out.println("解密信息 = " + new String(decryptData));
    }

}
