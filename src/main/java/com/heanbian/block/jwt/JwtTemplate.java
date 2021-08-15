package com.heanbian.block.jwt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.heanbian.block.crypto.EcTemplate;

public class JwtTemplate {

	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private final Algorithm algorithm;

	public JwtTemplate() {
		EcTemplate ec = new EcTemplate();
		KeyPair keyPair = ec.getKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
		this.algorithm = Algorithm.ECDSA256((ECPublicKey) this.publicKey, (ECPrivateKey) this.privateKey);
	}

	public String createToken(Map<String, ?> claims) {
		return JWT.create()//
				.withIssuer("Party_A") //
				.withAudience("Party_B") //
				.withIssuedAt(new Date()) //
				.withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) //
				.withPayload(claims)//
				.withNotBefore(new Date())//
				.withJWTId(UUID.randomUUID().toString())//
				.sign(this.algorithm);
	}

	public Map<String, Claim> getClaims(String token) {
		DecodedJWT jwt = getDecodedJWT(token);
		return jwt != null ? jwt.getClaims() : null;
	}

	DecodedJWT getDecodedJWT(String token) {
		try {
			return JWT.require(this.algorithm).withIssuer("Party_A").build().verify(token);
		} catch (JWTVerificationException e) {
			e.printStackTrace();
		}
		return null;
	}

}