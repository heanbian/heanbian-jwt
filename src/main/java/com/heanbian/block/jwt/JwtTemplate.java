package com.heanbian.block.jwt;

import static com.heanbian.block.crypto.RsaTemplate.getKeyPair;
import static java.util.Objects.requireNonNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTemplate {

	private PrivateKey privateKey;
	private PublicKey publicKey;

	public JwtTemplate() {
		KeyPair kp = getKeyPair();
		this.privateKey = kp.getPrivate();
		this.publicKey = kp.getPublic();
	}

	public JwtTemplate(KeyPair keyPair) {
		KeyPair kp = requireNonNull(keyPair, "keyPair must not be null");
		this.privateKey = kp.getPrivate();
		this.publicKey = kp.getPublic();
	}

	public JwtTemplate(PrivateKey privateKey, PublicKey publicKey) {
		this.privateKey = requireNonNull(privateKey, "privateKey must not be null");
		this.publicKey = requireNonNull(publicKey, "publicKey must not be null");
	}

	public String generateToken(Map<String, Object> claims) {
		return generateToken(claims, this.privateKey, new Date(System.currentTimeMillis() + 1800000));
	}

	public String generateToken(Map<String, Object> claims, Date exp) {
		return generateToken(claims, this.privateKey, exp);
	}

	public String generateToken(Map<String, Object> claims, PrivateKey privateKey, Date exp) {
		return Jwts.builder().setId(UUID.randomUUID().toString()).setIssuedAt(new Date()).setClaims(claims)
				.setExpiration(exp).signWith(SignatureAlgorithm.PS512, privateKey).compact();
	}

	public Claims getClaimsFromToken(String token) {
		return getClaimsFromToken(token, this.publicKey);
	}

	public Claims getClaimsFromToken(String token, PublicKey publicKey) {
		try {
			return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public boolean verify(String token) {
		return verify(token, this.publicKey);
	}

	public boolean verify(String token, PublicKey publicKey) {
		try {
			Claims claims = getClaimsFromToken(token, publicKey);
			Date exp = claims.getExpiration();
			return exp.after(new Date());
		} catch (Exception e) {
			return false;
		}
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

}