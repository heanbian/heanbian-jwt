package com.heanbian.block.jwt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.heanbian.block.crypto.EcTemplate;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTemplate {

	private PrivateKey privateKey;
	private PublicKey publicKey;

	public JwtTemplate() {
		EcTemplate ec = new EcTemplate();
		KeyPair keyPair = ec.getKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	public String generateToken(Map<String, Object> claims) {
		return generateToken(claims, new Date(System.currentTimeMillis() + 1800000));
	}

	public String generateToken(Map<String, Object> claims, Date exp) {
		return Jwts.builder().setId(UUID.randomUUID().toString()).setIssuedAt(new Date()).setClaims(claims)
				.setExpiration(exp).signWith(this.privateKey, SignatureAlgorithm.ES256).compact();
	}

	public Claims getClaimsFromToken(String token) {
		try {
			return Jwts.parserBuilder().setSigningKey(this.publicKey).build().parseClaimsJws(token).getBody();
		} catch (JwtException e) {
			throw new RuntimeException(e);
		}
	}

	public boolean check(String token) {
		try {
			Claims claims = getClaimsFromToken(token);
			Date exp = claims.getExpiration();
			return exp.after(new Date());
		} catch (Exception e) {
			return false;
		}
	}

}