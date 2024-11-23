import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;

public class JwtUtil {
    private static final String SECRET_KEY = "your-256-bit-secret-your-256-bit-secret";

    private static SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(SECRET_KEY));
    }

    public static Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
