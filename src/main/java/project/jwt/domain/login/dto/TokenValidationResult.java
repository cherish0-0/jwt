package project.jwt.domain.login.dto;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import project.jwt.domain.login.jwt.token.TokenStatus;
import project.jwt.domain.login.jwt.token.TokenType;

@Getter
@Setter
@ToString
@AllArgsConstructor
public class TokenValidationResult {

    private TokenStatus tokenStatus;
    private TokenType tokenType;
    private String tokenId;
    private Claims claims;
    
    public String getEmail() {
        if (claims == null) {
            throw new IllegalStateException("Claim value is null");
        }

        return claims.getSubject();
    }

    public boolean isValid() {
        return TokenStatus.TOKEN_VALID == this.tokenStatus;
    }
}
