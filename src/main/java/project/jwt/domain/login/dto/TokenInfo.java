package project.jwt.domain.login.dto;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

import java.util.Date;

@Data
@ToString(exclude = "accessToken")
@Builder
/** 어차피 클래스 레벨의 @Builder는 모든 필드에 대한 선택적 생성자 및 setter를 만들기 때문에
 * 여기서는 생성자 레벨에 @Builder를 사용할 필요가 없음 (모든 필드를 쓰니까)
 */

public class TokenInfo {

    private String accessToken;

    private Date accessTokenExpireTime;
    private String ownerEmail;
    private String tokenId;

    public TokenInfo(String accessToken, Date accessTokenExpireTime, String ownerEmail, String tokenId) {
        this.accessToken = accessToken;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.ownerEmail = ownerEmail;
        this.tokenId = tokenId;
    }
}
