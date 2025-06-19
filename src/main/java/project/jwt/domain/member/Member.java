package project.jwt.domain.member;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // 생성자 접근 제한을 protected로 설정하여 기본 생성자 호출 막음
public class Member {

    @Id // 이 필드가 엔티티의 기본 키임을 나타냄
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    // 데이터베이스 IDENTITY 컬럼(자동증가 컬럼)을 사용하여 필드의 기본 키 값을 자동 생성
    @Column(name  = "member_id")
    private Long id;

    @Column(unique = true, length = 50)
    private String email;

    @Column(length = 100)
    private String password;

    @Column(length = 50)
    private String username;

    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * 매개변수에 있는 값을 선택적으로 포함하는 생성자를 자동으로 만들어줌.
     * 클래스 레벨이 아닌 생성자 레벨에 @Builder를 사용하면
     * 해당 필드에 대해서만 빌더 패턴을 적용할 수 있음.
     */
    @Builder //
    public Member(String email, String password, String username, Role role) {
        this.email = email;
        this.password = password;
        this.username = username;
        this.role = role;
    }
}
