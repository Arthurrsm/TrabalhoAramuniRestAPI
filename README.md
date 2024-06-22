# API Rest TrabalhoAramuni

## Introdução

A API Rest TrabalhoAramuni permite registrar usuários, autenticar via login e extrair o papel (role) do usuário através de tokens JWT.

## Base URL

http://localhost:8080


## Endpoints

### POST /register

Registra um novo usuário.

#### Requisição

```http
POST /register
Content-Type: application/json

{
  "username": "johndoe",
  "password": "password",
  "role": "USER"
}
```

Resposta de Sucesso
* Status: 200 OK
Corpo:
```
"User registered successfully"
```

Resposta de Erro
* Status: 400 Bad Request
Corpo:
```
{
  "message": "Erro ao registrar usuário"
}
```

### GET /login

Autentica um usuário e retorna um token JWT.

#### Requisição
```
GET /login?username=johndoe&password=password
```

Resposta de Sucesso
* Status: 200 OK
Corpo:
```
"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huZG9lIiwicm9sZSI6IlVTRVIifQ.QZ-7B9rVo10t6w4njWCMjXJRe7FiW76FfplTPbm1Ows"
```

Resposta de Erro
* Status: 401 Unauthorized
Corpo:

```
{
  "message": "Credenciais inválidas"
}
```

### GET /role/{token}

Extrai o papel (role) do usuário a partir do token JWT.

#### Requisição
```
GET /role/{token}
```

Resposta de Sucesso
* Status: 200 OK
Corpo:
```
"USER"
```

Resposta de Erro
* Status: 401 Unauthorized
Corpo:

```
{
  "message": "Token inválido"
}
```

## Autenticação

A autenticação é feita via JWT (JSON Web Token). Inclua o token JWT no cabeçalho Authorization como Bearer <token> em todas as requisições autenticadas.

Exemplo:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huZG9lIiwicm9sZSI6IlVTRVIifQ.QZ-7B9rVo10t6w4njWCMjXJRe7FiW76FfplTPbm1Ows
```

## Segurança
A API utiliza criptografia para assegurar a integridade e confidencialidade dos dados. Os endpoints /register e /login estão disponíveis publicamente, enquanto outros exigem autenticação via JWT.

## Exceções
A API retorna os seguintes códigos de status de erro:

* 400 Bad Request: Requisição inválida
* 401 Unauthorized: Falha na autenticação
* 404 Not Found: Recurso não encontrado

## Descrição das Classes

### TrabalhoAramuniRestAPIApplication
```
@SpringBootApplication(scanBasePackages = {"com.example"})
    @EnableMongoRepositories("com.example.TrabalhoAramuniRestAPI.repository")
    public class TrabalhoAramuniRestAPIApplication {

        public static void main(String[] args) {
            SpringApplication.run(TrabalhoAramuniRestAPIApplication.class, args);
        }

    }
```
Esta classe é a aplicação principal Spring Boot. Ela configura e inicializa a aplicação, especificando os pacotes base para escaneamento (scanBasePackages) e habilitando os repositórios MongoDB.

### AppConfig
```
@Configuration
@EnableWebSecurity
public class AppConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers(HttpMethod.POST, "/register").permitAll()
                        .requestMatchers(HttpMethod.GET, "/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/role/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```
Classe de configuração Spring responsável por configurar a segurança da aplicação. Define as regras de autorização (HttpSecurity) para os endpoints, habilita o uso de filtros de autenticação JWT e configura um encoder de senha (BCryptPasswordEncoder).

### AuthController
```
@RestController
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        String response = userService.registerUser(user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        String token = authService.authenticateUser(username, password);
        if (token != null) {
            return ResponseEntity.ok(token);
        } else {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    @GetMapping("/role/{token}")
    public ResponseEntity<String> extractRole(@PathVariable String token) {
        String role = authService.extractRole(token);
        if (role != null) {
            System.out.println(role);
            return ResponseEntity.ok(role);
        } else {
            System.err.println(token);
            return ResponseEntity.status(400).body("Role não existe.");
        }
    }
}
```
Controlador Spring que define os endpoints da API relacionados à autenticação e registro de usuários. Possui métodos para registrar um novo usuário (register), autenticar um usuário (login) e extrair o papel (role) de um usuário autenticado (extractRole).

### User
```
@Document(collection = "users")
public class User {
    @Id
    private String id;
    private String username;
    private String password;
    private String role;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
```
Classe de modelo que representa um usuário da aplicação. Mapeada para o MongoDB como um documento (@Document), possui campos como username, password e role.

### UserRepository
```
public interface UserRepository extends MongoRepository<User, String> {
    User findByUsername(String username);
}
```
Interface que estende MongoRepository para operações de acesso a dados relacionados aos usuários (User). Define métodos de consulta como findByUsername para buscar usuários por nome de usuário.

### JwtAuthenticationFilter
```
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final SecretKey SECRET_KEY;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secret) {
        this.SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String username = claims.getSubject();
            String role = claims.get("role", String.class);
            if (username != null && role != null) {
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
```
Filtro de autenticação Spring que intercepta requisições HTTP para validar e extrair tokens JWT do cabeçalho Authorization. Utiliza a chave secreta configurada (SECRET_KEY) para verificar e decodificar tokens JWT, autenticando usuários com base nas informações contidas nos tokens.

### JwtUtil
```
@Component
public class JwtUtil {

    private final SecretKey SECRET_KEY;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    private static final long EXPIRATION_TIME = 864_000_000; // 10 days

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
                .compact();
    }

    public String extractUsername(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public String extractRole(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("role", String.class);
    }
}
```
Classe utilitária que fornece métodos para gerar tokens JWT (generateToken), extrair informações como nome de usuário (extractUsername) e papel (role) do token (extractRole). Usa uma chave secreta para assinar e verificar tokens JWT.

### AuthService
```
@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public String authenticateUser(String username, String password) {
        User user = userRepository.findByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            return jwtUtil.generateToken(username, user.getRole());
        }
        return null;
    }

    public String extractUsername(String token) {
        return jwtUtil.extractUsername(token);
    }

    public String extractRole(String token) {
        return jwtUtil.extractRole(token);
    }
}
```
Serviço Spring que encapsula a lógica de negócio relacionada à autenticação de usuários. Utiliza o UserRepository para verificar as credenciais do usuário durante a autenticação e o JwtUtil para gerar e extrair informações de tokens JWT.

### UserService
```
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "User registered successfully";
    }
}

```
Serviço Spring responsável por operações relacionadas aos usuários, como registrar um novo usuário. Usa o UserRepository para salvar usuários no banco de dados MongoDB e o PasswordEncoder para criptografar senhas antes de armazená-las.

## Conclusão

Esta documentação abrange os principais endpoints da API Rest TrabalhoAramuni, detalhando as operações disponíveis, exemplos de requisições e respostas esperadas, além de informações sobre autenticação, segurança e uma breve descrição das classes envolvidas na implementação da API.

Para mais detalhes sobre cada classe, métodos e configurações, consulte a seção correspondente na documentação. A API é projetada para proporcionar funcionalidades de registro de usuários, autenticação segura via tokens JWT e gestão de papéis de usuário de forma eficiente e segura.
