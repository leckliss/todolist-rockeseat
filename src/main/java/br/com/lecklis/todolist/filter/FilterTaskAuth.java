package br.com.lecklis.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.lecklis.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

            var servletPath = request.getServletPath();

            //Verificar se a rota é a de tasks
            //Outras rotas protegidas por login adidionar aqui
            if(servletPath.startsWith("/tasks/")){


            //Pegar dados de autenticação 
            var authorization = request.getHeader("Authorization");
            
            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authSting = new String(authDecode);

            String[] credentials = authSting.split(":");
            String username = credentials[0];
            String password = credentials[1];

            System.out.println(username);
            System.out.println(password);

            //Verificar se o usuário existe
            var user = this.userRepository.findByUsername(username);
            if(user == null){
                response.sendError(401,"Usário inexistente, faça o cadastro");
                System.out.println("Usário inexistente, faça o cadastro");
            }else{
                //Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if(passwordVerify.verified){
                    request.setAttribute("idUser",user.getId());
                    filterChain.doFilter(request, response); // seguir com aplicação
                }else{
                    response.sendError(401, "Senha incorreta");
                    System.out.println("Senha incorreta");
                }

                
            }
        }
        else{
            filterChain.doFilter(request, response); // se não for rota tasks seguir com aplicação
        }
    }

}
