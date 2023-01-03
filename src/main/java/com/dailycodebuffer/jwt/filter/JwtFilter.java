package com.dailycodebuffer.jwt.filter;

import com.dailycodebuffer.jwt.service.UserService;
import com.dailycodebuffer.jwt.utility.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {
    //to make the system understand whatever we are passing we need to implement jwt filter
    //for each auth request we will pass the request through series of filters
    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private UserService userService;

    //override the doFilterInternal method
    //we get request, response and filterChain as input
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        //get 'Authorization' header
        String authorization = httpServletRequest.getHeader("Authorization");
        String token = null;
        String userName = null;

        if(null != authorization && authorization.startsWith("Bearer ")) {
            //extract the token which starts from index 7
            token = authorization.substring(7);
            userName = jwtUtility.getUsernameFromToken(token);
        }
        // if username is not null and security context is null
        if(null != userName && SecurityContextHolder.getContext().getAuthentication() == null) {

            //load the username and validate the token
            UserDetails userDetails
                    = userService.loadUserByUsername(userName);

            if(jwtUtility.validateToken(token,userDetails)) {
                //create a token and add all the deatils from the request
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                        = new UsernamePasswordAuthenticationToken(userDetails,
                        null, userDetails.getAuthorities());

                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(httpServletRequest)
                );
                //add the information in the security context
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }

        }
        //finally doFilter will filter the request and response
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
