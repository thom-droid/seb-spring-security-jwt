package com.codestates.seb.springsecurityjwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class FirstFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
        log.info("first filter initiated");
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("do the rest of the application");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        res.setCharacterEncoding("UTF-8");
        if (req.getMethod().equals("POST")) {
            String headAuth = req.getHeader("Authorization");

            if (headAuth.equals("codestates")) {
                log.info("token received");
                chain.doFilter(req, res);
            } else {
                log.info("authentication failed");
                PrintWriter writer = res.getWriter();
                writer.write("authentication failed");
            }
        }
    }
}
