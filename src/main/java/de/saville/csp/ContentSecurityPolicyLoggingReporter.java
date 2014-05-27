package de.saville.csp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs content security policy violations using Slf4J.
 * 
 *     <servlet>
 *         <servlet-name>ContentSecurityPolicyReporter</servlet-name>
 *         <servlet-class>de.saville.csp.ContentSecurityPolicyReporter</servlet-class>
 *     </servlet>
 *  
 *     <servlet-mapping>
 *         <servlet-name>ContentSecurityPolicyReporter</servlet-name>
 *         <url-pattern>/ContentSecurityPolicyReporter</url-pattern>
 *     </servlet-mapping>  
 */
public class ContentSecurityPolicyLoggingReporter extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(ContentSecurityPolicyLoggingReporter.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.warn(IOUtils.toString(request.getReader()));
    }

}
